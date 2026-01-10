#include "capture.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <iterator>

namespace pv {
namespace {

constexpr int kSnapLen = 1536;   // bytes captured per frame
constexpr int kReadTimeoutMs = 100;
constexpr size_t kPendingCap = 8192; // backstop if the UI stalls

double now_seconds(const timeval& tv) {
  return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
}

// pcap reports permission problems in several ways depending on the platform;
// turn any of them into one actionable message.
std::string permission_hint() {
#ifdef __APPLE__
  return "Permission denied opening the capture device.\n"
         "portveil needs raw access to /dev/bpf*; run it with sudo:\n"
         "  sudo portveil\n"
         "Installing Wireshark's ChmodBPF helper grants your user permanent\n"
         "access instead, so portveil can run without sudo.";
#else
  return "Permission denied opening the capture device.\n"
         "portveil needs CAP_NET_RAW; run it with sudo:\n"
         "  sudo portveil\n"
         "Or grant the binary the capability once:\n"
         "  sudo setcap cap_net_raw,cap_net_admin=eip $(command -v portveil)";
#endif
}

bool is_permission_error(int status, const char* msg) {
  if (status == PCAP_ERROR_PERM_DENIED) return true;
  if (msg == nullptr) return false;
  const std::string m(msg);
  return m.find("Permission denied") != std::string::npos ||
         m.find("Operation not permitted") != std::string::npos ||
         m.find("socket: Operation not permitted") != std::string::npos;
}

} // namespace

Capture::~Capture() {
  stop();
  if (handle_ != nullptr) {
    pcap_close(reinterpret_cast<pcap_t*>(handle_));
    handle_ = nullptr;
  }
}

bool Capture::open(const std::string& iface, const std::string& bpf, std::string& err) {
  char errbuf[PCAP_ERRBUF_SIZE] = {};
  pcap_t* p = pcap_create(iface.c_str(), errbuf);
  if (p == nullptr) {
    err = is_permission_error(0, errbuf) ? permission_hint()
                                         : std::format("Cannot open {}: {}", iface, errbuf);
    return false;
  }

  pcap_set_snaplen(p, kSnapLen);
  pcap_set_promisc(p, 1);
  pcap_set_timeout(p, kReadTimeoutMs);
  pcap_set_buffer_size(p, 4 * 1024 * 1024); // 4 MB kernel ring
  // Without immediate mode the kernel holds frames until its buffer fills,
  // which makes a live view feel frozen on a quiet link.
  pcap_set_immediate_mode(p, 1);

  const int status = pcap_activate(p);
  if (status < 0) {
    const char* msg = pcap_geterr(p);
    if (is_permission_error(status, msg)) {
      err = permission_hint();
    } else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
      err = std::format("No such interface: {}", iface);
    } else {
      err = std::format("Cannot capture on {}: {}", iface, msg ? msg : "unknown error");
    }
    pcap_close(p);
    return false;
  }

  if (!bpf.empty()) {
    bpf_program prog{};
    if (pcap_compile(p, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
      err = std::format("Invalid capture filter: {}", pcap_geterr(p));
      pcap_close(p);
      return false;
    }
    if (pcap_setfilter(p, &prog) < 0) {
      err = std::format("Cannot apply capture filter: {}", pcap_geterr(p));
      pcap_freecode(&prog);
      pcap_close(p);
      return false;
    }
    pcap_freecode(&prog);
  }

  handle_ = reinterpret_cast<pcap*>(p);
  iface_ = iface;
  linktype_ = pcap_datalink(p);
  return true;
}

void Capture::start() {
  if (handle_ == nullptr || running_.load()) return;
  running_.store(true);
  thread_ = std::thread([this] { loop(); });
}

void Capture::stop() {
  if (!running_.exchange(false)) return;
  if (handle_ != nullptr) pcap_breakloop(reinterpret_cast<pcap_t*>(handle_));
  if (thread_.joinable()) thread_.join();
}

void Capture::loop() {
  auto* p = reinterpret_cast<pcap_t*>(handle_);
  while (running_.load(std::memory_order_relaxed)) {
    pcap_pkthdr* hdr = nullptr;
    const uint8_t* data = nullptr;
    const int rc = pcap_next_ex(p, &hdr, &data);
    if (rc == 0) continue;      // read timeout: poll the running flag again
    if (rc == PCAP_ERROR_BREAK) break;
    if (rc < 0) break;          // capture device went away
    if (hdr == nullptr || data == nullptr) continue;

    captured_.fetch_add(1, std::memory_order_relaxed);
    if (paused_.load(std::memory_order_relaxed)) continue;

    if (start_time_ == 0.0) start_time_ = now_seconds(hdr->ts);

    Packet pkt;
    pkt.no = next_no_++;
    pkt.ts = now_seconds(hdr->ts) - start_time_;
    pkt.wirelen = hdr->len;
    pkt.bytes.assign(data, data + hdr->caplen);
    pkt.d = dissect(pkt.bytes.data(), hdr->caplen, hdr->len, linktype_, false);

    {
      std::lock_guard<std::mutex> lock(mu_);
      if (pending_.size() < kPendingCap) {
        pending_.push_back(std::move(pkt));
      } else {
        ui_dropped_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    // libpcap is not safe to call concurrently on one handle, so the kernel
    // drop counter is sampled here rather than from the UI thread.
  }
  running_.store(false);
}

void Capture::drain(std::vector<Packet>& out) {
  std::vector<Packet> taken;
  {
    std::lock_guard<std::mutex> lock(mu_);
    taken.swap(pending_);
  }
  out.insert(out.end(), std::make_move_iterator(taken.begin()),
             std::make_move_iterator(taken.end()));
}

uint64_t Capture::dropped() const {
  return ui_dropped_.load(std::memory_order_relaxed) +
         kernel_dropped_.load(std::memory_order_relaxed);
}

} // namespace pv
