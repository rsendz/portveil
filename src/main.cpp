#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "capture.hpp"
#include "ui.hpp"

namespace {

void usage() {
  std::puts(R"(portveil — a Wireshark-style packet analyzer for the terminal

USAGE
  sudo portveil [options]

OPTIONS
  -i, --interface <name>   capture on this interface (skips the picker)
  -f, --filter <expr>      libpcap capture filter, e.g. "tcp port 443"
  -l, --list               list capture interfaces and exit
  -d, --dump <n>           print n packets as plain text and exit (no UI)
  -v, --version            print the version and exit
  -h, --help               show this help

KEYS
  ↑ ↓ / j k  move          tab  cycle panes      /  display filter
  → ←        expand layer  p    pause            c  clear
  g / G      first / last  ?    help             q  quit

Capturing needs raw access to the network device, so portveil is normally
run with sudo.)");
}

// Non-interactive mode: capture `count` packets and print each one the way the
// UI would show it, so output can be piped or diffed.
int dump(pv::Capture& cap, int count) {
  std::vector<pv::Packet> packets;
  int printed = 0;
  while (printed < count) {
    const size_t before = packets.size();
    cap.drain(packets);
    if (packets.size() == before) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }
    for (size_t i = before; i < packets.size() && printed < count; ++i, ++printed) {
      const pv::Packet& p = packets[i];
      std::printf("%6llu  %8.3f  %-22s %-22s %-8s %5u  %s\n",
                  static_cast<unsigned long long>(p.no), p.ts, p.d.src.c_str(),
                  p.d.dst.c_str(), p.d.proto.c_str(), p.wirelen, p.d.info.c_str());
    }
  }
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  std::string iface;
  std::string bpf;
  bool list_only = false;
  int dump_count = 0;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&](const char* what) -> std::string {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "portveil: %s expects a value\n", what);
        std::exit(2);
      }
      return argv[++i];
    };

    if (a == "-i" || a == "--interface") {
      iface = next("--interface");
    } else if (a.rfind("--interface=", 0) == 0) {
      iface = a.substr(std::strlen("--interface="));
    } else if (a == "-f" || a == "--filter") {
      bpf = next("--filter");
    } else if (a.rfind("--filter=", 0) == 0) {
      bpf = a.substr(std::strlen("--filter="));
    } else if (a == "-l" || a == "--list") {
      list_only = true;
    } else if (a == "-d" || a == "--dump") {
      dump_count = std::atoi(next("--dump").c_str());
      if (dump_count <= 0) {
        std::fprintf(stderr, "portveil: --dump expects a positive count\n");
        return 2;
      }
    } else if (a == "-v" || a == "--version") {
      std::printf("portveil %s\n", PORTVEIL_VERSION);
      return 0;
    } else if (a == "-h" || a == "--help") {
      usage();
      return 0;
    } else {
      std::fprintf(stderr, "portveil: unknown option '%s' (try --help)\n", a.c_str());
      return 2;
    }
  }

  std::string err;
  const std::vector<pv::Iface> ifaces = pv::list_interfaces(err);
  if (ifaces.empty()) {
    std::fprintf(stderr, "portveil: no capture interfaces available.\n%s\n",
                 err.empty() ? "" : err.c_str());
    return 1;
  }

  if (list_only) {
    for (const pv::Iface& f : ifaces) {
      std::printf("%-16s %-40s%s%s\n", f.name.c_str(),
                  f.address.empty() ? "-" : f.address.c_str(),
                  f.up ? "up" : "down", f.loopback ? " loopback" : "");
    }
    return 0;
  }

  if (iface.empty() && dump_count > 0) iface = ifaces.front().name;

  if (iface.empty()) {
    const auto chosen = pv::pick_interface(ifaces);
    if (!chosen.has_value()) return 0; // user quit the picker
    iface = *chosen;
  }

  pv::Capture cap;
  if (!cap.open(iface, bpf, err)) {
    std::fprintf(stderr, "portveil: %s\n", err.c_str());
    return 1;
  }

  cap.start();
  const int rc = dump_count > 0 ? dump(cap, dump_count) : (pv::run_ui(cap), 0);
  cap.stop();
  return rc;
}
