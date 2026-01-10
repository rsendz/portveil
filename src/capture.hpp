// libpcap capture session running on a background thread.
#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "dissect.hpp"

struct pcap; // pcap_t

namespace pv {

struct Iface {
  std::string name;
  std::string description;
  std::string address; // first IPv4/IPv6 address, when the interface has one
  bool up = false;
  bool loopback = false;
};

struct Packet {
  uint64_t no = 0;
  double ts = 0.0; // seconds since the capture started
  uint32_t wirelen = 0;
  std::vector<uint8_t> bytes;
  Dissection d; // summary only; call dissect(detail=true) for the tree
};

// Lists the interfaces libpcap can capture from. Returns an empty vector and
// sets `err` when the platform denies access.
std::vector<Iface> list_interfaces(std::string& err);

class Capture {
 public:
  ~Capture();

  // Opens a live capture. `bpf` may be empty. On failure returns false and
  // fills `err` with a message meant for the user, not a raw pcap string.
  bool open(const std::string& iface, const std::string& bpf, std::string& err);
  void start();
  void stop();

  // Moves the packets captured since the last call onto the end of `out`.
  void drain(std::vector<Packet>& out);

  void set_paused(bool p) { paused_.store(p, std::memory_order_relaxed); }
  bool paused() const { return paused_.load(std::memory_order_relaxed); }

  int linktype() const { return linktype_; }
  const std::string& iface() const { return iface_; }
  uint64_t captured() const { return captured_.load(std::memory_order_relaxed); }
  uint64_t dropped() const;

 private:
  void loop();

  pcap* handle_ = nullptr;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> paused_{false};
  std::atomic<uint64_t> captured_{0};
  std::atomic<uint64_t> ui_dropped_{0};     // dropped because the UI fell behind
  std::atomic<uint64_t> kernel_dropped_{0}; // dropped by the kernel buffer

  std::mutex mu_;
  std::vector<Packet> pending_;

  std::string iface_;
  int linktype_ = 0;
  uint64_t next_no_ = 1;
  double start_time_ = 0.0;
};

} // namespace pv
