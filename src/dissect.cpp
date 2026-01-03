#include "dissect.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <format>

namespace pv {
namespace {

// Bounds-checked view over the captured bytes. Every read goes through has().
struct Bytes {
  const uint8_t* p = nullptr;
  uint32_t n = 0;

  bool has(uint32_t off, uint32_t len) const {
    return off <= n && len <= n - off;
  }
  uint8_t u8(uint32_t o) const { return p[o]; }
  uint16_t u16(uint32_t o) const {
    return static_cast<uint16_t>(p[o] << 8 | p[o + 1]);
  }
  uint32_t u32(uint32_t o) const {
    return static_cast<uint32_t>(p[o]) << 24 | static_cast<uint32_t>(p[o + 1]) << 16 |
           static_cast<uint32_t>(p[o + 2]) << 8 | p[o + 3];
  }
};

std::string mac_str(const uint8_t* m) {
  return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2],
                     m[3], m[4], m[5]);
}

std::string ipv4_str(const uint8_t* a) {
  return std::format("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
}

const char* ip_proto_name(uint8_t p) {
  switch (p) {
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    case 58: return "ICMPv6";
    case 89: return "OSPF";
    case 132: return "SCTP";
    default: return "IP";
  }
}

// Walks the frame, filling a Dissection. Sections are only emitted when
// `detail_` is set, so the capture path stays allocation-light.
class Dissector {
 public:
  Dissector(Bytes b, uint32_t wirelen, bool detail)
      : b_(b), wirelen_(wirelen), detail_(detail) {}

  Dissection run(int linktype) {
    frame_section(linktype);

    uint32_t off = 0;
    uint16_t ethertype = 0;

    switch (linktype) {
      case DLT_EN10MB:
        if (!ethernet(off, ethertype)) return std::move(d_);
        off = 14;
        break;
      case DLT_NULL:
      case DLT_LOOP: {
        // 4-byte BSD loopback header holding an address family.
        if (!b_.has(0, 4)) return truncated();
        const uint32_t af_le = static_cast<uint32_t>(b_.p[0]) | b_.p[1] << 8 |
                               b_.p[2] << 16 | b_.p[3] << 24;
        const uint32_t af = (af_le == AF_INET || af_le == AF_INET6) ? af_le : b_.u32(0);
        ethertype = (af == AF_INET6) ? ETHERTYPE_IPV6 : ETHERTYPE_IP;
        open_section("Loopback", 0, 4);
        add("Address family", af == AF_INET6 ? "IPv6" : "IPv4", 0, 4);
        close_section();
        off = 4;
        break;
      }
      case DLT_RAW:
      default: {
        // Raw IP (tunnels): infer the version from the first nibble.
        if (!b_.has(0, 1)) return truncated();
        ethertype = (b_.u8(0) >> 4) == 6 ? ETHERTYPE_IPV6 : ETHERTYPE_IP;
        break;
      }
    }

    switch (ethertype) {
      case ETHERTYPE_IP: ipv4(off); break;
      case ETHERTYPE_ARP:
      case ETHERTYPE_REVARP: arp(off); break;
      default:
        d_.proto = "0x" + std::format("{:04x}", ethertype);
        if (d_.info.empty()) d_.info = "Unknown ethertype";
        break;
    }
    return std::move(d_);
  }

 private:
  Bytes b_;
  uint32_t wirelen_;
  bool detail_;
  Dissection d_;

  Dissection truncated() {
    if (d_.proto.empty()) d_.proto = "Frame";
    d_.info = "Truncated frame";
    return std::move(d_);
  }

  void open_section(std::string name, uint32_t off, uint32_t len) {
    if (!detail_) return;
    d_.sections.push_back({std::move(name), off, len, {}});
  }
  void close_section() {}
  void add(std::string name, std::string value, uint32_t off, uint32_t len) {
    if (!detail_ || d_.sections.empty()) return;
    d_.sections.back().fields.push_back({std::move(name), std::move(value), off, len});
  }

  void frame_section(int linktype) {
    if (!detail_) return;
    const char* dlt = pcap_datalink_val_to_name(linktype);
    open_section("Frame", 0, b_.n);
    add("Captured length", std::format("{} bytes", b_.n), 0, b_.n);
    add("Wire length", std::format("{} bytes", wirelen_), 0, b_.n);
    add("Link type", dlt ? dlt : std::format("DLT {}", linktype), 0, 0);
    close_section();
  }

  bool ethernet(uint32_t off, uint16_t& ethertype) {
    if (!b_.has(off, 14)) {
      truncated();
      return false;
    }
    ethertype = b_.u16(off + 12);
    open_section("Ethernet II", off, 14);
    add("Destination", mac_str(b_.p + off), off, 6);
    add("Source", mac_str(b_.p + off + 6), off + 6, 6);
    add("Type", std::format("0x{:04x}", ethertype), off + 12, 2);
    close_section();
    // Overwritten by the network layer when present; useful for ARP/unknown.
    d_.src = mac_str(b_.p + off + 6);
    d_.dst = mac_str(b_.p + off);
    return true;
  }

  void arp(uint32_t off) {
    d_.is_arp = true;
    d_.proto = "ARP";
    if (!b_.has(off, 28)) {
      d_.info = "Truncated ARP";
      return;
    }
    const uint16_t op = b_.u16(off + 6);
    const std::string sender_mac = mac_str(b_.p + off + 8);
    const std::string sender_ip = ipv4_str(b_.p + off + 14);
    const std::string target_ip = ipv4_str(b_.p + off + 24);

    open_section("ARP", off, 28);
    add("Hardware type", std::format("{}", b_.u16(off)), off, 2);
    add("Protocol type", std::format("0x{:04x}", b_.u16(off + 2)), off + 2, 2);
    add("Opcode", op == 1 ? "request (1)" : op == 2 ? "reply (2)" : std::format("{}", op),
        off + 6, 2);
    add("Sender MAC", sender_mac, off + 8, 6);
    add("Sender IP", sender_ip, off + 14, 4);
    add("Target MAC", mac_str(b_.p + off + 18), off + 18, 6);
    add("Target IP", target_ip, off + 24, 4);
    close_section();

    d_.src = sender_ip;
    d_.dst = target_ip;
    if (op == 1) {
      d_.info = std::format("Who has {}? Tell {}", target_ip, sender_ip);
    } else if (op == 2) {
      d_.info = std::format("{} is at {}", sender_ip, sender_mac);
    } else {
      d_.info = std::format("ARP opcode {}", op);
    }
  }

  void ipv4(uint32_t off) {
    d_.is_ipv4 = true;
    if (!b_.has(off, 20)) {
      d_.proto = "IPv4";
      d_.info = "Truncated IPv4 header";
      return;
    }
    const uint8_t ihl = (b_.u8(off) & 0x0f) * 4;
    const uint8_t proto = b_.u8(off + 9);
    const uint16_t total_len = b_.u16(off + 2);
    const uint16_t frag = b_.u16(off + 6);
    d_.src = ipv4_str(b_.p + off + 12);
    d_.dst = ipv4_str(b_.p + off + 16);
    d_.proto = ip_proto_name(proto);

    const uint32_t hdr_len = std::max<uint32_t>(ihl, 20);
    open_section("Internet Protocol Version 4", off, hdr_len);
    add("Version", "4", off, 1);
    add("Header length", std::format("{} bytes", ihl), off, 1);
    add("Differentiated services", std::format("0x{:02x}", b_.u8(off + 1)), off + 1, 1);
    add("Total length", std::format("{}", total_len), off + 2, 2);
    add("Identification", std::format("0x{:04x}", b_.u16(off + 4)), off + 4, 2);
    add("Flags", std::format("{}{}", (frag & 0x4000) ? "DF" : "",
                             (frag & 0x2000) ? " MF" : ""),
        off + 6, 1);
    add("Fragment offset", std::format("{}", (frag & 0x1fff) * 8), off + 6, 2);
    add("Time to live", std::format("{}", b_.u8(off + 8)), off + 8, 1);
    add("Protocol", std::format("{} ({})", ip_proto_name(proto), proto), off + 9, 1);
    add("Header checksum", std::format("0x{:04x}", b_.u16(off + 10)), off + 10, 2);
    add("Source", d_.src, off + 12, 4);
    add("Destination", d_.dst, off + 16, 4);
    close_section();

  }

};

} // namespace

Dissection dissect(const uint8_t* data, uint32_t caplen, uint32_t wirelen, int linktype,
                   bool detail) {
  Dissector dis(Bytes{data, caplen}, wirelen, detail);
  return dis.run(linktype);
}

} // namespace pv
