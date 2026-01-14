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

std::string ipv6_str(const uint8_t* a) {
  char buf[INET6_ADDRSTRLEN] = {};
  if (!inet_ntop(AF_INET6, a, buf, sizeof buf)) return "?";
  return buf;
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

const char* dns_type_name(uint16_t t) {
  switch (t) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 41: return "OPT";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return "?";
  }
}

const char* dns_rcode_name(uint8_t r) {
  switch (r) {
    case 0: return "No error";
    case 1: return "Format error";
    case 2: return "Server failure";
    case 3: return "No such name";
    case 4: return "Not implemented";
    case 5: return "Refused";
    default: return "Unknown";
  }
}

const char* tls_version_name(uint16_t v) {
  switch (v) {
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: return "TLS";
  }
}

// Reads a DNS name, following compression pointers. Returns the encoded length
// consumed at `off` (0 on malformed input); the expanded name goes to `out`.
uint32_t dns_name(const Bytes& b, uint32_t dns_start, uint32_t off, std::string& out) {
  uint32_t consumed = 0;
  bool jumped = false;
  int guard = 0;

  while (guard++ < 64) {
    if (!b.has(off, 1)) return 0;
    const uint8_t len = b.u8(off);
    if (len == 0) {
      if (!jumped) consumed += 1;
      if (out.empty()) out = "<root>";
      return consumed;
    }
    if ((len & 0xc0) == 0xc0) { // compression pointer
      if (!b.has(off, 2)) return 0;
      const uint32_t target = dns_start + (b.u16(off) & 0x3fff);
      if (!jumped) consumed += 2;
      if (target >= off) return 0; // pointers must point backwards
      off = target;
      jumped = true;
      continue;
    }
    if ((len & 0xc0) != 0) return 0; // reserved label type
    if (!b.has(off + 1, len)) return 0;
    if (!out.empty()) out.push_back('.');
    for (uint32_t i = 0; i < len; ++i) {
      const uint8_t c = b.p[off + 1 + i];
      out.push_back(c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '.');
    }
    off += 1 + len;
    if (!jumped) consumed += 1 + len;
  }
  return 0;
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
      case ETHERTYPE_IPV6: ipv6(off); break;
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

    if ((frag & 0x1fff) != 0) { // non-first fragment: no usable L4 header
      d_.info = std::format("Fragmented IP protocol (proto={} off={})", proto,
                            (frag & 0x1fff) * 8);
      return;
    }
    // Trust the header length only if it is sane and within the capture.
    const uint32_t l4 = off + (ihl >= 20 ? ihl : 20);
    transport(proto, l4);
  }

  void ipv6(uint32_t off) {
    d_.is_ipv6 = true;
    if (!b_.has(off, 40)) {
      d_.proto = "IPv6";
      d_.info = "Truncated IPv6 header";
      return;
    }
    uint8_t next = b_.u8(off + 6);
    d_.src = ipv6_str(b_.p + off + 8);
    d_.dst = ipv6_str(b_.p + off + 24);
    d_.proto = ip_proto_name(next);

    open_section("Internet Protocol Version 6", off, 40);
    add("Version", "6", off, 1);
    add("Traffic class", std::format("0x{:02x}", ((b_.u16(off) >> 4) & 0xff)), off, 2);
    add("Flow label", std::format("0x{:05x}", b_.u32(off) & 0xfffff), off + 1, 3);
    add("Payload length", std::format("{}", b_.u16(off + 4)), off + 4, 2);
    add("Next header", std::format("{} ({})", ip_proto_name(next), next), off + 6, 1);
    add("Hop limit", std::format("{}", b_.u8(off + 7)), off + 7, 1);
    add("Source", d_.src, off + 8, 16);
    add("Destination", d_.dst, off + 24, 16);
    close_section();

    // Walk the common extension headers to reach the transport header.
    uint32_t cur = off + 40;
    for (int i = 0; i < 8; ++i) {
      const bool is_ext = next == 0 || next == 43 || next == 60 || next == 51;
      if (!is_ext) break;
      if (!b_.has(cur, 2)) {
        d_.info = "Truncated IPv6 extension header";
        return;
      }
      const uint32_t ext_len = (next == 51) ? (b_.u8(cur + 1) + 2u) * 4u
                                            : (b_.u8(cur + 1) + 1u) * 8u;
      next = b_.u8(cur);
      cur += ext_len;
      d_.proto = ip_proto_name(next);
    }
    if (next == 44) { // fragment header: payload is not a full L4 header
      d_.proto = "IPv6";
      d_.info = "IPv6 fragment";
      return;
    }
    transport(next, cur);
  }

  void transport(uint8_t proto, uint32_t off) {
    switch (proto) {
      case 6: tcp(off); break;
      case 17: udp(off); break;
      case 1: icmp(off, false); break;
      case 58: icmp(off, true); break;
      default:
        if (d_.info.empty()) {
          d_.info = std::format("{} payload, {} bytes", ip_proto_name(proto),
                                b_.has(off, 0) ? b_.n - off : 0);
        }
        break;
    }
  }

  void tcp(uint32_t off) {
    d_.is_tcp = true;
    d_.proto = "TCP";
    if (!b_.has(off, 20)) {
      d_.info = "Truncated TCP header";
      return;
    }
    const uint16_t sport = b_.u16(off);
    const uint16_t dport = b_.u16(off + 2);
    const uint32_t seq = b_.u32(off + 4);
    const uint32_t ack = b_.u32(off + 8);
    const uint8_t data_off = (b_.u8(off + 12) >> 4) * 4;
    const uint8_t flags = b_.u8(off + 13);
    const uint16_t win = b_.u16(off + 14);
    d_.sport = sport;
    d_.dport = dport;
    d_.has_ports = true;

    std::string flag_str;
    const std::pair<uint8_t, const char*> kFlags[] = {
        {0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"},
        {0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"}};
    for (const auto& [bit, name] : kFlags) {
      if (flags & bit) {
        if (!flag_str.empty()) flag_str += ", ";
        flag_str += name;
      }
    }

    const uint32_t hdr = std::max<uint32_t>(data_off, 20);
    open_section("Transmission Control Protocol", off, hdr);
    add("Source port", std::format("{}", sport), off, 2);
    add("Destination port", std::format("{}", dport), off + 2, 2);
    add("Sequence number", std::format("{}", seq), off + 4, 4);
    add("Acknowledgment number", std::format("{}", ack), off + 8, 4);
    add("Header length", std::format("{} bytes", data_off), off + 12, 1);
    add("Flags", std::format("0x{:03x} [{}]", flags, flag_str), off + 13, 1);
    add("Window", std::format("{}", win), off + 14, 2);
    add("Checksum", std::format("0x{:04x}", b_.u16(off + 16)), off + 16, 2);
    close_section();

    const uint32_t payload = off + hdr;
    const uint32_t payload_len = b_.has(payload, 0) ? b_.n - payload : 0;
    d_.info = std::format("{} → {} [{}] Seq={} Ack={} Win={} Len={}", sport, dport,
                          flag_str.empty() ? "none" : flag_str, seq, ack, win,
                          payload_len);

    if (payload_len == 0) return;
    if (sport == 53 || dport == 53) {
      dns(payload); // DNS over TCP is length-prefixed
      return;
    }
    if (tls(payload)) return;
    if (payload_len > 0) {
      open_section("Payload", payload, payload_len);
      add("Data", std::format("{} bytes", payload_len), payload, payload_len);
      close_section();
    }
  }

  void udp(uint32_t off) {
    d_.is_udp = true;
    d_.proto = "UDP";
    if (!b_.has(off, 8)) {
      d_.info = "Truncated UDP header";
      return;
    }
    const uint16_t sport = b_.u16(off);
    const uint16_t dport = b_.u16(off + 2);
    const uint16_t len = b_.u16(off + 4);
    d_.sport = sport;
    d_.dport = dport;
    d_.has_ports = true;

    open_section("User Datagram Protocol", off, 8);
    add("Source port", std::format("{}", sport), off, 2);
    add("Destination port", std::format("{}", dport), off + 2, 2);
    add("Length", std::format("{}", len), off + 4, 2);
    add("Checksum", std::format("0x{:04x}", b_.u16(off + 6)), off + 6, 2);
    close_section();

    const uint32_t payload = off + 8;
    const uint32_t payload_len = b_.has(payload, 0) ? b_.n - payload : 0;
    d_.info = std::format("{} → {} Len={}", sport, dport, payload_len);
    if (payload_len == 0) return;

    if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) {
      dns(payload);
      return;
    }
    if (sport == 443 || dport == 443) { // QUIC: label it, don't decode
      d_.proto = "QUIC";
      d_.info = std::format("QUIC {} → {} Len={}", sport, dport, payload_len);
      return;
    }
    open_section("Payload", payload, payload_len);
    add("Data", std::format("{} bytes", payload_len), payload, payload_len);
    close_section();
  }

  void icmp(uint32_t off, bool v6) {
    d_.is_icmp = true;
    d_.proto = v6 ? "ICMPv6" : "ICMP";
    if (!b_.has(off, 4)) {
      d_.info = "Truncated ICMP header";
      return;
    }
    const uint8_t type = b_.u8(off);
    const uint8_t code = b_.u8(off + 1);

    std::string desc;
    if (v6) {
      switch (type) {
        case 128: desc = "Echo request"; break;
        case 129: desc = "Echo reply"; break;
        case 133: desc = "Router solicitation"; break;
        case 134: desc = "Router advertisement"; break;
        case 135: desc = "Neighbor solicitation"; break;
        case 136: desc = "Neighbor advertisement"; break;
        case 1: desc = "Destination unreachable"; break;
        case 3: desc = "Time exceeded"; break;
        default: desc = std::format("Type {}", type); break;
      }
    } else {
      switch (type) {
        case 0: desc = "Echo (ping) reply"; break;
        case 3: desc = "Destination unreachable"; break;
        case 8: desc = "Echo (ping) request"; break;
        case 11: desc = "Time-to-live exceeded"; break;
        default: desc = std::format("Type {}", type); break;
      }
    }

    open_section(v6 ? "Internet Control Message Protocol v6"
                    : "Internet Control Message Protocol",
                 off, 8);
    add("Type", std::format("{} ({})", type, desc), off, 1);
    add("Code", std::format("{}", code), off + 1, 1);
    add("Checksum", std::format("0x{:04x}", b_.u16(off + 2)), off + 2, 2);

    const bool echo = v6 ? (type == 128 || type == 129) : (type == 0 || type == 8);
    if (echo && b_.has(off + 4, 4)) {
      const uint16_t id = b_.u16(off + 4);
      const uint16_t seq = b_.u16(off + 6);
      add("Identifier", std::format("{}", id), off + 4, 2);
      add("Sequence number", std::format("{}", seq), off + 6, 2);
      d_.info = std::format("{}  id={} seq={}", desc, id, seq);
    } else {
      d_.info = desc;
    }
    close_section();
  }

  void dns(uint32_t off) {
    // DNS over TCP prefixes the message with a 2-byte length.
    if (d_.is_tcp) {
      if (!b_.has(off, 2)) return;
      off += 2;
    }
    if (!b_.has(off, 12)) {
      d_.proto = "DNS";
      d_.info = "Truncated DNS header";
      return;
    }
    d_.proto = "DNS";
    d_.l7 = L7::DNS;

    const uint16_t id = b_.u16(off);
    const uint16_t flags = b_.u16(off + 2);
    const bool response = (flags & 0x8000) != 0;
    const uint8_t opcode = (flags >> 11) & 0x0f;
    const uint8_t rcode = flags & 0x0f;
    const uint16_t qd = b_.u16(off + 4);
    const uint16_t an = b_.u16(off + 6);

    open_section("Domain Name System", off, b_.n - off);
    add("Transaction ID", std::format("0x{:04x}", id), off, 2);
    add("Flags", std::format("0x{:04x} ({})", flags, response ? "response" : "query"),
        off + 2, 2);
    add("Questions", std::format("{}", qd), off + 4, 2);
    add("Answer RRs", std::format("{}", an), off + 6, 2);
    add("Authority RRs", std::format("{}", b_.u16(off + 8)), off + 8, 2);
    add("Additional RRs", std::format("{}", b_.u16(off + 10)), off + 10, 2);

    std::string qname;
    std::string qtype = "?";
    uint32_t cur = off + 12;
    if (qd > 0) {
      const uint32_t used = dns_name(b_, off, cur, qname);
      if (used > 0 && b_.has(cur + used, 4)) {
        add("Query name", qname, cur, used);
        const uint16_t t = b_.u16(cur + used);
        qtype = dns_type_name(t);
        add("Query type", std::format("{} ({})", qtype, t), cur + used, 2);
        cur += used + 4;
      } else {
        cur = 0; // malformed; stop before the answer section
      }
      d_.host = qname;
    }

    // Decode the first answer's rdata for the common record types.
    std::string answer;
    std::string aname;
    std::string atype;
    if (response && an > 0 && cur != 0) {
      std::string rname;
      const uint32_t used = dns_name(b_, off, cur, rname);
      if (used > 0 && b_.has(cur + used, 10)) {
        const uint32_t rr = cur + used;
        const uint16_t rtype = b_.u16(rr);
        const uint16_t rdlen = b_.u16(rr + 8);
        const uint32_t rdata = rr + 10;
        aname = rname;
        atype = dns_type_name(rtype);
        add("Answer name", rname, cur, used);
        add("Answer type", std::format("{} ({})", dns_type_name(rtype), rtype), rr, 2);
        add("TTL", std::format("{}", b_.u32(rr + 4)), rr + 4, 4);
        if (rtype == 1 && rdlen == 4 && b_.has(rdata, 4)) {
          answer = ipv4_str(b_.p + rdata);
          add("Address", answer, rdata, 4);
        } else if (rtype == 28 && rdlen == 16 && b_.has(rdata, 16)) {
          answer = ipv6_str(b_.p + rdata);
          add("Address", answer, rdata, 16);
        } else if (rtype == 5 && b_.has(rdata, rdlen)) {
          std::string cname;
          if (dns_name(b_, off, rdata, cname) > 0) {
            answer = cname;
            add("CNAME", cname, rdata, rdlen);
          }
        }
      }
    }
    close_section();

    // mDNS announcements carry no question, so fall back to the first answer.
    std::string name = qname;
    std::string type = qtype;
    if (name.empty() && !aname.empty()) {
      name = aname;
      type = atype;
      d_.host = aname;
    }

    const char* kind = opcode == 0 ? "Standard query" : "Query";
    if (!response) {
      d_.info = std::format("{} 0x{:04x} {} {}", kind, id, type, name);
    } else if (rcode != 0) {
      d_.info = std::format("{} response 0x{:04x} {} {} — {}", kind, id, type, name,
                            dns_rcode_name(rcode));
    } else if (!answer.empty()) {
      d_.info =
          std::format("{} response 0x{:04x} {} {} → {}", kind, id, type, name, answer);
    } else {
      d_.info = std::format("{} response 0x{:04x} {} {}", kind, id, type, name);
    }
    if (an > 1) d_.info += std::format(" (+{} more)", an - 1);
  }

  // Returns true if the payload parsed as a TLS record.
  bool tls(uint32_t off) {
    if (!b_.has(off, 5)) return false;
    const uint8_t type = b_.u8(off);
    const uint16_t ver = b_.u16(off + 1);
    const uint16_t len = b_.u16(off + 3);
    if (type < 20 || type > 24) return false;
    if ((ver >> 8) != 0x03) return false;

    d_.proto = "TLS";
    d_.l7 = L7::TLS;

    const char* type_name = "Record";
    switch (type) {
      case 20: type_name = "Change Cipher Spec"; break;
      case 21: type_name = "Alert"; break;
      case 22: type_name = "Handshake"; break;
      case 23: type_name = "Application Data"; break;
      default: break;
    }

    open_section("Transport Layer Security", off, std::min<uint32_t>(len + 5, b_.n - off));
    add("Content type", std::format("{} ({})", type_name, type), off, 1);
    add("Version", std::format("{} (0x{:04x})", tls_version_name(ver), ver), off + 1, 2);
    add("Length", std::format("{}", len), off + 3, 2);

    std::string summary = type_name;
    if (type == 22 && b_.has(off + 5, 4)) {
      const uint8_t hs = b_.u8(off + 5);
      switch (hs) {
        case 1: summary = "Client Hello"; break;
        case 2: summary = "Server Hello"; break;
        case 4: summary = "New Session Ticket"; break;
        case 11: summary = "Certificate"; break;
        case 12: summary = "Server Key Exchange"; break;
        case 16: summary = "Client Key Exchange"; break;
        case 20: summary = "Finished"; break;
        default: summary = std::format("Handshake type {}", hs); break;
      }
      add("Handshake type", std::format("{} ({})", summary, hs), off + 5, 1);
      if (hs == 1) {
        std::string sni;
        if (client_hello_sni(off + 9, sni) && !sni.empty()) {
          d_.host = sni;
          add("Server Name Indication", sni, off + 9, 0);
          summary += std::format(" (SNI={})", sni);
        }
      }
    }
    close_section();
    d_.info = std::format("{} — {}", tls_version_name(ver), summary);
    return true;
  }

  // Walks a ClientHello body to the server_name extension. `off` is the first
  // byte after the handshake header (i.e. client_version).
  bool client_hello_sni(uint32_t off, std::string& sni) {
    if (!b_.has(off, 34)) return false;
    uint32_t cur = off + 34; // client_version(2) + random(32)

    if (!b_.has(cur, 1)) return false;
    cur += 1 + b_.u8(cur); // session id

    if (!b_.has(cur, 2)) return false;
    cur += 2 + b_.u16(cur); // cipher suites

    if (!b_.has(cur, 1)) return false;
    cur += 1 + b_.u8(cur); // compression methods

    if (!b_.has(cur, 2)) return false;
    const uint32_t ext_end = cur + 2 + b_.u16(cur);
    cur += 2;

    while (cur + 4 <= ext_end && b_.has(cur, 4)) {
      const uint16_t ext_type = b_.u16(cur);
      const uint16_t ext_len = b_.u16(cur + 2);
      const uint32_t body = cur + 4;
      if (ext_type == 0) { // server_name
        if (!b_.has(body, 5)) return false;
        const uint16_t name_len = b_.u16(body + 3);
        if (!b_.has(body + 5, name_len)) return false;
        sni.assign(reinterpret_cast<const char*>(b_.p + body + 5), name_len);
        return true;
      }
      cur = body + ext_len;
    }
    return false;
  }
};

} // namespace

Dissection dissect(const uint8_t* data, uint32_t caplen, uint32_t wirelen, int linktype,
                   bool detail) {
  Dissector dis(Bytes{data, caplen}, wirelen, detail);
  return dis.run(linktype);
}

} // namespace pv
