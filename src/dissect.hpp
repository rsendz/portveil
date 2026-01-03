// Pure packet dissection: bytes in, protocol tree out. No UI or capture deps.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pv {

// Application-layer hint used for row coloring and display filters.
enum class L7 { None, DNS, TLS, HTTP };

// One decoded header field, tagged with the byte range it occupies in the
// frame so the hex pane can highlight it.
struct Field {
  std::string name;
  std::string value;
  uint32_t offset = 0;
  uint32_t length = 0;
};

// A protocol layer: Frame, Ethernet, IPv4, TCP, DNS, ...
struct Section {
  std::string name;
  uint32_t offset = 0;
  uint32_t length = 0;
  std::vector<Field> fields;
};

struct Dissection {
  std::string src;   // source address as displayed in the packet list
  std::string dst;   // destination address
  std::string proto; // short label: TCP, UDP, DNS, TLS, HTTP, ARP, ICMP, ...
  std::string info;  // one-line summary
  std::string host;  // TLS SNI, HTTP Host, or DNS query name, when present

  uint16_t sport = 0;
  uint16_t dport = 0;
  bool has_ports = false;

  L7 l7 = L7::None;
  bool is_arp = false;
  bool is_ipv4 = false;
  bool is_ipv6 = false;
  bool is_tcp = false;
  bool is_udp = false;
  bool is_icmp = false;

  // Populated only when dissect() is called with detail = true.
  std::vector<Section> sections;
};

// Decodes one captured frame. `linktype` is the pcap DLT_* of the capture.
// With detail = false only the summary fields are filled, which is all the
// packet list and display filters need; the capture thread uses that path.
Dissection dissect(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                   int linktype, bool detail);

} // namespace pv
