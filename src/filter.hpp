// Display filter: space-separated terms, all of which must match (AND).
//
//   tcp udp icmp arp dns tls http quic ipv4 ipv6   protocol tests
//   port 443            port N        endpoint port on either side
//   host example.com    host 1.2.3.4  substring of either address, SNI,
//                                     HTTP Host or DNS query name
//   len>500  len<100  len=64          captured frame length
//   anything else                     substring match against the info column
#pragma once

#include <string>
#include <vector>

#include "capture.hpp"

namespace pv {

class Filter {
 public:
  // Compiles `text`. Always succeeds; unparsable terms are reported in error()
  // and the filter falls back to matching everything.
  void set(const std::string& text);

  bool matches(const Packet& p) const;
  bool empty() const { return terms_.empty(); }
  const std::string& text() const { return text_; }
  const std::string& error() const { return error_; }

 private:
  enum class Kind { Proto, Port, Host, LenGt, LenLt, LenEq, Text };
  struct Term {
    Kind kind = Kind::Text;
    std::string str; // protocol name, host substring, or free text
    uint32_t num = 0;
  };

  std::string text_;
  std::string error_;
  std::vector<Term> terms_;
};

} // namespace pv
