#include "filter.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <sstream>

namespace pv {
namespace {

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) return true;
  return lower(haystack).find(needle) != std::string::npos;
}

bool parse_uint(const std::string& s, uint32_t& out) {
  if (s.empty()) return false;
  const char* begin = s.data();
  const char* end = s.data() + s.size();
  auto [ptr, ec] = std::from_chars(begin, end, out);
  return ec == std::errc() && ptr == end;
}

bool is_proto_word(const std::string& w) {
  static const char* kProtos[] = {"tcp",  "udp",  "icmp", "arp",  "dns",
                                  "tls",  "http", "quic", "ip",   "ipv4",
                                  "ipv6", "ssl"};
  return std::any_of(std::begin(kProtos), std::end(kProtos),
                     [&](const char* p) { return w == p; });
}

bool proto_matches(const std::string& want, const Packet& p) {
  const Dissection& d = p.d;
  if (want == "tcp") return d.is_tcp;
  if (want == "udp") return d.is_udp;
  if (want == "icmp") return d.is_icmp;
  if (want == "arp") return d.is_arp;
  if (want == "dns") return d.l7 == L7::DNS;
  if (want == "tls" || want == "ssl") return d.l7 == L7::TLS;
  if (want == "http") return d.l7 == L7::HTTP;
  if (want == "quic") return d.proto == "QUIC";
  if (want == "ipv4") return d.is_ipv4;
  if (want == "ipv6") return d.is_ipv6;
  if (want == "ip") return d.is_ipv4 || d.is_ipv6;
  return false;
}

} // namespace

void Filter::set(const std::string& text) {
  text_ = text;
  error_.clear();
  terms_.clear();

  std::istringstream in(lower(text));
  std::vector<std::string> words;
  for (std::string w; in >> w;) words.push_back(w);

  for (size_t i = 0; i < words.size(); ++i) {
    const std::string& w = words[i];

    if (is_proto_word(w)) {
      terms_.push_back({Kind::Proto, w, 0});
      continue;
    }

    // "port 443" / "port443" / "host example.com"
    auto take_arg = [&](std::string_view key, std::string& arg) -> bool {
      if (w.rfind(key, 0) != 0) return false;
      if (w.size() > key.size()) {
        arg = w.substr(key.size());
      } else if (i + 1 < words.size()) {
        arg = words[++i];
      } else {
        error_ = std::format("`{}` needs a value", key);
        return false;
      }
      return !arg.empty();
    };

    std::string arg;
    if (w.rfind("port", 0) == 0) {
      if (!take_arg("port", arg)) {
        if (error_.empty()) error_ = "`port` needs a number";
        continue;
      }
      uint32_t n = 0;
      if (!parse_uint(arg, n) || n > 65535) {
        error_ = std::format("`port {}` is not a valid port", arg);
        continue;
      }
      terms_.push_back({Kind::Port, {}, n});
      continue;
    }
    if (w.rfind("host", 0) == 0) {
      if (!take_arg("host", arg)) {
        if (error_.empty()) error_ = "`host` needs an address or name";
        continue;
      }
      terms_.push_back({Kind::Host, arg, 0});
      continue;
    }

    // len>500, len<100, len=64
    if (w.rfind("len", 0) == 0 && w.size() > 4) {
      const char op = w[3];
      uint32_t n = 0;
      if ((op == '>' || op == '<' || op == '=') && parse_uint(w.substr(4), n)) {
        terms_.push_back({op == '>'   ? Kind::LenGt
                          : op == '<' ? Kind::LenLt
                                      : Kind::LenEq,
                          {}, n});
        continue;
      }
      error_ = std::format("`{}` should look like len>500", w);
      continue;
    }

    terms_.push_back({Kind::Text, w, 0});
  }

  if (!error_.empty()) terms_.clear();
}

bool Filter::matches(const Packet& p) const {
  const Dissection& d = p.d;
  for (const Term& t : terms_) {
    switch (t.kind) {
      case Kind::Proto:
        if (!proto_matches(t.str, p)) return false;
        break;
      case Kind::Port:
        if (!d.has_ports || (d.sport != t.num && d.dport != t.num)) return false;
        break;
      case Kind::Host:
        if (!contains_ci(d.src, t.str) && !contains_ci(d.dst, t.str) &&
            !contains_ci(d.host, t.str)) {
          return false;
        }
        break;
      case Kind::LenGt:
        if (p.wirelen <= t.num) return false;
        break;
      case Kind::LenLt:
        if (p.wirelen >= t.num) return false;
        break;
      case Kind::LenEq:
        if (p.wirelen != t.num) return false;
        break;
      case Kind::Text:
        if (!contains_ci(d.info, t.str) && !contains_ci(d.proto, t.str) &&
            !contains_ci(d.src, t.str) && !contains_ci(d.dst, t.str) &&
            !contains_ci(d.host, t.str)) {
          return false;
        }
        break;
    }
  }
  return true;
}

} // namespace pv
