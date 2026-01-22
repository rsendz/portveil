#include "ui.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/screen/string.hpp>
#include <ftxui/screen/terminal.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <format>
#include <thread>

#include "filter.hpp"

using namespace ftxui;

namespace pv {
namespace {

constexpr size_t kMaxPackets = 4000; // packets of history kept in memory
constexpr size_t kTrimChunk = 256;   // erase in batches to keep trimming cheap
constexpr auto kRefresh = std::chrono::milliseconds(150);

// --- theme -------------------------------------------------------------------

struct Theme {
  Color bg, bar_bg, accent, on_accent, text, muted, dim, warn, error;
  Color sel_bg, sel_bg_idle;   // selected row, in the focused / unfocused pane
  Color hl_bg, hl_fg;          // bytes of the selected field
  Color dns, tls, http, quic, arp, icmp, tcp, udp;
  std::array<Color, 6> sections;
};

const Theme kDark = {
    .bg = Color::RGB(15, 23, 42),
    .bar_bg = Color::RGB(30, 41, 59),
    .accent = Color::RGB(94, 234, 212),
    .on_accent = Color::RGB(4, 30, 30),
    .text = Color::RGB(226, 232, 240),
    .muted = Color::RGB(148, 163, 184),
    .dim = Color::RGB(100, 116, 139),
    .warn = Color::RGB(251, 146, 60),
    .error = Color::RGB(248, 113, 113),
    .sel_bg = Color::RGB(51, 65, 85),
    .sel_bg_idle = Color::RGB(34, 43, 60),
    .hl_bg = Color::RGB(22, 78, 99),
    .hl_fg = Color::RGB(224, 242, 254),
    .dns = Color::RGB(103, 232, 249),
    .tls = Color::RGB(196, 181, 253),
    .http = Color::RGB(253, 224, 71),
    .quic = Color::RGB(167, 139, 250),
    .arp = Color::RGB(148, 163, 184),
    .icmp = Color::RGB(134, 239, 172),
    .tcp = Color::RGB(147, 197, 253),
    .udp = Color::RGB(125, 211, 252),
    .sections = {Color::RGB(148, 163, 184), Color::RGB(134, 239, 172),
                 Color::RGB(147, 197, 253), Color::RGB(253, 186, 116),
                 Color::RGB(196, 181, 253), Color::RGB(244, 114, 182)},
};

const Theme* g_theme = &kDark;
const Theme& th() { return *g_theme; }

Color proto_color(const Dissection& d) {
  switch (d.l7) {
    case L7::DNS: return th().dns;
    case L7::TLS: return th().tls;
    case L7::HTTP: return th().http;
    case L7::None: break;
  }
  if (d.proto == "QUIC") return th().quic;
  if (d.is_arp) return th().arp;
  if (d.is_icmp) return th().icmp;
  if (d.is_tcp) return th().tcp;
  if (d.is_udp) return th().udp;
  return th().text;
}

Color section_color(size_t i) { return th().sections[i % th().sections.size()]; }

// --- small helpers -----------------------------------------------------------

std::string commas(uint64_t n) {
  std::string s = std::format("{}", n);
  for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3) s.insert(i, ",");
  return s;
}

// Column arithmetic, not byte arithmetic: the rows carry "…" and "→", which
// are three bytes wide but occupy a single cell.
size_t utf8_seq_len(uint8_t lead) {
  if (lead >= 0xf0) return 4;
  if (lead >= 0xe0) return 3;
  if (lead >= 0xc0) return 2;
  return 1;
}

// Byte index at which `s` has covered `cols` display columns.
size_t byte_at_column(const std::string& s, int cols) {
  int c = 0;
  size_t i = 0;
  while (i < s.size() && c < cols) {
    const size_t n = std::min(utf8_seq_len(static_cast<uint8_t>(s[i])), s.size() - i);
    c += string_width(s.substr(i, n));
    i += n;
  }
  return i;
}

// Pads or ellipsis-truncates to exactly `width` display columns.
std::string fit(std::string s, int width) {
  const int w = string_width(s);
  if (w == width) return s;
  if (w < width) return s + std::string(width - w, ' ');
  if (width <= 1) return std::string(width, ' ');
  return s.substr(0, byte_at_column(s, width - 1)) + "…";
}

// A run of text in a row, kept as data so the row can be scrolled sideways
// without losing its per-column colors.
struct Seg {
  std::string text;
  Color color;
  bool bold = false;
};

int segs_width(const std::vector<Seg>& segs) {
  int w = 0;
  for (const Seg& s : segs) w += string_width(s.text);
  return w;
}

// Renders a row shifted left by `offset` columns and clipped to `avail`.
//
// The clipping is what keeps the columns aligned: an hbox wider than its pane
// makes FTXUI shrink every child proportionally, size() constraints included
// (see ComputeShrinkHard), which knocks a column off each field. Trimming the
// row to the pane width here means that never happens.
Element row_from(const std::vector<Seg>& segs, int offset, int avail) {
  Elements out;
  int pos = 0;  // column reached within the untrimmed row
  int used = 0; // columns emitted so far
  for (const Seg& s : segs) {
    if (used >= avail) break;
    const int len = string_width(s.text);
    if (pos + len <= offset) {
      pos += len;
      continue;
    }
    const int cut = std::max(0, offset - pos);
    std::string t = s.text.substr(cut > 0 ? byte_at_column(s.text, cut) : 0);
    int vis = len - cut;
    if (vis > avail - used) {
      vis = avail - used;
      t = t.substr(0, byte_at_column(t, vis));
    }
    Element e = text(std::move(t));
    if (s.bold) e = e | bold;
    out.push_back(e | color(s.color) | size(WIDTH, EQUAL, vis));
    used += vis;
    pos += len;
  }
  if (out.empty()) out.push_back(text(""));
  return hbox(std::move(out));
}

int box_height(const Box& b) { return std::max(0, b.y_max - b.y_min + 1); }
int box_width(const Box& b) { return std::max(0, b.x_max - b.x_min + 1); }

// Reflected boxes are a frame behind, and empty before the first render, so a
// caller-supplied fallback keeps the very first frame correct.
int view_height(const Box& b, int fallback) {
  const int h = box_height(b);
  return h > 1 ? h : std::max(1, fallback);
}

void scroll_to(int& scroll, int sel, int height, int total) {
  if (height <= 0) return;
  if (sel < scroll) scroll = sel;
  if (sel >= scroll + height) scroll = sel - height + 1;
  scroll = std::clamp(scroll, 0, std::max(0, total - height));
}

enum class Pane { List, Detail, Hex };

struct TreeRow {
  int section = 0;
  int field = -1; // -1 marks the section header row
};

// Geometry of one hex row: "0000  " then 3 columns per byte with a gap after
// the middle group, a spacer, then the ASCII gutter.
struct HexLayout {
  int per_row;
  int offset_w = 6;
  int hex_at(int c) const { return offset_w + c * 3 + (c >= per_row / 2 ? 1 : 0); }
  int ascii_start() const { return offset_w + per_row * 3 + 2; }
  int ascii_at(int c) const { return ascii_start() + c + (c >= per_row / 2 ? 1 : 0); }
  int width() const { return ascii_at(per_row - 1) + 1; }

  // Byte column under a pane-relative x, or -1. A byte owns the blank that
  // follows it, so pointing between two digits still lands on one.
  int column_at(int rx) const {
    for (int c = 0; c < per_row; ++c) {
      const int s = hex_at(c);
      if (rx >= s && rx < s + 3) return c;
      if (rx == ascii_at(c)) return c;
    }
    return -1;
  }
};

class App {
 public:
  explicit App(Capture& cap) : cap_(cap) {}

  void run() {
    auto screen = ScreenInteractive::Fullscreen();
    // FTXUI v5.0.0 leaves Screen::Cursor::shape default-initialized, so give it
    // a value before the first render reads it.
    screen.SetCursor({0, 0, Screen::Cursor::Hidden});
    screen_ = &screen;

    auto component = Renderer([this] { return render(); });
    component |= CatchEvent([this](Event e) { return on_event(e); });

    std::atomic<bool> alive{true};
    std::thread ticker([&] {
      while (alive.load()) {
        std::this_thread::sleep_for(kRefresh);
        screen.PostEvent(Event::Custom);
      }
    });

    screen.Loop(component);
    alive.store(false);
    ticker.join();
    screen_ = nullptr;
  }

 private:
  Capture& cap_;
  ScreenInteractive* screen_ = nullptr;

  std::vector<Packet> packets_;
  uint64_t base_ = 0;
  std::vector<uint64_t> shown_;

  Filter filter_;
  bool editing_filter_ = false;
  std::string filter_draft_;

  Pane focus_ = Pane::List;
  bool follow_ = true;
  bool show_help_ = false;

  int sel_ = 0, list_scroll_ = 0, list_hscroll_ = 0;
  int list_max_width_ = 0; // widest rendered row, to bound sideways scrolling
  int detail_sel_ = 0, detail_scroll_ = 0;
  int hex_scroll_ = 0;
  int hex_rows_ = 0;
  int hex_per_row_ = 16;
  uint32_t hex_cursor_ = 0; // byte the hex pane points at
  bool hex_hover_ = false;  // mouse resting over the bytes pane

  uint64_t detail_no_ = 0;
  Dissection detail_;
  std::vector<bool> collapsed_;
  std::vector<TreeRow> tree_;

  Box list_box_, detail_box_, hex_box_;

  // The bytes pane is "live" when it holds focus or the mouse is over it.
  bool hex_active() const { return focus_ == Pane::Hex || hex_hover_; }

  const Packet* at(uint64_t abs) const {
    if (abs < base_) return nullptr;
    const size_t i = abs - base_;
    return i < packets_.size() ? &packets_[i] : nullptr;
  }

  const Packet* selected() const {
    if (shown_.empty()) return nullptr;
    const int s = std::clamp(sel_, 0, static_cast<int>(shown_.size()) - 1);
    return at(shown_[s]);
  }

  // --- state ---------------------------------------------------------------

  void sync() {
    const size_t before = packets_.size();
    cap_.drain(packets_);
    for (size_t i = before; i < packets_.size(); ++i) {
      if (filter_.matches(packets_[i])) shown_.push_back(base_ + i);
    }

    if (packets_.size() > kMaxPackets + kTrimChunk) {
      packets_.erase(packets_.begin(), packets_.begin() + kTrimChunk);
      base_ += kTrimChunk;
      const auto first = std::lower_bound(shown_.begin(), shown_.end(), base_);
      const auto removed = static_cast<int>(first - shown_.begin());
      shown_.erase(shown_.begin(), first);
      sel_ = std::max(0, sel_ - removed);
      list_scroll_ = std::max(0, list_scroll_ - removed);
    }

    if (follow_ && !shown_.empty()) sel_ = static_cast<int>(shown_.size()) - 1;
    sel_ = std::clamp(sel_, 0, std::max(0, static_cast<int>(shown_.size()) - 1));
    refresh_detail();
  }

  void refilter() {
    const Packet* keep = selected();
    const uint64_t keep_no = keep ? keep->no : 0;

    shown_.clear();
    for (size_t i = 0; i < packets_.size(); ++i) {
      if (filter_.matches(packets_[i])) shown_.push_back(base_ + i);
    }

    sel_ = 0;
    if (keep_no != 0) {
      for (size_t i = 0; i < shown_.size(); ++i) {
        const Packet* p = at(shown_[i]);
        if (p != nullptr && p->no >= keep_no) {
          sel_ = static_cast<int>(i);
          break;
        }
      }
    }
    sel_ = std::clamp(sel_, 0, std::max(0, static_cast<int>(shown_.size()) - 1));
    refresh_detail();
  }

  void refresh_detail() {
    const Packet* p = selected();
    if (p == nullptr) {
      detail_no_ = 0;
      detail_ = {};
      tree_.clear();
      collapsed_.clear();
      return;
    }
    if (p->no == detail_no_) return;

    detail_no_ = p->no;
    detail_ = dissect(p->bytes.data(), static_cast<uint32_t>(p->bytes.size()),
                      p->wirelen, cap_.linktype(), true);
    collapsed_.assign(detail_.sections.size(), false);
    detail_sel_ = 0;
    detail_scroll_ = 0;
    hex_scroll_ = 0;
    hex_cursor_ = 0;
    rebuild_tree();
  }

  void rebuild_tree() {
    tree_.clear();
    for (size_t s = 0; s < detail_.sections.size(); ++s) {
      tree_.push_back({static_cast<int>(s), -1});
      if (collapsed_[s]) continue;
      for (size_t f = 0; f < detail_.sections[s].fields.size(); ++f) {
        tree_.push_back({static_cast<int>(s), static_cast<int>(f)});
      }
    }
    detail_sel_ =
        std::clamp(detail_sel_, 0, std::max(0, static_cast<int>(tree_.size()) - 1));
  }

  std::pair<uint32_t, uint32_t> range_of(int tree_index) const {
    if (tree_.empty()) return {0, 0};
    const int i = std::clamp(tree_index, 0, static_cast<int>(tree_.size()) - 1);
    const TreeRow& row = tree_[i];
    const Section& sec = detail_.sections[row.section];
    if (row.field < 0) return {sec.offset, sec.length};
    const Field& f = sec.fields[row.field];
    return {f.offset, f.length};
  }

  std::pair<uint32_t, uint32_t> highlight() const { return range_of(detail_sel_); }

  void clear_packets() {
    packets_.clear();
    shown_.clear();
    base_ = 0;
    sel_ = 0;
    list_scroll_ = 0;
    list_hscroll_ = 0;
    detail_no_ = 0;
    detail_ = {};
    tree_.clear();
    collapsed_.clear();
    follow_ = true;
  }

  // --- rendering -----------------------------------------------------------

  Element render() {
    sync();
    Element main = vbox({
                       title_bar(),
                       list_pane() | flex,
                       hbox({detail_pane() | flex, hex_pane()}) | flex,
                       status_bar(),
                   }) |
                   bgcolor(th().bg) | color(th().text);
    if (!show_help_) return main;
    return dbox({main, help_overlay() | clear_under | center});
  }

  Element title_bar() {
    const char* dlt = "Link";
    switch (cap_.linktype()) {
      case 1: dlt = "Ethernet"; break;
      case 0: dlt = "Loopback"; break;
      case 12: dlt = "Raw IP"; break;
      default: break;
    }

    Elements right;
    right.push_back(text(commas(cap_.captured()) + " captured") | color(th().muted));
    right.push_back(text(" · ") | color(th().dim));
    right.push_back(text(commas(shown_.size()) + " shown") | color(th().muted));
    if (const uint64_t d = cap_.dropped(); d > 0) {
      right.push_back(text(" · ") | color(th().dim));
      right.push_back(text(commas(d) + " dropped") | color(th().warn));
    }
    right.push_back(text("  "));
    right.push_back(cap_.paused() ? text("❚❚ paused") | color(th().warn) | bold
                                  : text("● live") | color(th().accent));

    return hbox({
               text(" portveil ") | bold | color(th().on_accent) | bgcolor(th().accent),
               text(" " + cap_.iface()) | bold | color(th().text),
               text(std::format(" · {} ", dlt)) | color(th().dim),
               filler(),
               hbox(std::move(right)),
               text(" "),
           }) |
           bgcolor(th().bar_bg);
  }

  Element list_pane() {
    const int reflected = box_width(list_box_);
    const int width = reflected > 1 ? reflected : std::max(40, Terminal::Size().dimx - 2);
    const int addr_w = std::clamp((width - 44) / 2, 15, 32);
    const int rows_h = std::max(1, view_height(list_box_, default_list_h()) - 1);

    scroll_to(list_scroll_, sel_, rows_h, static_cast<int>(shown_.size()));

    const std::vector<Seg> header = {
        {fit("No.", 8), th().dim, true},         {fit("Time", 10), th().dim, true},
        {fit("Source", addr_w + 1), th().dim, true},
        {fit("Destination", addr_w + 1), th().dim, true},
        {fit("Proto", 8), th().dim, true},       {fit("Len", 6), th().dim, true},
        {"Info", th().dim, true},
    };

    Elements rows;
    rows.push_back(row_from(header, list_hscroll_, width));

    int widest = segs_width(header);
    const int last = std::min(static_cast<int>(shown_.size()), list_scroll_ + rows_h);
    for (int i = list_scroll_; i < last; ++i) {
      const Packet* p = at(shown_[i]);
      if (p == nullptr) continue;
      const Dissection& d = p->d;
      const Color c = proto_color(d);

      const std::vector<Seg> segs = {
          {fit(commas(p->no), 8), th().dim},
          {fit(std::format("{:.3f}", p->ts), 10), th().dim},
          {fit(d.src, addr_w + 1), c},
          {fit(d.dst, addr_w + 1), c},
          {fit(d.proto, 8), c, true},
          {fit(std::format("{}", p->wirelen), 6), th().dim},
          {d.info, c},
      };
      widest = std::max(widest, segs_width(segs));

      Element row = row_from(segs, list_hscroll_, width);
      if (i == sel_) {
        row = row | bgcolor(focus_ == Pane::List ? th().sel_bg : th().sel_bg_idle);
      }
      rows.push_back(row);
    }
    list_max_width_ = widest;

    if (shown_.empty()) {
      rows.push_back(text(packets_.empty() ? "  Waiting for packets…"
                                           : "  No packets match the filter.") |
                     color(th().dim));
    }

    return panel("Packets", vbox({vbox(std::move(rows)), filler()}) | reflect(list_box_),
                 focus_ == Pane::List);
  }

  Element detail_pane() {
    const int height = view_height(detail_box_, default_pane_h());
    scroll_to(detail_scroll_, detail_sel_, height, static_cast<int>(tree_.size()));

    Elements rows;
    if (tree_.empty()) rows.push_back(text("  Select a packet.") | color(th().dim));

    const int last = std::min(static_cast<int>(tree_.size()), detail_scroll_ + height);
    for (int i = detail_scroll_; i < last; ++i) {
      const TreeRow& r = tree_[i];
      const Section& sec = detail_.sections[r.section];
      Element row;
      if (r.field < 0) {
        row = hbox({
            text(collapsed_[r.section] ? "▸ " : "▾ ") | color(th().dim),
            text(sec.name) | bold | color(section_color(r.section)),
            text(std::format("  ({} bytes)", sec.length)) | color(th().dim),
        });
      } else {
        const Field& f = sec.fields[r.field];
        row = hbox({
            text("    "),
            text(f.name + ": ") | color(th().muted),
            text(f.value) | color(th().text),
        });
      }
      if (i == detail_sel_) {
        row = row | bgcolor(focus_ == Pane::Detail ? th().sel_bg : th().sel_bg_idle);
      }
      rows.push_back(row);
    }

    return panel("Details",
                 vbox({vbox(std::move(rows)), filler()}) | reflect(detail_box_),
                 focus_ == Pane::Detail);
  }

  Element hex_pane() {
    const Packet* p = selected();
    // Sized from the full-width packet list rather than this pane's own width,
    // which would otherwise feed back into the width chosen here.
    const int screen_w = box_width(list_box_);
    const HexLayout lay{(screen_w == 0 || screen_w >= 110) ? 16 : 8};
    hex_per_row_ = lay.per_row;
    const int pane_w = lay.width() + 2;

    if (p == nullptr || p->bytes.empty()) {
      return panel("Bytes", vbox({text("  No data.") | color(th().dim), filler()}),
                   focus_ == Pane::Hex) |
             size(WIDTH, EQUAL, pane_w);
    }

    std::vector<int> owner(p->bytes.size(), -1);
    for (size_t s = 0; s < detail_.sections.size(); ++s) {
      const Section& sec = detail_.sections[s];
      for (uint32_t i = sec.offset; i < sec.offset + sec.length && i < owner.size(); ++i) {
        owner[i] = static_cast<int>(s);
      }
    }

    const auto [hl_off, hl_len] = highlight();
    hex_cursor_ = std::min<uint32_t>(hex_cursor_,
                                     static_cast<uint32_t>(p->bytes.size()) - 1);
    const int total_rows =
        (static_cast<int>(p->bytes.size()) + lay.per_row - 1) / lay.per_row;
    hex_rows_ = total_rows;
    const int height = view_height(hex_box_, default_pane_h());
    hex_scroll_ = std::clamp(hex_scroll_, 0, std::max(0, total_rows - height));

    // Keep whatever the panes agree is current on screen.
    if (hex_active()) {
      scroll_to(hex_scroll_, static_cast<int>(hex_cursor_) / lay.per_row, height,
                total_rows);
    } else if (hl_len > 0 && focus_ == Pane::Detail) {
      scroll_to(hex_scroll_, static_cast<int>(hl_off) / lay.per_row, height, total_rows);
    }

    Elements rows;
    const int last = std::min(total_rows, hex_scroll_ + height);
    for (int r = hex_scroll_; r < last; ++r) {
      const size_t start = static_cast<size_t>(r) * lay.per_row;
      Elements hex, ascii;
      for (int c = 0; c < lay.per_row; ++c) {
        const size_t i = start + c;
        if (i >= p->bytes.size()) {
          hex.push_back(text("   "));
          ascii.push_back(text(" "));
        } else {
          const uint8_t b = p->bytes[i];
          const bool in_field = hl_len > 0 && i >= hl_off && i < hl_off + hl_len;
          const bool is_cursor = hex_active() && i == hex_cursor_;

          Element h = text(std::format("{:02x} ", b));
          Element a = text(
              std::string(1, b >= 0x20 && b < 0x7f ? static_cast<char>(b) : '.'));
          if (is_cursor) {
            const auto style = bgcolor(th().accent) | color(th().on_accent) | bold;
            h = h | style;
            a = a | style;
          } else if (in_field) {
            const auto style = bgcolor(th().hl_bg) | color(th().hl_fg);
            h = h | style;
            a = a | style;
          } else {
            const Color oc = owner[i] >= 0 ? section_color(owner[i]) : th().dim;
            h = h | color(oc);
            a = a | color(oc);
          }
          hex.push_back(std::move(h));
          ascii.push_back(std::move(a));
        }
        if (c == lay.per_row / 2 - 1) {
          hex.push_back(text(" "));
          ascii.push_back(text(" "));
        }
      }
      rows.push_back(hbox({
          text(std::format("{:04x}  ", start)) | color(th().dim),
          hbox(std::move(hex)),
          text(" "),
          hbox(std::move(ascii)),
      }));
    }

    return panel("Bytes", vbox({vbox(std::move(rows)), filler()}) | reflect(hex_box_),
                 focus_ == Pane::Hex) |
           size(WIDTH, EQUAL, pane_w);
  }

  Element status_bar() {

    Elements left;
    if (!filter_.error().empty()) {
      left.push_back(text(" filter ") | color(th().on_accent) | bgcolor(th().error) |
                     bold);
      left.push_back(text(" " + filter_.error()) | color(th().error));
    } else if (!filter_.text().empty()) {
      left.push_back(text(" filter ") | color(th().on_accent) | bgcolor(th().accent) |
                     bold);
      left.push_back(text(" " + filter_.text()) | color(th().text));
    } else {
      left.push_back(text(" no filter") | color(th().dim));
    }

    // While the bytes pane is in play, say what the cursor is pointing at.

    return hbox({
               hbox(std::move(left)),
               filler(),
               text("tab panes · / filter · p pause · t theme · ? help · q quit ") |
                   color(th().dim),
           }) |
           bgcolor(th().bar_bg);
  }

  Element panel(std::string title, Element content, bool focused) {
    return window(text(" " + title + " ") | bold |
                      color(focused ? th().accent : th().muted),
                  std::move(content)) |
           color(focused ? th().accent : th().dim);
  }

  Element help_overlay() {
    auto key = [](std::string k, std::string desc) {
      return hbox({
          text(" " + k) | color(th().accent) | bold | size(WIDTH, EQUAL, 17),
          text(desc) | color(th().text),
          text(" "),
      });
    };
    return window(text(" Keys ") | bold | color(th().accent),
                  vbox({
                      key("↑ ↓ / j k", "move the selection"),
                      key("← →", "packets: scroll sideways · bytes: previous/next byte"),
                      key("g / G", "jump to first / last"),
                      key("pgup pgdn", "page through the list"),
                      key("tab", "cycle panes"),
                      key("enter / space", "fold or unfold a protocol layer"),
                      key("/", "edit the display filter"),
                      key("p", "pause or resume capture"),
                      key("c", "clear captured packets"),
                      key("f", "follow new packets"),
                      key("t", "switch between dark and light"),
                      key("?", "toggle this help"),
                      key("q", "quit"),
                      separator(),
                      text(" In Bytes, moving the cursor (or hovering the mouse) names") |
                          color(th().muted),
                      text(" the field those bytes belong to in the status bar.") |
                          color(th().muted),
                      separator(),
                      text(" Filter: tcp udp icmp arp dns tls http quic ipv4 ipv6") |
                          color(th().muted),
                      text("         port 443 · host example.com · len>500") |
                          color(th().muted),
                      text("         anything else matches the Info column") |
                          color(th().dim),
                  })) |
           color(th().accent) | bgcolor(th().bg);
  }

  // Sensible first-frame sizes, before any box has been reflected.
  int default_list_h() const { return std::max(3, (Terminal::Size().dimy - 4) / 2); }
  int default_pane_h() const { return std::max(3, (Terminal::Size().dimy - 6) / 2); }

  // --- input ---------------------------------------------------------------

  bool on_event(Event& e) {
    if (e == Event::Custom) return true;

    if (e == Event::Character('q')) {
      if (screen_ != nullptr) screen_->Exit();
      return true;
    }
    if (e == Event::Character('?')) {
      show_help_ = !show_help_;
      return true;
    }
    if (show_help_) { // any other key dismisses the overlay
      show_help_ = false;
      return true;
    }
    if (e == Event::Escape) {
      if (screen_ != nullptr) screen_->Exit();
      return true;
    }

    if (e == Event::Tab) {
      focus_ = focus_ == Pane::List     ? Pane::Detail
               : focus_ == Pane::Detail ? Pane::Hex
                                        : Pane::List;
      return true;
    }
    if (e == Event::TabReverse) {
      focus_ = focus_ == Pane::List  ? Pane::Hex
               : focus_ == Pane::Hex ? Pane::Detail
                                     : Pane::List;
      return true;
    }
    if (e == Event::Character('p')) {
      cap_.set_paused(!cap_.paused());
      return true;
    }
    if (e == Event::Character('c')) {
      clear_packets();
      return true;
    }
    if (e == Event::Character('f')) {
      follow_ = true;
      return true;
    }

    if (e == Event::ArrowUp || e == Event::Character('k')) return move(-1);
    if (e == Event::ArrowDown || e == Event::Character('j')) return move(1);
    if (e == Event::PageUp) return move(-page());
    if (e == Event::PageDown) return move(page());
    if (e == Event::Home || e == Event::Character('g')) return jump(true);
    if (e == Event::End || e == Event::Character('G')) return jump(false);

    if (focus_ == Pane::Detail && (e == Event::Return || e == Event::Character(' '))) {
      return toggle();
    }
    return false;
  }

  int page() const {
    switch (focus_) {
      case Pane::List: return std::max(1, box_height(list_box_) - 2);
      case Pane::Detail: return std::max(1, box_height(detail_box_) - 1);
      case Pane::Hex: return std::max(1, box_height(hex_box_) - 1);
    }
    return 1;
  }

  bool move(int delta) {
    switch (focus_) {
      case Pane::List: {
        if (shown_.empty()) return true;
        const int last = static_cast<int>(shown_.size()) - 1;
        sel_ = std::clamp(sel_ + delta, 0, last);
        follow_ = (sel_ == last);
        refresh_detail();
        return true;
      }
      case Pane::Detail: {
        if (tree_.empty()) return true;
        detail_sel_ =
            std::clamp(detail_sel_ + delta, 0, static_cast<int>(tree_.size()) - 1);
        const auto [off, len] = highlight();
        if (len > 0) hex_cursor_ = off;
        return true;
      }
    }
    return false;
  }

  bool jump(bool top) {
    switch (focus_) {
      case Pane::List:
        if (shown_.empty()) return true;
        sel_ = top ? 0 : static_cast<int>(shown_.size()) - 1;
        follow_ = !top;
        refresh_detail();
        return true;
      case Pane::Detail:
        detail_sel_ = top ? 0 : std::max(0, static_cast<int>(tree_.size()) - 1);
        return true;
    }
    return false;
  }

  bool expand(bool open) {
    if (tree_.empty()) return true;
    const TreeRow& r = tree_[detail_sel_];
    if (open) {
      if (collapsed_[r.section]) {
        collapsed_[r.section] = false;
        rebuild_tree();
      } else if (r.field < 0 && detail_sel_ + 1 < static_cast<int>(tree_.size())) {
        ++detail_sel_; // step into the layer
      }
      return true;
    }
    if (r.field >= 0) {
      // Move up to the section header first, then collapse on a second press.
      for (int i = detail_sel_; i >= 0; --i) {
        if (tree_[i].field < 0) {
          detail_sel_ = i;
          break;
        }
      }
      return true;
    }
    collapsed_[r.section] = true;
    rebuild_tree();
    return true;
  }

  bool toggle() {
    if (tree_.empty()) return true;
    const TreeRow& r = tree_[detail_sel_];
    if (r.field < 0) {
      collapsed_[r.section] = !collapsed_[r.section];
      rebuild_tree();
    }
    return true;
  }
};

} // namespace

void run_ui(Capture& cap) {
  App app(cap);
  app.run();
}

} // namespace pv
