// Terminal UI: interface picker and the three-pane analyzer view.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "capture.hpp"

namespace pv {

// Interactive interface chooser. Returns the selected name, or nullopt if the
// user quit without choosing.
std::optional<std::string> pick_interface(const std::vector<Iface>& ifaces);

// Runs the analyzer until the user quits. `cap` must already be open.
void run_ui(Capture& cap);

} // namespace pv
