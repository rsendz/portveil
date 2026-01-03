cmake_minimum_required(VERSION 3.22)
project(portveil VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
  GIT_TAG v5.0.0
  GIT_SHALLOW TRUE
)
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(ftxui)

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR
    "libpcap not found.\n"
    "  macOS:  ships with the Xcode command line tools (xcode-select --install)\n"
    "  Debian: sudo apt install libpcap-dev\n"
    "  Fedora: sudo dnf install libpcap-devel\n"
    "  Arch:   sudo pacman -S libpcap")
endif()

add_executable(portveil
  src/main.cpp
  src/capture.cpp
  src/dissect.cpp
  src/filter.cpp
  src/ui.cpp
)

target_include_directories(portveil PRIVATE src ${PCAP_INCLUDE_DIR})
# ftxui::component transitively pulls in ftxui::dom and ftxui::screen.
target_link_libraries(portveil PRIVATE ${PCAP_LIBRARY} ftxui::component)
target_compile_definitions(portveil PRIVATE PORTVEIL_VERSION="${PROJECT_VERSION}")

install(TARGETS portveil RUNTIME DESTINATION bin)
