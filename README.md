# portveil

A Wireshark-style packet analyzer that lives in your terminal.

Three panes, the way you already know them: a live packet list, a foldable
protocol tree, and a hex dump that highlights whichever field you have
selected. One binary, no runtime dependencies.

## Build from source

Needs CMake 3.22+, a C++20 compiler, and libpcap headers. FTXUI is fetched
automatically during configuration.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/portveil --list
```

## License

MIT.
