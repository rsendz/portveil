# portveil

A Wireshark-style packet analyzer that lives in your terminal.

Three panes, the way you already know them: a live packet list, a foldable
protocol tree, and a hex dump that highlights whichever field you have
selected. One binary, no runtime dependencies.

## Usage

```
portveil [options]

  -i, --interface <name>   capture on this interface (skips the picker)
  -f, --filter <expr>      libpcap capture filter, e.g. "tcp port 443"
  -l, --list               list capture interfaces and exit
  -d, --dump <n>           print n packets as plain text and exit (no UI)
  -v, --version            print the version and exit
  -h, --help               show this help
```

Run it with no arguments and it shows a picker of the interfaces it can
capture on, most useful first.

### Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k` | move the selection |
| `g` / `G` | jump to the first / last row |
| `PgUp` `PgDn` | page through the list |
| `Tab` | cycle between the three panes |
| `Enter` `Space` | fold or unfold a protocol layer |
| `/` | edit the display filter |
| `p` | pause or resume capture |
| `c` | clear captured packets |
| `f` | resume following new packets |
| `?` | toggle the key help |
| `q` | quit |


The mouse works too: scroll any pane, click a packet to select it, click a
layer to fold it.

### Display filters

Press `/` and type space-separated terms. Every term has to match.

| Term | Matches |
| --- | --- |
| `tcp` `udp` `icmp` `arp` `dns` `tls` `http` `quic` `ipv4` `ipv6` | that protocol |
| `port 443` | that port, on either side |
| `host example.com` | an address, TLS SNI, HTTP `Host`, or DNS name containing it |
| `len>500` `len<100` `len=64` | frame length on the wire |
| anything else | substring of the Info column |

So `tls host github` shows TLS records to or from anything with "github" in
its name, and `dns len>200` finds the chunky DNS responses.

That filter only changes what the list shows. Capture keeps running, so
clearing it brings the hidden packets back. To drop traffic before it ever
reaches portveil, use `-f` with a libpcap expression instead:

```sh
portveil -i en0 -f "tcp port 443 or udp port 53"
```

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
