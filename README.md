# Cesium

**Cesium** is a simple, cross-platform DNS tunneling system designed to be a modern, user-friendly replacement for [iodine](https://code.kryo.se/iodine/). It uses [cesium-core](https://github.com/TransIRC/cesium-core), a Go library for embedding DNS tunnels in any application. Cesium gives users a SOCKS5 proxy interface tunneled over DNS --- with no need for virtual interfaces like TUN/TAP, making it lightweight and portable across Linux and Windows.

---

## ✨ Features

- 🧠 **Built on `cesium-core`**: handles DNS encoding/decoding, connection multiplexing, and reliability.
- 🧦 **SOCKS5 proxy client**: tunnel any TCP-based traffic easily (web browsers, SSH, etc).
- 🌐 **DNS server backend**: receives tunneled data via DNS queries and forwards it transparently.
- 🛠 **Cross-platform**: no kernel modules, no admin rights --- just Go binaries.
- 🔐 **Password protection**: basic authentication support out of the box.
- 🔄 **Inspired by Iodine**: but easier to set up, script, and run in diverse environments.



🔄 Relationship to Other Projects
---------------------------------

### 🌐 [`cesium-core`](https://github.com/TransIRC/cesium-core)

Cesium is built entirely on top of [`cesium-core`](https://github.com/TransIRC/cesium-core), a Go library that handles DNS-based `net.Conn` style streams. It does all the heavy lifting --- packet encoding, DNS query/response formatting, fragmentation, keepalives, etc.

You can use `cesium-core` directly in your own Go applications to embed DNS tunnels as part of larger systems.

* * * * *

### 🪱 [`TapeWorm`](https://github.com/TransIRC/TapeWorm)

[TapeWorm](https://github.com/TransIRC/TapeWorm) is a higher-level tool also built on `cesium-core`. It creates:

-   A DNS **server** that terminates DNS tunnels and **forwards to an SSH server**, injecting the user's real IP via the **PROXY protocol**.

-   A DNS tunneling **client** that acts as an **SSH client**, allowing you to log in over DNS.


* * * * *


🧪 Example Use Cases
--------------------

-   Bypass restrictive firewalls by tunneling through DNS.

-   Get internet access on captive portals or limited networks.

-   Lightweight tunnel from Windows environments without admin rights.

-   Use with `curl`, `ssh`, or full browsers through the SOCKS5 proxy.

* * * * *

