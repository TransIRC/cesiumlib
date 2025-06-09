# cesiumlib

**cesiumlib** is a pure-Go library for building DNS tunnels, inspired by [iodine](https://github.com/yarrick/iodine) but designed for modern Go applications. It provides a simple, idiomatic API for tunneling TCP-like streams over DNS, making it suitable for research, penetration testing, and learning about covert networking.

## Features

- Client/server DNS tunnel abstractions via `net.Conn` interface
- Handles chunking, retransmission, flow control, and keepalives
- Pluggable configuration for performance tuning
- Pure Go, no C dependencies
- Inspired by the robust design of iodine but modernized for Go

## Why cesiumlib?

[**iodine**](https://github.com/yarrick/iodine) set the standard for DNS tunneling using C. **cesiumlib** re-imagines that spirit for the Go ecosystem: composable, embeddable, and easy to use in Go apps, proxies, and experiments.

## Installation

```sh
go get github.com/TransIRC/cesiumlib
```

## Quick Start

### 1. Running a DNS tunnel server

```go
package main

import (
	"log"
	"net"
	"github.com/TransIRC/cesiumlib/cesiumcore"
)

func main() {
	addr := ":5353"
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 5353})
	if err != nil {
		log.Fatal(err)
	}
	domain := "mytunnel.example.com"
	password := "secret"
	err = cesiumcore.AcceptServerDnsTunnelConns(udpConn, domain, password, func(conn net.Conn) {
		defer conn.Close()
		buffer := make([]byte, 4096)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}
			log.Printf("Received: %s", buffer[:n])
			conn.Write([]byte("pong"))
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

### 2. Connecting as a client

```go
package main

import (
	"log"
	"github.com/TransIRC/cesiumlib/cesiumcore"
)

func main() {
	serverAddr := "8.8.8.8:53" // Replace with your server's IP/port
	domain := "mytunnel.example.com"
	password := "secret"
	conn, err := cesiumcore.NewDnsTunnelConn(serverAddr, domain, password)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got: %s", buffer[:n])
}
```

## Configuration

Tweak tunneling parameters using `cesiumcore.Configure()`:

```go
cesiumcore.Configure(cesiumcore.Config{
    ClientRawChunkSize: 32,
    FlowControlWindow:  8,
    // etc...
})
```

## Security & Caveats

- **cesiumlib** is for educational, research, and authorized security work only.
- Tunneling over DNS may break terms of service or laws in your jurisdiction.
- The protocol here does not encrypt payloads—use TLS over the tunnel if you need confidentiality.

## Inspiration

- **iodine** by Björn Andersson: https://github.com/yarrick/iodine
