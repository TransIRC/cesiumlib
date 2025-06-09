package cesiumlib

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ServerSideDnsTunnelConn implements net.Conn for a single UDP "session" (client address).
type ServerSideDnsTunnelConn struct {
	udpConn        *net.UDPConn
	remoteAddr     *net.UDPAddr
	tunnelDomain   string
	tunnelPassword string

	readBuffer     bytes.Buffer
	readReady      chan struct{}
	closeOnce      sync.Once
	closed         bool
	stopChan       chan struct{}
	lastActive     time.Time
	mutex          sync.Mutex
}

// AcceptServerDnsTunnelConns listens on udpConn and for every new client address (session), spawns handle(conn).
func AcceptServerDnsTunnelConns(
	udpConn *net.UDPConn,
	tunnelDomain, tunnelPassword string,
	handle func(net.Conn),
) error {
	sessionMap := make(map[string]*ServerSideDnsTunnelConn)
	var mu sync.Mutex
	buf := make([]byte, MaxDNSPacketSize)
	for {
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP ReadFromUDP error: %v", err)
			return err
		}
		key := remoteAddr.String()
		mu.Lock()
		session, exists := sessionMap[key]
		if !exists {
			session = &ServerSideDnsTunnelConn{
				udpConn:        udpConn,
				remoteAddr:     remoteAddr,
				tunnelDomain:   tunnelDomain,
				tunnelPassword: tunnelPassword,
				readReady:      make(chan struct{}, 1),
				stopChan:       make(chan struct{}),
				lastActive:     time.Now(),
			}
			sessionMap[key] = session
			go func(sess *ServerSideDnsTunnelConn, k string) {
				handle(sess)
				mu.Lock()
				delete(sessionMap, k)
				mu.Unlock()
			}(session, key)
		}
		mu.Unlock()
		session.handleIncomingPacket(buf[:n])
	}
}

func (c *ServerSideDnsTunnelConn) handleIncomingPacket(data []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.closed {
		return
	}
	query, _, err := DecodeDNSQuery(data, c.tunnelDomain, c.tunnelPassword)
	if err != nil {
		return
	}
	if len(query.Payload) > 0 {
		c.readBuffer.Write(query.Payload)
		select {
		case c.readReady <- struct{}{}:
		default:
		}
	}
	resp, err := CreateDNSResponse(query.ID, 0, []byte{})
	if err == nil {
		_, _ = c.udpConn.WriteToUDP(resp, c.remoteAddr)
	}
}

func (c *ServerSideDnsTunnelConn) Read(b []byte) (int, error) {
	for {
		c.mutex.Lock()
		if c.closed {
			c.mutex.Unlock()
			return 0, io.EOF
		}
		n, _ := c.readBuffer.Read(b)
		c.mutex.Unlock()
		if n > 0 {
			return n, nil
		}
		select {
		case <-c.stopChan:
			return 0, io.EOF
		case <-c.readReady:
		case <-time.After(ReadPollInterval):
		}
	}
}

func (c *ServerSideDnsTunnelConn) Write(b []byte) (int, error) {
	max := MaxRawChunkSize
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		resp, err := CreateDNSResponse(0, 0, chunk)
		if err != nil {
			return total, err
		}
		_, err = c.udpConn.WriteToUDP(resp, c.remoteAddr)
		if err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *ServerSideDnsTunnelConn) Close() error {
	c.closeOnce.Do(func() {
		c.mutex.Lock()
		c.closed = true
		close(c.stopChan)
		c.mutex.Unlock()
	})
	return nil
}
func (c *ServerSideDnsTunnelConn) LocalAddr() net.Addr  { return c.udpConn.LocalAddr() }
func (c *ServerSideDnsTunnelConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *ServerSideDnsTunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *ServerSideDnsTunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ServerSideDnsTunnelConn) SetWriteDeadline(t time.Time) error { return nil }
