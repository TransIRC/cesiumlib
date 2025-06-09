package cesiumlib

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type DnsTunnelConn struct {
	udpConn        *net.UDPConn
	remoteAddr     *net.UDPAddr
	readBuffer     bytes.Buffer
	readReady      chan struct{}
	lastActive     time.Time
	readDeadline   time.Time
	stopChan       chan struct{}
	mutex          sync.Mutex
	once           sync.Once
	closed         bool
	TunnelDomain   string
	TunnelPassword string
	sendPoll       bool
	pollTimer      *time.Timer

	ackMutex    sync.Mutex
	pendingAcks map[uint16]*pendingChunk
	ackChan     chan uint16
	nextSeq     uint16
	writeSem    chan struct{}
}

type pendingChunk struct {
	payload   []byte
	timestamp time.Time
	retries   int
}

func NewDnsTunnelConn(dnsServerAddr, tunnelDomain, tunnelPassword string) (*DnsTunnelConn, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", dnsServerAddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	conn := &DnsTunnelConn{
		udpConn:        udpConn,
		remoteAddr:     remoteAddr,
		readReady:      make(chan struct{}, 1),
		stopChan:       make(chan struct{}),
		TunnelDomain:   tunnelDomain,
		TunnelPassword: tunnelPassword,
		pollTimer:      time.NewTimer(0),
		pendingAcks:    make(map[uint16]*pendingChunk),
		ackChan:        make(chan uint16, 100),
		writeSem:       make(chan struct{}, FlowControlWindow),
	}
	<-conn.pollTimer.C
	go conn.reader()
	go conn.keepalive()
	go conn.ackManager()
	return conn, nil
}

func (c *DnsTunnelConn) Read(b []byte) (int, error) {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return 0, io.EOF
	}
	c.mutex.Unlock()
	for {
		c.mutex.Lock()
		n, err := c.readBuffer.Read(b)
		c.mutex.Unlock()
		if n > 0 {
			c.lastActive = time.Now()
			return n, err
		}
		select {
		case <-c.stopChan:
			return 0, io.EOF
		case <-c.readReady:
		case <-time.After(ReadPollInterval):
		}
		c.mutex.Lock()
		deadline := c.readDeadline
		c.mutex.Unlock()
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *DnsTunnelConn) Write(b []byte) (int, error) {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return 0, io.EOF
	}
	c.mutex.Unlock()
	totalWritten := 0
	for len(b) > 0 {
		chunkSize := Min(ClientRawChunkSize, len(b))
		chunk := b[:chunkSize]
		select {
		case c.writeSem <- struct{}{}:
		case <-c.stopChan:
			return totalWritten, io.EOF
		case <-time.After(WriteTimeout):
			return totalWritten, errors.New("write timeout: failed to acquire flow control slot")
		}
		c.mutex.Lock()
		seq := c.nextSeq
		c.nextSeq++
		c.mutex.Unlock()
		query, err := c.createDNSQuery([]string{"d" + base64.RawURLEncoding.EncodeToString(chunk)}, seq)
		if err != nil {
			select {
			case <-c.writeSem:
			default:
			}
			return totalWritten, err
		}
		c.ackMutex.Lock()
		c.pendingAcks[seq] = &pendingChunk{
			payload:   chunk,
			timestamp: time.Now(),
			retries:   0,
		}
		c.ackMutex.Unlock()
		c.udpConn.SetWriteDeadline(time.Now().Add(WriteTimeout))
		if _, err := c.udpConn.WriteToUDP(query, c.remoteAddr); err != nil {
			c.ackMutex.Lock()
			delete(c.pendingAcks, seq)
			c.ackMutex.Unlock()
			select {
			case <-c.writeSem:
			default:
			}
			return totalWritten, err
		}
		totalWritten += chunkSize
		b = b[chunkSize:]
		c.lastActive = time.Now()
	}
	return totalWritten, nil
}

func (c *DnsTunnelConn) ackManager() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopChan:
			return
		case seq := <-c.ackChan:
			c.handleAck(seq)
		case <-ticker.C:
			c.retryExpiredChunks()
		}
	}
}

func (c *DnsTunnelConn) handleAck(seq uint16) {
	c.ackMutex.Lock()
	defer c.ackMutex.Unlock()
	if _, exists := c.pendingAcks[seq]; exists {
		delete(c.pendingAcks, seq)
		select {
		case <-c.writeSem:
			log.Printf("ACK received for seq %d, released writeSem", seq)
		default:
			log.Printf("ACK received for seq %d, but no writeSem to release (likely already released)", seq)
		}
	}
}

func (c *DnsTunnelConn) retryExpiredChunks() {
	c.ackMutex.Lock()
	defer c.ackMutex.Unlock()
	now := time.Now()
	for seq, chunk := range c.pendingAcks {
		if now.Sub(chunk.timestamp) > AckTimeout {
			if chunk.retries >= MaxRetransmits {
				log.Printf("Max retries reached for seq %d, dropping chunk.", seq)
				delete(c.pendingAcks, seq)
				select {
				case <-c.writeSem:
					log.Printf("Released writeSem for seq %d due to max retries.", seq)
				default:
					log.Printf("No writeSem to release for seq %d (max retries), already released?", seq)
				}
				continue
			}
			encodedPayload := base64.RawURLEncoding.EncodeToString(chunk.payload)
			query, err := c.createDNSQuery([]string{"d" + encodedPayload}, seq)
			if err == nil {
				if _, err := c.udpConn.WriteToUDP(query, c.remoteAddr); err != nil {
					log.Printf("Failed to retransmit seq %d: %v", seq, err)
				} else {
					chunk.retries++
					chunk.timestamp = now
					log.Printf("Retransmitted seq %d (attempt %d)", seq, chunk.retries)
				}
			} else {
				log.Printf("Failed to create DNS query for retransmission of seq %d: %v", seq, err)
			}
		}
	}
}

func (c *DnsTunnelConn) reader() {
	buf := make([]byte, MaxDNSPacketSize)
	for {
		select {
		case <-c.stopChan:
			return
		default:
			c.udpConn.SetReadDeadline(time.Now().Add(ReadPollInterval))
			n, _, err := c.udpConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Printf("UDP ReadFromUDP error: %v", err)
				c.Close()
				return
			}
			if seq, isAck := c.parseAck(buf[:n]); isAck {
				select {
				case c.ackChan <- seq:
				default:
					log.Printf("Ack channel full for seq %d, dropping ACK", seq)
				}
				continue
			}
			payload, err := ParseDNSResponse(buf[:n])
			if err != nil {
				log.Printf("Failed to parse DNS response: %v", err)
				continue
			}
			if len(payload) > 0 {
				c.mutex.Lock()
				c.readBuffer.Write(payload)
				select {
				case c.readReady <- struct{}{}:
				default:
				}
				c.mutex.Unlock()
			}
		}
	}
}

func (c *DnsTunnelConn) parseAck(data []byte) (uint16, bool) {
	if len(data) < 12 {
		return 0, false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return 0, false
	}
	seq := binary.BigEndian.Uint16(data[0:2])
	c.ackMutex.Lock()
	_, exists := c.pendingAcks[seq]
	c.ackMutex.Unlock()
	rcode := flags & 0x000F
	if exists && rcode == 0 {
		return seq, true
	}
	return 0, false
}

func (c *DnsTunnelConn) keepalive() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopChan:
			log.Println("DNS tunnel keepalive goroutine stopped.")
			return
		case <-ticker.C:
			c.mutex.Lock()
			if c.closed {
				c.mutex.Unlock()
				return
			}
			if time.Since(c.lastActive) > KeepaliveInterval {
				query, err := c.createDNSQuery([]string{"k"}, 0)
				if err != nil {
					log.Printf("Keepalive query creation failed: %v", err)
					c.mutex.Unlock()
					continue
				}
				if _, err := c.udpConn.WriteToUDP(query, c.remoteAddr); err != nil {
					log.Printf("Keepalive write failed: %v", err)
				} else {
					log.Println("Sent DNS keepalive query.")
				}
			}
			c.mutex.Unlock()
		}
	}
}

func (c *DnsTunnelConn) Close() error {
	c.once.Do(func() {
		log.Println("DnsTunnelConn.Close: Initiating close sequence.")
		c.mutex.Lock()
		c.closed = true
		close(c.stopChan)
		if c.pollTimer != nil {
			c.pollTimer.Stop()
			select {
			case <-c.pollTimer.C:
			default:
			}
		}
		c.mutex.Unlock()
		udpErr := c.udpConn.Close()
		if udpErr != nil {
			log.Printf("DnsTunnelConn.Close: Error closing UDP connection: %v", udpErr)
		} else {
			log.Println("DnsTunnelConn.Close: UDP connection closed successfully.")
		}
		log.Println("DnsTunnelConn.Close: Marked as closed and signals sent.")
	})
	return nil
}

func (c *DnsTunnelConn) LocalAddr() net.Addr  { return c.udpConn.LocalAddr() }
func (c *DnsTunnelConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *DnsTunnelConn) SetDeadline(t time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.readDeadline = t
	return nil
}
func (c *DnsTunnelConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *DnsTunnelConn) SetWriteDeadline(t time.Time) error { return nil }
