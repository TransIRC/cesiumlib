package cesiumlib

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DnsQuery represents a parsed DNS query from the tunnel.
type DnsQuery struct {
	ID      uint16
	Payload []byte
}

// createDNSQuery constructs a DNS query packet with the given payloads and sequence number.
func (c *DnsTunnelConn) createDNSQuery(payloads []string, seq uint16) ([]byte, error) {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, seq)
	binary.Write(&buffer, binary.BigEndian, uint16(0x0100))
	binary.Write(&buffer, binary.BigEndian, uint16(1))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))

	fullDomain := fmt.Sprintf("%s.%s", strings.Join(payloads, "."), c.TunnelPassword)
	if c.TunnelDomain != "" {
		fullDomain = fmt.Sprintf("%s.%s", fullDomain, c.TunnelDomain)
	}
	labels := strings.Split(fullDomain, ".")
	for _, label := range labels {
		if len(label) > MaxDNSLabelSize {
			return nil, fmt.Errorf("DNS label '%s' exceeds maximum size of %d", label, MaxDNSLabelSize)
		}
		buffer.WriteByte(byte(len(label)))
		buffer.WriteString(label)
	}
	buffer.WriteByte(0)
	binary.Write(&buffer, binary.BigEndian, uint16(1))
	binary.Write(&buffer, binary.BigEndian, uint16(1))
	return buffer.Bytes(), nil
}

// DecodeDNSQuery parses a raw DNS query packet, extracts the data payload, sequence ID, and the extracted password.
func DecodeDNSQuery(data []byte, expectedTunnelDomain, expectedPassword string) (*DnsQuery, string, error) {
	if len(data) < 12 {
		return nil, "", errors.New("DNS query too short")
	}
	queryID := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	if (flags&0x8000 != 0) || (flags&0x7800 != 0) {
		return nil, "", errors.New("not a standard DNS query")
	}
	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount != 1 {
		return nil, "", fmt.Errorf("unexpected QDCOUNT: %d (expected 1)", qdcount)
	}
	offset := 12
	var qnameLabels []string
	for {
		if offset >= len(data) {
			return nil, "", errors.New("malformed QNAME in DNS query (truncated)")
		}
		labelLen := int(data[offset])
		offset++
		if (labelLen & 0xC0) == 0xC0 {
			return nil, "", errors.New("unexpected QNAME pointer in DNS query")
		}
		if labelLen == 0 {
			break
		}
		if offset+labelLen > len(data) {
			return nil, "", fmt.Errorf("QNAME label length out of bounds (len: %d, remaining: %d)", labelLen, len(data)-offset)
		}
		qnameLabels = append(qnameLabels, string(data[offset:offset+labelLen]))
		offset += labelLen
	}
	if offset+4 > len(data) {
		return nil, "", errors.New("DNS query truncated at QTYPE/QCLASS")
	}
	offset += 4

	fullQName := strings.Join(qnameLabels, ".")
	if !strings.HasSuffix(fullQName, expectedTunnelDomain) {
		return nil, "", fmt.Errorf("QNAME suffix mismatch: '%s' vs expected '%s'", fullQName, expectedTunnelDomain)
	}
	domainStartIndex := strings.LastIndex(fullQName, expectedTunnelDomain)
	if domainStartIndex == -1 {
		return nil, "", fmt.Errorf("internal error: expected tunnel domain not found in QNAME '%s'", fullQName)
	}
	prefix := fullQName[:domainStartIndex]
	if len(prefix) > 0 && strings.HasSuffix(prefix, ".") {
		prefix = strings.TrimSuffix(prefix, ".")
	}
	passwordLastIndex := strings.LastIndex(prefix, ".")
	var payloadEncoded, extractedPassword string
	if passwordLastIndex == -1 {
		extractedPassword = prefix
		payloadEncoded = ""
	} else {
		extractedPassword = prefix[passwordLastIndex+1:]
		payloadEncoded = prefix[:passwordLastIndex]
	}
	if extractedPassword != expectedPassword {
		return nil, "", fmt.Errorf("invalid password: '%s' (expected '%s')", extractedPassword, expectedPassword)
	}
	var decodedPayload []byte
	var err error
	if payloadEncoded == "" {
		decodedPayload = []byte{}
	} else if strings.HasPrefix(payloadEncoded, "d") {
		payloadEncoded = strings.TrimPrefix(payloadEncoded, "d")
		decodedPayload, err = base64.RawURLEncoding.DecodeString(payloadEncoded)
		if err != nil {
			return nil, "", fmt.Errorf("failed to base64 decode query payload: %w", err)
		}
	} else if payloadEncoded == "k" {
		decodedPayload = []byte("k")
	} else {
		return nil, "", fmt.Errorf("unexpected payload format in QNAME: '%s'", payloadEncoded)
	}
	return &DnsQuery{ID: queryID, Payload: decodedPayload}, extractedPassword, nil
}

// CreateDNSResponse creates a DNS response packet with optional TXT payloads.
func CreateDNSResponse(queryID uint16, rcode uint16, payloads []byte) ([]byte, error) {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, queryID)
	flags := uint16(0x8000) | (rcode & 0x000F)
	binary.Write(&buffer, binary.BigEndian, flags)
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	var ancount uint16 = 0
	if len(payloads) > 0 {
		encodedPayload := base64.RawURLEncoding.EncodeToString(payloads)
		txtChunks := splitIntoChunks(encodedPayload, MaxB64SegmentSize)
		for _, chunk := range txtChunks {
			buffer.WriteByte(0x00)
			binary.Write(&buffer, binary.BigEndian, uint16(16))
			binary.Write(&buffer, binary.BigEndian, uint16(1))
			binary.Write(&buffer, binary.BigEndian, uint32(60))
			rdataLen := 1 + len(chunk)
			binary.Write(&buffer, binary.BigEndian, uint16(rdataLen))
			buffer.WriteByte(byte(len(chunk)))
			buffer.WriteString(chunk)
			ancount++
			if buffer.Len() > MaxDNSPacketSize {
				return nil, fmt.Errorf("DNS response packet too large (payload too big for TXT records)")
			}
		}
	}
	currentBytes := buffer.Bytes()
	binary.BigEndian.PutUint16(currentBytes[6:8], ancount)
	return currentBytes, nil
}

// splitIntoChunks splits a string into smaller chunks.
func splitIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// ParseDNSResponse parses a DNS response packet and extracts the data payload from TXT records.
func ParseDNSResponse(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("DNS response too short")
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error RCODE: %d (flags: 0x%X)", rcode, flags)
	}
	if ancount == 0 {
		if rcode == 0 {
			return []byte{}, nil
		}
		return nil, errors.New("no answer records in DNS response")
	}
	offset := 12
	for q := 0; q < int(qdcount); q++ {
		for {
			if offset >= len(data) {
				return nil, fmt.Errorf("malformed QNAME in DNS response (truncated)")
			}
			labelLen := int(data[offset])
			if (labelLen & 0xC0) == 0xC0 {
				offset += 2
				break
			}
			offset++
			if labelLen == 0 {
				break
			}
			offset += labelLen
		}
		if offset+4 > len(data) {
			return nil, fmt.Errorf("DNS response truncated at QTYPE/QCLASS")
		}
		offset += 4
	}
	if offset >= len(data) {
		return nil, fmt.Errorf("DNS response truncated before Answer section")
	}
	var fullPayload bytes.Buffer
	for i := 0; i < int(ancount); i++ {
		if offset >= len(data) {
			return nil, fmt.Errorf("malformed answer record NAME in DNS response (truncated, RR %d)", i+1)
		}
		if (data[offset] & 0xC0) == 0xC0 {
			offset += 2
		} else {
			for {
				if offset >= len(data) {
					return nil, fmt.Errorf("malformed answer record NAME in DNS response (truncated label, RR %d)", i+1)
				}
				labelLen := int(data[offset])
				offset++
				if labelLen == 0 {
					break
				}
				offset += labelLen
			}
		}
		if offset+10 > len(data) {
			return nil, fmt.Errorf("DNS response truncated at RR header (RR %d)", i+1)
		}
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10
		if offset+int(rdLength) > len(data) {
			return nil, fmt.Errorf("RDLENGTH (%d) out of bounds when reading RDATA (packet size: %d, current offset: %d, RR %d)", rdLength, len(data), offset, i+1)
		}
		if rrType == 16 {
			txtData := data[offset : offset+int(rdLength)]
			txtOffset := 0
			var combinedEncodedChunk bytes.Buffer
			for txtOffset < len(txtData) {
				if txtOffset+1 > len(txtData) {
					return nil, errors.New("TXT record string length byte missing")
				}
				chunkLen := int(txtData[txtOffset])
				txtOffset++
				if txtOffset+chunkLen > len(txtData) {
					return nil, fmt.Errorf("TXT record string data out of bounds (chunkLen: %d, remaining txtData: %d)", chunkLen, len(txtData)-txtOffset)
				}
				combinedEncodedChunk.Write(txtData[txtOffset : txtOffset+chunkLen])
				txtOffset += chunkLen
			}
			encoded := combinedEncodedChunk.String()
			decodedChunk, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("failed to base64 decode TXT data '%s': %w", encoded, err)
			} else {
				fullPayload.Write(decodedChunk)
			}
		}
		offset += int(rdLength)
	}
	if fullPayload.Len() == 0 {
		return nil, errors.New("no decodable payload found in DNS response (despite ANCOUNT > 0)")
	}
	return fullPayload.Bytes(), nil
}
