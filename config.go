package cesiumlib

import (
	"time"
)

var (
	MaxB64SegmentSize  = 255
	MaxRawChunkSize    = 190
	MaxDNSLabelSize    = 63
	ClientRawChunkSize = 46
	MaxDNSPacketSize   = 1500
	KeepaliveInterval  = 5 * time.Second
	ReadPollInterval   = 100 * time.Millisecond

	AckTimeout        = 1500 * time.Millisecond
	MaxRetransmits    = 3
	FlowControlWindow = 5
	WriteTimeout      = 10 * time.Second
)

type Config struct {
	ClientRawChunkSize int
	KeepaliveInterval  time.Duration
	ReadPollInterval   time.Duration
	AckTimeout         time.Duration
	MaxRetransmits     int
	FlowControlWindow  int
	WriteTimeout       time.Duration
}

func DefaultConfig() Config {
	return Config{
		ClientRawChunkSize: ClientRawChunkSize,
		KeepaliveInterval:  KeepaliveInterval,
		ReadPollInterval:   ReadPollInterval,
		AckTimeout:         AckTimeout,
		MaxRetransmits:     MaxRetransmits,
		FlowControlWindow:  FlowControlWindow,
		WriteTimeout:       WriteTimeout,
	}
}

func Configure(cfg Config) {
	if cfg.ClientRawChunkSize > 0 {
		ClientRawChunkSize = cfg.ClientRawChunkSize
	}
	if cfg.KeepaliveInterval > 0 {
		KeepaliveInterval = cfg.KeepaliveInterval
	}
	if cfg.ReadPollInterval > 0 {
		ReadPollInterval = cfg.ReadPollInterval
	}
	if cfg.AckTimeout > 0 {
		AckTimeout = cfg.AckTimeout
	}
	if cfg.MaxRetransmits > 0 {
		MaxRetransmits = cfg.MaxRetransmits
	}
	if cfg.FlowControlWindow > 0 {
		FlowControlWindow = cfg.FlowControlWindow
	}
	if cfg.WriteTimeout > 0 {
		WriteTimeout = cfg.WriteTimeout
	}
}
