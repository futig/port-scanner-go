package domain

import (
	"net"
	"time"
)

type ScannerConfig struct {
	Timeout    time.Duration
	Threads    int
	Verbose    bool
	Guess      bool
	Ports      []PortScanInfo
	PortsCount int
	Ip         net.IP
}

func NewDefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig{
		Timeout: time.Second * 2,
		Threads: 1,
		Ports:   make([]PortScanInfo, 0),
		Ip:      nil,
	}
}
