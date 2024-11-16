package domain

import "time"

type ScannerConfig struct {
	Timeout time.Duration
	Threads int
	Verbose bool
	Guess bool
	Ports []PortScan
	Ip string
}

func NewDefaultScannerConfig() *ScannerConfig {
	return &ScannerConfig {
		Timeout: time.Second * 2,
		Threads: 1,
		Ports: make([]PortScan, 0),
		Ip: "",
	}
}
