package controller

import (
	"net"
	"sync"
	"time"

	"github.com/futig/PortScannerGo/domain"
)


func ScanPorts(cfg *domain.ScannerConfig, writer func(domain.ScanResult, *domain.ScannerConfig)) {
	if cfg.Threads == 0 {
		syncScan(cfg, writer)
	} else {
		goScan(cfg, writer)
	}
}

func syncScan(cfg *domain.ScannerConfig, writer func(domain.ScanResult, *domain.ScannerConfig)) {
	for _, portsRange := range cfg.Ports {
		for port := portsRange.Start; port <= portsRange.End; port++ {
			value, ok := scanPort(portsRange.Protocol, port, cfg)
			if ok {
				writer(value, cfg)
			}
		}
	}
}

func goScan(cfg *domain.ScannerConfig, writer func(domain.ScanResult, *domain.ScannerConfig)) {
	var wg sync.WaitGroup
	results := make(chan domain.ScanResult, cfg.PortsCount)
	data := make(chan domain.PortScan, cfg.PortsCount)
	wg.Add(cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		go goScanPort(&wg, &results, &data, cfg)
	}

	go func() {
		checked := make(map[int]struct{}, cfg.PortsCount)
		for _, portsRange := range cfg.Ports {
			for port := portsRange.Start; port <= portsRange.End; port++ {
				if _, ok := checked[port]; ok {
					continue
				}
				data <- domain.PortScan{
					Protocol: portsRange.Protocol,
					Port:     port,
				}
				checked[port] = struct{}{}
			}
		}
		close(data)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		writer(res, cfg)
	}
}

func goScanPort(wg *sync.WaitGroup, results *chan domain.ScanResult,
	data *chan domain.PortScan, cfg *domain.ScannerConfig) {
	defer wg.Done()
	for val := range *data {
		value, ok := scanPort(val.Protocol, val.Port, cfg)
		if ok {
			*results <- value
		}
	}
}

func scanPort(protocol string, dstPort int, cfg *domain.ScannerConfig ) (domain.ScanResult, bool) {
	var open bool
	var duration time.Duration
	var err error
	var protocolDetected string
	var result domain.ScanResult

	if protocol == "tcp" {
		srcIp := net.ParseIP(domain.SRC_IP).To4()
		open, duration, err = scanTCP(srcIp, cfg.Ip, domain.SRC_PORT, dstPort, cfg.Timeout, cfg.Verbose)
		if err != nil {
			return result, false
		}
	} else if protocol == "udp" {
		open, err = scanUDP(cfg.Ip, dstPort, cfg.Timeout)
		if err != nil {
			return result, false
		}
	} else {
		return result, false
	}

	if !open {
		return result, false
	}

	if cfg.Guess {
		guessedProtocol, err := GuessProtocol(cfg.Ip, dstPort, cfg.Timeout)
		if err == nil {
			protocolDetected = guessedProtocol
		}
	}

	result = domain.ScanResult{
		Port:     dstPort,
		Protocol: protocol,
		Guess:    protocolDetected,
		Duration: duration,
	}
	return result, true
}