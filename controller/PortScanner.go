package controller

import (
	"sync"
	"github.com/futig/PortScannerGo/domain"
)

func ScanPorts(cfg *domain.ScannerConfig) []domain.ScanResult {
	var checked sync.Map
	var wg sync.WaitGroup
	results := make(chan domain.ScanResult, cfg.PortsCount)
	data := make(chan domain.PortScan, cfg.PortsCount)
	wg.Add(cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		go ScanPort(&wg, &results, &data, &checked)
	}

	for _, portsRange := range cfg.Ports {
		for port := portsRange.Start; port < portsRange.End; port++ {
			data <- domain.PortScan{
				Protocol: portsRange.Protocol,
				Port: port,	
			}
		}
	}

	portsArray := make([]domain.ScanResult, cfg.PortsCount)
	for res <- results {
		portsArray = append(portsArray, res)
	}
	wg.Wait()
	return portsArray
}


func ScanPort(wg *sync.WaitGroup, result *chan domain.ScanResult, 
			data *chan domain.PortScan, checked *sync.Map) {
	defer wg.Done()
}

func ScanPortUDP() {

}

func ScanPortTCP() {

}