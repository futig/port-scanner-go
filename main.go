package main

import (
	"fmt"
	"os"

	cli "github.com/futig/PortScannerGo/presentation"
	"github.com/futig/PortScannerGo/application/controller"
	"github.com/futig/PortScannerGo/domain"
)

func main() {
	cfg, err := cli.ParseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	controller.ScanPorts(cfg, PrintOpenPort)
}

func PrintOpenPort(result domain.ScanResult, cfg *domain.ScannerConfig) {
	line := fmt.Sprintf("%s %-10s %d %-10s", result.Protocol, " ", result.Port, " ")

	if cfg.Verbose {
		if result.Protocol == "tcp" {
			line += fmt.Sprintf(" [%dms] %-10s", result.Duration.Milliseconds(), " ")
		} else {
			line += fmt.Sprintf(" [%s] %-10s", "-", " ")
		}
	}

	if cfg.Guess {
		guess := result.Guess
		if guess == "" {
			guess = "-"
		}
		line += fmt.Sprintf(" %-6s", guess)
	}

	fmt.Println(line)
}