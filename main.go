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
	// header := "PROTOCOL  PORT"
	// if cfg.Verbose {
	// 	header += "     TIME(ms)"
	// }
	// if cfg.Guess {
	// 	header += "     GUESS"
	// }
	// fmt.Println(header)
	// fmt.Println("------------------------------------------------")

	line := fmt.Sprintf("%-9s %-6d", result.Protocol, result.Port)

	if cfg.Verbose {
		line += fmt.Sprintf(" %-10d", result.Duration.Milliseconds())
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