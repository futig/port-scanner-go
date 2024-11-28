package main

import (
	"fmt"
	"os"

	cli "github.com/futig/PortScannerGo/presentation"
	"github.com/futig/PortScannerGo/controller"
)

func main() {
	cfg, err := cli.ParseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	result := controller.ScanPorts(cfg)
	
	fmt.Printf("%+v", cfg)
}
