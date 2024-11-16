package main

import (
	"fmt"
	"os"

	cli "github.com/futig/PortScannerGo/presentation"
)

func main() {
	cfg, err := cli.ParseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%+v", cfg)
}
