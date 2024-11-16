package presentation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	domain "github.com/futig/PortScannerGo/domain"
)

func ParseArgs() (*domain.ScannerConfig, error) {
	args := os.Args[1:]
	cfg := domain.NewDefaultScannerConfig()

	optionsEnd, err := readOptions(args, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	if optionsEnd+1 >= len(args) {
		return nil, fmt.Errorf("failed to parse ip: there is no ip")
	}

	err = readIp(args[optionsEnd+1], cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip: %w", err)
	}

	if optionsEnd+2 >= len(args) {
		return nil, fmt.Errorf("failed to parse ports: there is no ports to scan")
	}

	err = readPorts(args[1:], cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ports: %w", err)
	}

	return cfg, nil
}

func readOptions(args []string, cfg *domain.ScannerConfig) (int, error) {
	timeoutSet := false
	threadsSet := false
	verboseSet := false
	guessSet := false
	i := 0
	for ; i < len(args); i++ {
		switch args[i] {
		case "--timeout":
			err := parseTimeoutOption(i, args, timeoutSet, cfg)
			if err != nil {
				return 0, err
			}
			i++
			timeoutSet = true

		case "-j", "--num-threads":
			err := parseThreadOption(i, args, threadsSet, cfg)
			if err != nil {
				return 0, err
			}
			i++
			threadsSet = true

		case "-v", "--verbose":
			if verboseSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			cfg.Verbose = true
			verboseSet = true

		case "-g", "--guess":
			if guessSet {
				return 0, fmt.Errorf("option '%v' is repeated", args[i])
			}
			cfg.Guess = true
			guessSet = true

		default:
			if strings.HasPrefix(args[i], "-") {
				return 0, fmt.Errorf("there is no such option: %v", args[i])
			}
			return i - 1, nil
		}
	}

	return i - 1, nil
}

func readIp(ip string, cfg *domain.ScannerConfig) error {
	if net.ParseIP(ip) == nil {
		fmt.Errorf("invalid IP address '%s'\n", ip)
	}
	cfg.Ip = ip
	return nil
}

func readPorts(args []string, cfg *domain.ScannerConfig) error {
	return nil
}

func readIntValue(i int, args []string) (int, error) {
	if i+1 >= len(args) {
		return 0, fmt.Errorf("there is no value for option '%v'", args[i])
	}
	value, err := strconv.Atoi(args[i+1])
	if err != nil {
		return 0, fmt.Errorf("value of option '%v' must be integer, not '%T'", args[i], args[i])
	}
	return value, nil
}

func parseTimeoutOption(i int, args []string, set bool, cfg *domain.ScannerConfig) error {
	if set {
		return fmt.Errorf("option '%v' is repeated", args[i])
	}
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	cfg.Timeout = time.Second * time.Duration(value)
	return nil
}

func parseThreadOption(i int, args []string, set bool, cfg *domain.ScannerConfig) error {
	if set {
		return fmt.Errorf("option '%v' is repeated", args[i])
	}
	value, err := readIntValue(i, args)
	if err != nil {
		return err
	}
	cfg.Threads = value
	return nil
}
