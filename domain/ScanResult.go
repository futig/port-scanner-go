package domain

import "time"

type ScanResult struct {
	Protocol string
	Port int
	Duration time.Duration
	Guess string
}