package domain

import "time"

type ScanResult struct {
	Protocol string
	Port int
	time time.Duration
	Gues string
}