package controller

import (
	"net"
	"time"
)

func scanUDP(targetIP net.IP, port int, timeout time.Duration) (bool, error) {
	addr := net.UDPAddr{
		IP:   targetIP,
		Port: port,
	}

    conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	_, err = conn.Write([]byte{})
	if err != nil {
		return false, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buf)
	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			// port may be open or filtered
			return true, nil
		}
		// Port Unreachable received
		return false, nil
	}
	return true, nil
}
