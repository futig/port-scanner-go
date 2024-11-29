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

	conn.SetDeadline(time.Now().Add(timeout))

	request := "HEAD / HTTP/1.0\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return false, err
	}

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return false, err
	}
	return true, nil
}
