package controller

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/futig/PortScannerGo/application/dns"
	"github.com/futig/PortScannerGo/domain"
)

func GuessProtocol( ip net.IP, port int, timeout time.Duration) (string, error) {
    stdProtocol, ok := detectStandartPort(port)
    if ok {
        return stdProtocol, nil
    }

    isHttp, err := detectHTTP(ip, port, timeout)
    if err == nil && isHttp {
        return "HTTP", nil
    }

    isEcho, err := detectEcho(ip, port, timeout)
    if err == nil && isEcho {
        return "ECHO", nil
    }
    
    isDns, err := detectDNS(ip, port, timeout)
    if err == nil && isDns {
        return "DNS", nil
    }

    return "", fmt.Errorf("failed to detect protocol")
}

func detectStandartPort(port int) (string, bool) {
    value, ok := domain.StandartPorts[port]
    return value, ok
}


func detectHTTP(targetIP net.IP, port int, timeout time.Duration) (bool, error) {
    address := fmt.Sprintf("%s:%d", targetIP.String(), port)
    conn, err := net.DialTimeout("tcp", address, timeout)
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

    reader := bufio.NewReader(conn)
    line, err := reader.ReadString('\n')
    if err != nil {
        return false, err
    }

    if strings.Contains(line, "HTTP/") {
        return true, nil
    }
    return false, nil
}


func detectDNS(targetIP net.IP, port int, timeout time.Duration) (bool, error) {
    address := fmt.Sprintf("%s:%d", targetIP.String(), port)
    conn, err := net.DialTimeout("udp", address, timeout)
    if err != nil {
        return false, err
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(timeout))
    // habrahabr.ru A
    hexStr := "9bce0100000100000000000109686162726168616272027275000001000100002904d000000000000c000a00085de710734d259aec"
    bytes, _ := hex.DecodeString(hexStr)
	_, err = conn.Write(bytes)
	if err != nil {
		return false, err
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
    
	if err != nil {
		return false, err
	}

    _, err = dns.ParseResponse(buffer[:n])
    if err != nil {
        return false, err
    }

    return true, nil
}


func detectEcho(targetIP net.IP, port int, timeout time.Duration) (bool, error) {
    address := fmt.Sprintf("%s:%d", targetIP.String(), port)
    conn, err := net.DialTimeout("udp", address, timeout)
    if err != nil {
        return false, err
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(timeout))

    message := "Echo test message"
    _, err = conn.Write([]byte(message))
    if err != nil {
        return false, err
    }

    buf := make([]byte, len(message))
    _, err = conn.Read(buf)
    if err != nil {
        return false, err
    }

    if string(buf) == message {
        return true, nil
    }
    return false, nil
}
