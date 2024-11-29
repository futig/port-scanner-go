package controller

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/futig/PortScannerGo/domain"
)


func scanTCP(srcIP, dstIP net.IP, srcPort, dstPort int, timeout time.Duration, timer bool) (bool, time.Duration, error) {
	var elapsedTime time.Duration
	startTime := time.Now()

	err := sendSYNPacket(srcIP, dstIP, srcPort, dstPort)
	if err != nil {
		return false, elapsedTime, err
	}
	
	open, err := listenForResponse(domain.INTERFACE_NAME, srcIP, dstIP, srcPort, dstPort, timeout)
	if err != nil {
		return false, elapsedTime, err
	}
	elapsedTime = time.Since(startTime)
	return open, elapsedTime, nil
}

func sendSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort int) error {
	ipHeader := buildIPHeader(srcIP, dstIP)
	tcpHeader := buildTCPHeader(srcIP, dstIP, srcPort, dstPort)

	packet := append(ipHeader, tcpHeader...)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return err
	}

	// ipLayer := &layers.IPv4{
	//     SrcIP:    srcIP, // Replace with your source IP
	//     DstIP:    dstIP,
	//     Version:  4,
	//     TTL:      64,
	//     Protocol: layers.IPProtocolTCP,
	// }

	// tcpLayer := &layers.TCP{
	//     SrcPort: layers.TCPPort(srcPort), // Arbitrary source port
	//     DstPort: layers.TCPPort(dstPort),
	//     Seq:     1105024978,
	//     SYN:     true,
	//     Window:  14600,
	// }

	// // Set network layer for checksum calculation
	// err = tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	// if err != nil {
	//     return err
	// }

	// // Serialize the layers
	// buf := gopacket.NewSerializeBuffer()
	// opts := gopacket.SerializeOptions{
	//     ComputeChecksums: true,
	//     FixLengths:       true,
	// }

	// err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	// if err != nil {
	//     return err
	// }

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], dstIP)

	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return err
	}

	return nil
}

func listenForResponse(interfaceName string, srcIP, dstIP net.IP, srcPort, dstPort int, timeout time.Duration) (bool, error) {
	handle, err := pcap.OpenLive(interfaceName, 65536, true, time.Microsecond)
	if err != nil {
		return false, err
	}
	defer handle.Close()
	// Установка BPF-фильтра для захвата релевантных пакетов
	filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d", dstIP.String(), dstPort, srcPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return false, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutChan := time.After(timeout)

    for {
        select {
        case packet := <-packetSource.Packets() :
            if packet == nil {
                continue
            }
            tcpLayer := packet.Layer(layers.LayerTypeTCP)
            if tcpLayer != nil {
                tcp, ok := tcpLayer.(*layers.TCP)
                if !ok {
                    continue
                }
                if tcp.SrcPort == layers.TCPPort(dstPort) && tcp.DstPort == layers.TCPPort(srcPort) {
                    if tcp.SYN && tcp.ACK {
                        return true, nil // Порт открыт
                    } else if tcp.RST {
                        return false, nil // Порт закрыт
                    }
                }
            }
        case <-timeoutChan:
            return false, nil
		default:
			continue
        }
    }
}

func buildTCPHeader(srcIP, dstIP net.IP, srcPort, dstPort int) []byte {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	tcpHeader[12] = byte(5) << 4
	tcpHeader[13] = byte(2)
	binary.BigEndian.PutUint16(tcpHeader[14:16], uint16(14600))

	checksum := computeTCPChecksum(srcIP, dstIP, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	return tcpHeader
}

func buildIPHeader(srcIP, dstIP net.IP) []byte {
	ipHeader := make([]byte, 20)
	ipHeader[0] = byte(69)
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(40))
	ipHeader[8] = 64
	ipHeader[9] = 6
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)

	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	return ipHeader
}

func computeTCPChecksum(srcIP, dstIP net.IP, tcpHeader []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(20))
	checksumData := append(pseudoHeader, tcpHeader...)

	return calculateChecksum(checksumData)
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func isSYNACK(packet []byte, srcPort, dstPort int) bool {
	if len(packet) < 40 {
		return false
	}
	// Check TCP header
	tcpHeader := packet[20:40]
	srcPortResp := binary.BigEndian.Uint16(tcpHeader[0:2])
	dstPortResp := binary.BigEndian.Uint16(tcpHeader[2:4])
	flags := tcpHeader[13]
	if srcPortResp == uint16(dstPort) && dstPortResp == uint16(srcPort) && flags&0x12 == 0x12 {
		return true
	}
	return false
}
