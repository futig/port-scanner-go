package dns

import "fmt"

type Header struct {
	ID      uint16
	QR      uint16
	OPCode  uint16
	AA      uint16
	TC      uint16
	RD      uint16
	RA      uint16
	Z       uint16
	RCode   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

type ResponseData struct {
	Name       []byte
	Type       uint16
	Class      uint16
	TTL        uint32
	DataLength uint16
	Data       []byte
}

var Classes = map[uint16]string{
	1: "IN",
	2: "CS",
	3: "NCHS",
	4: "HS",
}

var Types = map[uint16]string{
	1: "A",
	28: "AAAA",
	2: "NS",
	5: "CNAME",
	15: "MX",
}

type Address struct {
	Ip   string
	Port uint16
}

type Request struct {
	Header Header
	Question Question
}

type Response struct {
	Header Header
	Question Question
	Answers []*ResponseData
	Authorities []*ResponseData
	Additionals []*ResponseData
}


func (h Header) String() string {
	return fmt.Sprintf("ID: %v, QR: %v, OPCode: %v, AA: %v, TC: %v, RD: %v, RA: %v, Z: %v, RCode: %v, QDCount: %v, ANCount: %v, NSCount: %v, ARCount: %v",
		h.ID, h.QR, h.OPCode, h.AA, h.TC, h.RD, h.RA, h.Z, h.RCode, h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}

func (q Question) String() string {
	return fmt.Sprintf("Name: %v, QType: %v, QClass: %v", parseNameRecord(q.QName), q.QType, q.QClass)
}

func (a ResponseData) String() string {
	return fmt.Sprintf("Name: %v, Type: %v, Class: %v, TTL: %v, DataLength: %v, Data: %v",
		parseNameRecord(a.Name), a.Type, a.Class, a.TTL, a.DataLength, a.Data)
}
