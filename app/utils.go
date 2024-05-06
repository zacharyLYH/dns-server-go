package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

func encodeLabelName(value string) []byte {
	var buf bytes.Buffer
	labels := bytes.Split([]byte(value), []byte("."))

	for _, label := range labels {
		length := len(label)
		buf.WriteByte(byte(length))
		buf.Write(label)
	}
	// Write the null byte to indicate the end of the domain name.
	buf.WriteByte(0)

	return buf.Bytes()
}

func appendBigEndian(buf *bytes.Buffer, value interface{}) error {
	return binary.Write(buf, binary.BigEndian, value)
}

func ipToBigEndian(ipStr string) []byte {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil
	}
	// Convert the IP address to a 4-byte big-endian integer
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, binary.BigEndian.Uint32(ip))
	return buf
}

// ParseDNSHeader parses the first 12 bytes of a DNS message header
func ParseDNSHeader(b []byte) (*DNSHeader, error) {
	if len(b) < 12 {
		return nil, errors.New("headers are 12 bytes long")
	}

	// Parse the flags (bytes 2-3) into the DNSHeader structure
	flags := binary.BigEndian.Uint16(b[2:4])

	header := &DNSHeader{
		PacketID:              binary.BigEndian.Uint16(b[0:2]),
		QueryRespIndicator:    uint8((flags & (1 << 15)) >> 15),
		OpCode:                uint8((flags & (15 << 11)) >> 11),
		AuthoritiativeAns:     uint8((flags & (1 << 10)) >> 10),
		Truncation:            uint8((flags & (1 << 9)) >> 9),
		RecursionDesired:      uint8((flags & (1 << 8)) >> 8),
		RecursionAvailable:    uint8((flags & (1 << 7)) >> 7),
		Reserved:              uint8((flags & (7 << 4)) >> 4),
		ResponseCode:          uint8(flags & 15),
		QuestionCount:         binary.BigEndian.Uint16(b[4:6]),
		AnsRecordCount:        binary.BigEndian.Uint16(b[6:8]),
		AuthorityRecordCount:  binary.BigEndian.Uint16(b[8:10]),
		AdditionalRecordCount: binary.BigEndian.Uint16(b[10:12]),
	}

	return header, nil
}
