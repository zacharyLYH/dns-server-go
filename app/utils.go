package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

func ParseDNSQuestion(b []byte, numQuestions int) ([]DNSQuestion, error) {
	var questions []DNSQuestion
	ptr := 12

	for i := 0; i < numQuestions; i++ {
		name, newPtr, err := ParseDNSName(b, ptr)
		if err != nil {
			return nil, err
		}
		ptr = newPtr

		if ptr+4 > len(b) {
			return nil, errors.New("not enough data for question type and class")
		}

		qType := binary.BigEndian.Uint16(b[ptr : ptr+2])
		qClass := binary.BigEndian.Uint16(b[ptr+2 : ptr+4])
		ptr += 4

		questions = append(questions, DNSQuestion{Name: name, Type: qType, Class: qClass})
	}

	return questions, nil
}

func ParseDNSName(b []byte, offset int) (string, int, error) {
	var name []byte
	originalOffset := offset
	pointerSeen := false

	for {
		if offset >= len(b) {
			return "", 0, fmt.Errorf("offset >= len(b)")
		}

		length := int(b[offset])

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(b) {
				return "", 0, fmt.Errorf("pointer at offset %d is incomplete", offset)
			}
			if !pointerSeen {
				originalOffset = offset + 2
				pointerSeen = true
			}

			pointerOffset := int(binary.BigEndian.Uint16(b[offset:offset+2]) & 0x3FFF)
			if pointerOffset >= len(b) {
				return "", 0, fmt.Errorf("pointer offset >= len(b)")
			}

			partialName, _, err := ParseDNSName(b, pointerOffset)
			if err != nil {
				return "", 0, err
			}
			name = append(name, partialName...)
			offset += 2
			break
		}

		offset++
		if length == 0 {
			break
		}
		if offset+length > len(b) {
			return "", 0, fmt.Errorf("length > len(b)")
		}

		name = append(name, b[offset:offset+length]...)
		name = append(name, '.')
		offset += length
	}

	if len(name) > 0 {
		name = name[:len(name)-1]
	}

	if pointerSeen {
		return string(name), originalOffset, nil
	}
	return string(name), offset, nil
}
