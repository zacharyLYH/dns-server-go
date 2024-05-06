package main

import (
	"bytes"
	"encoding/binary"
)

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func encodeDomainName(domain string) []byte {
	var buf bytes.Buffer
	labels := bytes.Split([]byte(domain), []byte("."))

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

func (ques *DNSQuestion) Bytes() []byte {
	var buff bytes.Buffer
	appendBigEndian(&buff, encodeDomainName(ques.Name))
	appendBigEndian(&buff, ques.Type)
	appendBigEndian(&buff, ques.Class)
	return buff.Bytes()
}
