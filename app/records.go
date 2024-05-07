package main

import (
	"bytes"
	"net"
)

type DNSAnswers struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   net.IP
}

func (records *DNSAnswers) Bytes() []byte {
	var buff bytes.Buffer
	appendBigEndian(&buff, encodeLabelName(records.Name))
	appendBigEndian(&buff, records.Type)
	appendBigEndian(&buff, records.Class)
	appendBigEndian(&buff, records.TTL)
	appendBigEndian(&buff, records.Length)
	appendBigEndian(&buff, ipToBigEndian(records.Data.String()))
	return buff.Bytes()
}
