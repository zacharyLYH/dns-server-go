package main

import (
	"bytes"
	"encoding/binary"
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
