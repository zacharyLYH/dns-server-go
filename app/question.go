package main

import (
	"bytes"
)

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func (ques *DNSQuestion) Bytes() []byte {
	var buff bytes.Buffer
	appendBigEndian(&buff, encodeLabelName(ques.Name))
	appendBigEndian(&buff, ques.Type)
	appendBigEndian(&buff, ques.Class)
	return buff.Bytes()
}
