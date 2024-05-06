package main

import "encoding/binary"

type DNSHeader struct {
	PacketID              uint16 // PacketID is a random ID assigned to query packets
	QueryRespIndicator    uint8  // QueryIndicator is 1 for a reply packet, and 0 for a question packet
	OpCode                uint8  // OpCode specifies the kind of query in a message
	AuthoritiativeAns     uint8  // AuthoritiativeAns is 1 if the responding server "owns" the domain queried i.e. it's authoritative
	Truncation            uint8  // Truncation is 1 if the message is larger thab 512 bytes. Always 0 in UDP responses.
	RecursionDesired      uint8  // RecursionDesired is set to 1 if the the server should solve this query recursively else 0.
	RecursionAvailable    uint8  // RecursionAvailable is set to 1 to indicate that recursion is available
	Reserved              uint8  // Reserved is used by DNSSEC queries. At inception, it was reserved for future use.
	ResponseCode          uint8  // ResponseCode indicating the status of the response.
	QuestionCount         uint16 // QuestionCount is number of questions in the question section
	AnsRecordCount        uint16 // AnsRecordCount holds number of records in answer section.
	AuthorityRecordCount  uint16 // AuthorityRecordCount holds number of records in the authority section
	AdditionalRecordCount uint16 // AdditionalRecordCount holds number of records in the additional section
}

func (header *DNSHeader) Bytes() []byte {
	buff := make([]byte, 12)
	binary.BigEndian.PutUint16(buff[0:2], header.PacketID)
	flags :=
		uint16(header.QueryRespIndicator)<<15 |
			uint16(header.OpCode)<<11 |
			uint16(header.AuthoritiativeAns)<<10 |
			uint16(header.Truncation)<<9 |
			uint16(header.RecursionDesired)<<8 |
			uint16(header.RecursionAvailable)<<7 |
			uint16(header.Reserved)<<4 |
			uint16(header.ResponseCode)
	binary.BigEndian.PutUint16(buff[2:4], flags)
	binary.BigEndian.PutUint16(buff[4:6], header.QuestionCount)
	binary.BigEndian.PutUint16(buff[6:8], header.AnsRecordCount)
	binary.BigEndian.PutUint16(buff[8:10], header.AuthorityRecordCount)
	binary.BigEndian.PutUint16(buff[10:12], header.AdditionalRecordCount)
	return buff
}
