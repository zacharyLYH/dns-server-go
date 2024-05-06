package main

import (
	"bytes"
	"fmt"
	"net"
)

type Message struct {
	Header   DNSHeader
	Question []DNSQuestion
	Answers  []DNSAnswers
}

func (m *Message) Bytes() []byte {
	var ret bytes.Buffer
	ret.Write(m.Header.Bytes())
	for _, question := range m.Question {
		ret.Write(question.Bytes())
	}
	for _, answer := range m.Answers {
		ret.Write(answer.Bytes())
	}
	return ret.Bytes()
}

// echo "Your Message" | nc -u 127.0.0.1 2053
func main() {
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedHeader, headerErr := ParseDNSHeader(buf[:size])

		if headerErr != nil {
			fmt.Println(err)
		}

		receivedQuestion, quesErr := ParseDNSQuestion(buf[12:])

		if quesErr != nil {
			fmt.Println(err)
		}

		response := Message{}

		response.Answers = []DNSAnswers{{
			Name:   receivedQuestion,
			Type:   1,
			Class:  1,
			TTL:    60,
			Length: 4,
			Data:   "8.8.8.8",
		}}

		response.Question = []DNSQuestion{{
			Name:  receivedQuestion,
			Type:  1,
			Class: 1,
		}}

		response.Header = DNSHeader{
			PacketID:           receivedHeader.PacketID,
			QueryRespIndicator: 1,
			OpCode:             receivedHeader.OpCode,
			AuthoritiativeAns:  0,
			Truncation:         0,
			RecursionDesired:   receivedHeader.RecursionDesired,
			RecursionAvailable: 0,
			Reserved:           0,
			ResponseCode: func() uint8 {
				if receivedHeader.OpCode == 0 {
					return 0 // No error
				}
				return 4 // Not implemented
			}(),
			QuestionCount:         uint16(len(response.Question)),
			AnsRecordCount:        uint16(len(response.Answers)),
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		}
		_, err = udpConn.WriteToUDP(response.Bytes(), source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
