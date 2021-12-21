package serve

import (
	"net"
	"fmt"
	"encoding/binary"
)

const (
	OPCODE_BITMASK = 0b10111111
	LOGIN_OPCODE = 0x03
	DSL_BITMASK = 0x00FFFFFF
)


type BHS struct {
	Opcode byte
	AHSLength byte
	DataSegmentLength uint32
	LUN uint64
	InitiatorTaskTag uint32
}

type ISCSIPacket struct {
	Header BHS
	Data []byte
}

func AcceptGor(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go readGor(c)
	}
}

func readGor(conn net.Conn) {
	defer conn.Close()
	bufBHS := make([]byte, 48)
	if reqLen, err := conn.Read(bufBHS); err != nil || reqLen != 48 {
		if err != nil {
			fmt.Errorf("%s\n", err)
		} else {
			fmt.Errorf("Error readig BHS!\n")
		}
		return
	}
	p := ISCSIPacket{}
	p.readBHS(bufBHS)
	dataLen := p.Header.DataSegmentLength
	p.Data = make([]byte, dataLen)
	if reqLen, err := conn.Read(p.Data); err != nil || uint32(reqLen) != dataLen {
		if err != nil {
			fmt.Errorf("%s\n", err)
		} else {
			fmt.Errorf("Error reading Data!\n")
		}
		return
	}
	return
}

func (p *ISCSIPacket) readBHS(buf []byte) {
	p.Header.Opcode = buf[0] & OPCODE_BITMASK
	p.Header.AHSLength = buf[4]
	p.Header.DataSegmentLength = binary.BigEndian.Uint32(buf[4:8]) & DSL_BITMASK
	p.Header.LUN = binary.BigEndian.Uint64(buf[8:16])
	p.Header.InitiatorTaskTag = binary.BigEndian.Uint32(buf[16:20])
}
