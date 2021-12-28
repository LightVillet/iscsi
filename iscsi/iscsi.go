package iscsi

import (
	"fmt"
	"net"
	"encoding/binary"
	"strings"
)

const (
	OPCODE_BITMASK = 0b10111111
	LOGIN_OPCODE = 0x03
	DSL_BITMASK = 0x00FFFFFF
)

type Config struct {
	CONN_HOST string
	CONN_PORT string
}

type Server struct {
	cfg Config
	Listener net.Listener
}

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

func NewIscsiConn(cfg Config) (*Server, error) {
	server := &Server{cfg: cfg}
	return server, nil
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.cfg.CONN_HOST + ":" + s.cfg.CONN_PORT)
	go AcceptGor(l)
	return err
}

func (s *Server) Stop() error {
	return s.Listener.Close()
}

func AcceptGor(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Errorf("%s\n", err)
			return
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
	if p.Header.Opcode == LOGIN_OPCODE {
		parseLoginReq(p)
	} else {
		fmt.Println("Not login!")
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


func parseLoginReq(packet ISCSIPacket) error {
	fmt.Printf("Data length: %d\n", packet.Header.DataSegmentLength)
	args := make(map[string]string)
	for _, i := range strings.Split(string(packet.Data), "\x00") {
		if len(i) != 0 {
			args[strings.Split(i, "=")[0]] = strings.Split(i, "=")[1]
		}
	}
	for i, j := range args {
		fmt.Printf("%s = %s\n", i, j)
	}
	return nil
}

