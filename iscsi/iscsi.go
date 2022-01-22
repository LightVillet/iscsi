package iscsi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	IMMEDIATE_DELIVERY_BITMASK = 0b01000000
	FINAL_PDU_BITMASK          = 0b10000000
	WITHOUT_FIRST_BYTE_BITMASK = 0x00FFFFFF
)

const (
	LOGIN_REQ_OPCODE  = 0x03
	LOGIN_RESP_OPCODE = 0x23
)

const (
	STATUS_FREE      = 1
	STATUS_LOGGED_IN = 5
)

const (
	STAGE_SEC_NEG      = 0
	STAGE_LOGIN_OP_NEG = 1
	STAGE_FULL         = 3
)

type Config struct {
	CONN_HOST string
	CONN_PORT string
}

type Server struct {
	cfg      Config
	Listener net.Listener
}

type BHS struct {
	immediate         bool
	opcode            byte
	final             bool
	arg0              []byte
	totalAHSLength    byte
	dataSegmentLength uint32
	arg1              []byte
	initiatorTaskTag  uint32
	arg2              []byte
}

type ISCSIPacket struct {
	bhs  BHS
	data []byte
}

type Session struct {
	conn   net.Conn
	status int
}

func NewIscsiConn(cfg Config) (*Server, error) {
	server := &Server{cfg: cfg}
	return server, nil
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.cfg.CONN_HOST+":"+s.cfg.CONN_PORT)
	if err != nil {
		return err
	}
	fmt.Println("Server started")
	AcceptGor(l)
	return nil
}

func (s *Server) Stop() error {
	return s.Listener.Close()
}

func AcceptGor(l net.Listener) {
	for {
		s := Session{}
		s.status = STATUS_FREE
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		s.conn = c
		go s.readGor()
	}
}

func (s *Session) readGor() {
	defer s.conn.Close()
	var err error
	for {
		p := ISCSIPacket{}
		err = p.recvBHS(s.conn)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		dataLen := p.bhs.dataSegmentLength
		p.data = make([]byte, dataLen)
		reqLen, err := s.conn.Read(p.data)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		if uint32(reqLen) != dataLen {
			fmt.Printf("Error reading Data!\n")
			return
		}
		switch p.bhs.opcode {
		case LOGIN_REQ_OPCODE:
			err = s.handleLoginReq(p)
		default:
			fmt.Println("Not login!")
		}
		if err != nil {
			fmt.Printf("%s\n", err)
		}
		if p.bhs.final {
			return
		}
	}
}

func (p *ISCSIPacket) recvBHS(conn net.Conn) error {
	buf := make([]byte, 48)
	reqLen, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if reqLen != 48 {
		return errors.New("Error reading BHS")
	}
	if (buf[0]&IMMEDIATE_DELIVERY_BITMASK)<<7 == 1 {
		p.bhs.immediate = true
	}
	p.bhs.opcode = buf[0] &^ IMMEDIATE_DELIVERY_BITMASK
	if (buf[1]&FINAL_PDU_BITMASK)<<7 == 1 {
		p.bhs.final = true
	}
	p.bhs.arg0 = make([]byte, 3)
	copy(p.bhs.arg0, buf[1:4])
	p.bhs.arg0[0] &^= FINAL_PDU_BITMASK
	p.bhs.totalAHSLength = buf[4]
	p.bhs.dataSegmentLength = binary.BigEndian.Uint32(buf[4:8]) & WITHOUT_FIRST_BYTE_BITMASK
	p.bhs.arg1 = make([]byte, 8)
	copy(p.bhs.arg1, buf[8:16])
	p.bhs.initiatorTaskTag = binary.BigEndian.Uint32(buf[16:20])
	p.bhs.arg2 = make([]byte, 28)
	copy(p.bhs.arg2, buf[20:48])
	return nil
}

func (s *Session) handleLoginReq(req ISCSIPacket) error {
	args := make(map[string]string)
	version_max := req.bhs.arg0[1]
	version_min := req.bhs.arg0[2]
	for _, i := range strings.Split(string(req.data), "\x00") {
		if len(i) != 0 {
			args[strings.Split(i, "=")[0]] = strings.Split(i, "=")[1]
		}
	}
	for i, j := range args {
		fmt.Printf("%s = %s\n", i, j)
	}
	ans := ISCSIPacket{}
	ans.bhs.immediate = true
	ans.bhs.opcode = LOGIN_RESP_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	ans.bhs.arg0[0] = STAGE_FULL // NSG
	ans.bhs.arg0[1] = version_max
	ans.bhs.arg0[2] = version_min
	ans.bhs.dataSegmentLength = 0 //
	ans.bhs.arg1 = make([]byte, 8)
	ans.bhs.initiatorTaskTag = req.bhs.initiatorTaskTag
	ans.bhs.arg2 = make([]byte, 28)
	ans.bhs.arg2[16] = 0 // Status-Class
	err := s.send(ans)
	return err
}

func (s *Session) send(p ISCSIPacket) error {
	buf := make([]byte, 48+p.bhs.dataSegmentLength)
	buf[0] = p.bhs.opcode
	if p.bhs.immediate {
		buf[0] |= 0b01000000
	}
	copy(buf[1:4], p.bhs.arg0)
	if p.bhs.final {
		buf[1] |= 0b10000000
	}
	binary.BigEndian.PutUint32(buf[4:8], p.bhs.dataSegmentLength)
	buf[4] = p.bhs.totalAHSLength
	copy(buf[8:16], p.bhs.arg1)
	binary.BigEndian.PutUint32(buf[16:20], p.bhs.initiatorTaskTag)
	copy(buf[20:48], p.bhs.arg2)
	copy(buf[48:], p.data)
	sendLen, err := s.conn.Write(buf)
	if err != nil {
		return err
	}
	if uint32(sendLen) != 48+p.bhs.dataSegmentLength {
		return errors.New("Error sending data")
	}
	return nil
}
