package iscsi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	IMMEDIATE_DELIVERY_BITMASK = 0b01000000
	FINAL_PDU_BITMASK          = 0b10000000
	WITHOUT_FIRST_BYTE_BITMASK = 0x00FFFFFF
)

// https://datatracker.ietf.org/doc/html/rfc3720#section-10.2.1.2
const (
	// Initiator opcodes
	NOP_OUT_OPCODE       = 0x00
	SCSI_COMMAND_OPCODE  = 0x01
	LOGIN_REQ_OPCODE     = 0x03
	SCSI_DATA_OUT_OPCODE = 0x05
	// Target opcodes
	NOP_IN_OPCODE       = 0x20
	SCSI_RESP_OPCODE    = 0x21
	LOGIN_RESP_OPCODE   = 0x23
	SCSI_DATA_IN_OPCODE = 0x25
	REJECT_OPCODE       = 0x3f
)

// https://datatracker.ietf.org/doc/html/rfc3720#section-7.1.1
const (
	STATE_FREE      = 1
	STATE_LOGGED_IN = 5
)

// https://datatracker.ietf.org/doc/html/rfc3720#section-10.12.3
const (
	STAGE_SEC_NEG      = 0
	STAGE_LOGIN_OP_NEG = 1
	STAGE_FULL         = 3
)

type Config struct {
	Host string
	Port string
}

type Server struct {
	addr     string
	listener net.Listener
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
	conn             net.Conn
	maxRecvDSL       int
	initiatorTaskTag uint32
	status           int
}

type CDB struct {
	cdb_length          byte
	groupCode           byte
	commandCode         byte
	arg0                byte
	logicalBlockAddress uint64
	transferLength      byte
	paramLIstLength     byte
	allocationLength    uint16
	arg1                byte
	control             byte
}

func NewIscsiServer(cfg Config) (*Server, error) {
	server := &Server{
		addr: net.JoinHostPort(cfg.Host, cfg.Port),
	}
	return server, nil
}

func (s *Server) Start() error {
	if s.listener == nil {
		l, err := net.Listen("tcp", s.addr)
		if err != nil {
			return err
		}
		s.listener = l
	}

	go s.acceptGor()
	return nil
}

func (s *Server) Stop() error {
	return s.listener.Close()
}

func (s *Server) acceptGor() {
	for {
		session := Session{}
		session.status = STATE_FREE
		c, err := s.listener.Accept()
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		session.conn = c
		go session.readGor()
	}
}

func (s *Session) readGor() {
	//defer s.conn.Close()
	for {
		p := ISCSIPacket{}
		err := p.recvBHS(s.conn)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		s.initiatorTaskTag = p.bhs.initiatorTaskTag
		dataLen := p.bhs.dataSegmentLength
		// Including padding
		if dataLen/4 != 0 {
			dataLen += 4 - dataLen%4
		}
		p.data = make([]byte, dataLen)
		_, err = io.ReadFull(s.conn, p.data)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		switch p.bhs.opcode {
		case NOP_OUT_OPCODE:
			err = s.handleNOPReq(p)
		case SCSI_COMMAND_OPCODE:
			err = s.handleSCSIReq(p)
		case LOGIN_REQ_OPCODE:
			err = s.handleLoginReq(p)
		default:
			fmt.Printf("Unsopported opcode: %x\n", p.bhs.opcode)
			err = s.handleUnsupportedReq(p)
		}
		if err != nil {
			fmt.Printf("%s\n", err)
		}
	}
}

func (p *ISCSIPacket) recvBHS(conn net.Conn) error {
	buf := make([]byte, 48)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	if (buf[0]&IMMEDIATE_DELIVERY_BITMASK)<<7 == 1 {
		p.bhs.immediate = true
	}
	p.bhs.opcode = buf[0] &^ IMMEDIATE_DELIVERY_BITMASK
	if (buf[1]&FINAL_PDU_BITMASK)>>7 == 1 {
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

func (s *Session) handleNOPReq(req ISCSIPacket) error {
	ans := ISCSIPacket{}
	ans.bhs.opcode = NOP_IN_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	copy(ans.bhs.arg0, req.bhs.arg0)
	ans.bhs.arg1 = make([]byte, 8)
	copy(ans.bhs.arg1, req.bhs.arg1)
	ans.bhs.arg2 = make([]byte, 28)
	copy(ans.bhs.arg2, req.bhs.arg2)
	return s.send(ans)
}

func (s *Session) handleLoginReq(req ISCSIPacket) error {
	args := make(map[string]string)
	var err error
	version_max := req.bhs.arg0[1]
	version_min := req.bhs.arg0[2]
	for _, i := range strings.Split(string(req.data), "\x00") {
		if len(i) != 0 {
			args[strings.Split(i, "=")[0]] = strings.Split(i, "=")[1]
		}
	}
	s.maxRecvDSL, err = strconv.Atoi(args["MaxRecvDataSegmentLength"])
	if err != nil {
		return err
	}
	ans := ISCSIPacket{}
	// Collecting BHS
	ans.bhs.opcode = LOGIN_RESP_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	ans.bhs.arg0[0] = (STAGE_LOGIN_OP_NEG << 2) + STAGE_FULL // CSG | NSG
	ans.bhs.arg0[1] = version_max
	ans.bhs.arg0[2] = version_min
	ans.bhs.arg1 = make([]byte, 8)
	copy(ans.bhs.arg1, req.bhs.arg1)
	ans.bhs.arg1[6] = 0x3 // random TSIH
	ans.bhs.initiatorTaskTag = req.bhs.initiatorTaskTag
	ans.bhs.arg2 = make([]byte, 28)
	ans.bhs.arg2[16] = 0 // Status-Class
	ans.bhs.arg2[15] = 1
	err = s.send(ans)
	return err
}

func (s *Session) handleSCSIReq(req ISCSIPacket) error {
	ans := ISCSIPacket{}
	var err error
	cdb := CDB{}
	cdb.groupCode = req.bhs.arg2[12] >> 5
	cdb.commandCode = req.bhs.arg2[12] & 0x1F
	// Group code determines cdb length
	switch cdb.groupCode {
	case 0b000:
		cdb.cdb_length = 6
	default:
		return errors.New(fmt.Sprintf("Error parsing CDB: unsopported group code %x", cdb.groupCode))
	}
	cdb.control = req.bhs.arg2[12+cdb.cdb_length-1]
	switch cdb.commandCode {
	case 0x12:
		ans, err = cdb.parseInquiryCDB(req)
	default:
		return errors.New(fmt.Sprintf("Error parsing CDB: unsopported command code %x", cdb.commandCode))
	}
	err = s.send(ans)
	return err
}

// https://docs.oracle.com/en/storage/tape-storage/storagetek-sl150-modular-tape-library/slorm/inquiry-12h.html
func (cdb *CDB) parseInquiryCDB(req ISCSIPacket) (ISCSIPacket, error) {
	cdb.allocationLength = binary.BigEndian.Uint16(req.bhs.arg2[15:17])
	// Temporary sending no devices
	// TODO
	ans := ISCSIPacket{}
	ans.bhs.opcode = SCSI_DATA_IN_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	ans.bhs.arg0[0] = 1
	ans.bhs.dataSegmentLength = uint32(cdb.allocationLength)
	ans.bhs.initiatorTaskTag = req.bhs.initiatorTaskTag
	ans.bhs.arg2 = make([]byte, 28)
	// Target transfer tag
	binary.BigEndian.PutUint32(ans.bhs.arg2[0:4], 0xFFFFFFFF)
	// StatSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[4:8], req.bhs.initiatorTaskTag)
	// ExpCmdSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[8:12], req.bhs.initiatorTaskTag)
	// MaxCmdSN ?????
	binary.LittleEndian.PutUint32(ans.bhs.arg2[12:16], req.bhs.initiatorTaskTag)
	ans.data = make([]byte, int(ans.bhs.dataSegmentLength))
	// Peripheral qualifier + device type
	ans.data[0] = (0b011 << 5) + 0x1F
	// Responce data format
	ans.data[3] = 2
	return ans, nil
}

func (s *Session) handleUnsupportedReq(req ISCSIPacket) error {
	ans := ISCSIPacket{}
	ans.bhs.opcode = REJECT_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	ans.bhs.arg0[1] = 0x05
	ans.bhs.dataSegmentLength = 48 + req.bhs.dataSegmentLength
	ans.bhs.arg1 = make([]byte, 8)
	copy(ans.bhs.arg1, req.bhs.arg1)
	ans.bhs.initiatorTaskTag = 0xFFFFFFFF
	ans.data = make([]byte, 48+req.bhs.dataSegmentLength)
	ans.data[0] = req.bhs.opcode
	if req.bhs.immediate {
		ans.data[0] |= 0b01000000
	}
	copy(ans.data[1:4], req.bhs.arg0)
	if req.bhs.final {
		ans.data[1] |= 0b10000000
	}
	binary.BigEndian.PutUint32(ans.data[4:8], req.bhs.dataSegmentLength)
	ans.data[4] = req.bhs.totalAHSLength
	copy(ans.data[8:16], req.bhs.arg1)
	binary.BigEndian.PutUint32(ans.data[16:20], req.bhs.initiatorTaskTag)
	copy(ans.data[20:48], req.bhs.arg2)
	copy(ans.data[48:], req.data)
	return s.send(ans)
}

func (s *Session) send(p ISCSIPacket) error {
	buf := make([]byte, 48)
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
	sendLen, err := s.conn.Write(buf)
	if err != nil {
		return err
	}
	if uint32(sendLen) != 48 {
		return errors.New(fmt.Sprintf("Error sending BHS: expected %d bytes, sent %d bytes", 48, sendLen))
	}
	sendLen, err = s.conn.Write(p.data)
	if err != nil {
		return err
	}
	if uint32(sendLen) != p.bhs.dataSegmentLength {
		return errors.New(fmt.Sprintf("Error sending data: expected %d bytes, sent %d bytes", p.bhs.dataSegmentLength, sendLen))
	}
	return nil
}
