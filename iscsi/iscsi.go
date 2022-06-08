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
type Opcode byte

const (
	// Initiator opcodes
	NOP_OUT_OPCODE       Opcode = 0x00
	SCSI_COMMAND_OPCODE         = 0x01
	LOGIN_REQ_OPCODE            = 0x03
	TEXT_REQ_OPCODE             = 0x04
	SCSI_DATA_OUT_OPCODE        = 0x05
	// Target opcodes
	NOP_IN_OPCODE       = 0x20
	SCSI_RESP_OPCODE    = 0x21
	LOGIN_RESP_OPCODE   = 0x23
	TEXT_RESP_OPCODE    = 0x24
	SCSI_DATA_IN_OPCODE = 0x25
	REJECT_OPCODE       = 0x3f
)

// https://datatracker.ietf.org/doc/html/rfc3720#section-7.1.1
type State byte

const (
	STATE_FREE      State = 1
	STATE_LOGGED_IN       = 5
)

// https://datatracker.ietf.org/doc/html/rfc3720#section-10.12.3
type Stage byte

const (
	STAGE_SEC_NEG      Stage = 0
	STAGE_LOGIN_OP_NEG       = 1
	STAGE_FULL               = 3
)

// Target's constants
const (
	discoveryData = "TargetName=test.abc\x00TargetAddress=127.0.0.1:3260,1\x00"
)

// Device constants
const (
	DEVICE_PAGE_LEN = 32 // Device Identification Page - IBM Bridged
)

var VITAL_PAGES = [...]byte{0x00, 0x80, 0x83}

// LUN is Logical Unit Number
// See https://datatracker.ietf.org/doc/html/rfc3720#section-10.2.1.7
var LUNS = map[byte]map[string]string{
	0x00: {
		"vendorId":   "COMPANY",
		"productId":  "CONTROL",
		"deviceType": "\x0C",
	},
	0x01: {
		"vendorId":   "COMPANY",
		"productId":  "DEVICE0",
		"deviceType": "\x00",
	},
}

type Config struct {
	Host string
	Port string
}

type Server struct {
	addr     string
	listener net.Listener
}

// BHS is Basic Header Segment
// See https://datatracker.ietf.org/doc/html/rfc3720#section-10.2.1
type BHS struct {
	immediate         bool
	opcode            Opcode
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

// See README for explanations of types of sessions and examples them
type Session struct {
	conn               net.Conn
	maxRecvDSL         int
	status             State
	isDiscoverySession bool
}

// CDB is Command Descriptor Block
// See https://datatracker.ietf.org/doc/html/rfc3720#section-10.3.5
type CDB struct {
	LUNNumber        byte
	cdbLength        byte
	groupCode        byte
	opCode           byte
	arg              []byte
	allocationLength uint32
	control          byte
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
		c, err := s.listener.Accept()
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		session := &Session{
			status: STATE_FREE,
			conn:   c,
		}
		go session.readGor()
	}
}

func (s *Session) readGor() {
	defer s.conn.Close()
	for {
		p := ISCSIPacket{}
		err := p.recvBHS(s.conn)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
		dataLen := p.bhs.dataSegmentLength
		// Including padding
		if dataLen%4 != 0 {
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
		case TEXT_REQ_OPCODE:
			err = s.hangleTextReq(p)
		case LOGIN_REQ_OPCODE:
			err = s.handleLoginReq(p)
		default:
			if s.isDiscoverySession {
				fmt.Printf("In discovery session:\n")
			}
			fmt.Printf("Unsupported opcode: %x\n", p.bhs.opcode)
			err = s.handleUnsupportedReq(p)
		}
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}
	}
}

func (p *ISCSIPacket) recvBHS(conn net.Conn) error {
	buf := make([]byte, 48)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	if buf[0]&IMMEDIATE_DELIVERY_BITMASK != 0 {
		p.bhs.immediate = true
	}
	p.bhs.opcode = (Opcode)(buf[0] &^ IMMEDIATE_DELIVERY_BITMASK)
	if buf[1]&FINAL_PDU_BITMASK != 0 {
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

func (s *Session) hangleTextReq(req ISCSIPacket) error {
	if !s.isDiscoverySession {
		return errors.New("Unsupported text request in not discovery session\n")
	}
	ans := ISCSIPacket{}
	ans.bhs.arg0 = make([]byte, 3)
	lenData := len(discoveryData)
	if lenData%4 != 0 {
		lenData += 4 - lenData%4
	}
	ans.data = make([]byte, lenData)
	ans.bhs.opcode = TEXT_RESP_OPCODE
	ans.bhs.final = true
	ans.bhs.dataSegmentLength = (uint32)(lenData)
	ans.bhs.arg1 = make([]byte, 8)
	ans.bhs.initiatorTaskTag = req.bhs.initiatorTaskTag
	ans.bhs.arg2 = make([]byte, 28)
	binary.BigEndian.PutUint32(ans.bhs.arg2[0:4], 0xFFFFFFFF)
	// StatSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[4:8], req.bhs.initiatorTaskTag)
	// ExpCmdSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[8:12], req.bhs.initiatorTaskTag)
	// MaxCmdSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[12:16], req.bhs.initiatorTaskTag)
	ans.data = make([]byte, lenData)
	copy(ans.data, discoveryData)
	err := s.send(ans)
	return err
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
	if args["SessionType"] == "Discovery" {
		s.isDiscoverySession = true
	}
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
	var err error
	ans := ISCSIPacket{}
	cdb := CDB{}
	ans.bhs.opcode = SCSI_DATA_IN_OPCODE
	ans.bhs.final = true
	ans.bhs.arg0 = make([]byte, 3)
	ans.bhs.arg0[0] = 1
	ans.bhs.initiatorTaskTag = req.bhs.initiatorTaskTag
	ans.bhs.arg2 = make([]byte, 28)
	// Target transfer tag
	binary.BigEndian.PutUint32(ans.bhs.arg2[0:4], 0xFFFFFFFF)
	// StatSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[4:8], req.bhs.initiatorTaskTag)
	// ExpCmdSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[8:12], req.bhs.initiatorTaskTag)
	// MaxCmdSN
	binary.LittleEndian.PutUint32(ans.bhs.arg2[12:16], req.bhs.initiatorTaskTag+8)
	cdb.LUNNumber = req.bhs.arg1[0]
	cdb.groupCode = req.bhs.arg2[12] >> 5
	cdb.opCode = req.bhs.arg2[12]
	// Group code determines cdb length
	switch cdb.groupCode {
	case 0b000:
		cdb.cdbLength = 6
		cdb.arg = make([]byte, 3)
		copy(cdb.arg, req.bhs.arg2[13:16])
		cdb.allocationLength = uint32(req.bhs.arg2[16])
	case 0b101:
		cdb.cdbLength = 12
		cdb.arg = make([]byte, 5)
		copy(cdb.arg, req.bhs.arg2[13:18])
		cdb.allocationLength = binary.BigEndian.Uint32(req.bhs.arg2[18:22])
	case 0b100:
		cdb.cdbLength = 16
		cdb.arg = make([]byte, 9)
		copy(cdb.arg, req.bhs.arg2[13:22])
		cdb.allocationLength = binary.BigEndian.Uint32(req.bhs.arg2[22:26])
	case 0b001:
		cdb.cdbLength = 10
		cdb.arg = make([]byte, 5)
		copy(cdb.arg, req.bhs.arg2[13:18])
		cdb.allocationLength = uint32(binary.BigEndian.Uint16(req.bhs.arg2[19:21]))
	default:
		return errors.New(fmt.Sprintf("Error parsing CDB: unsupported group code %b\n", cdb.groupCode))
	}
	cdb.control = req.bhs.arg2[12+cdb.cdbLength-1]
	switch cdb.opCode {
	case 0x12:
		ans.data, err = cdb.parseInquiry()
	case 0xA0:
		ans.data, err = cdb.parseReportLun()
	case 0x00:
		ans.data, err = cdb.parseTestUnitReady()
	case 0x9E:
		ans.data, err = cdb.parseReadCapacity()
	case 0x1A:
		ans.data, err = cdb.parseModeSense()
	case 0xA3:
		ans.data, err = cdb.parseReportOpcodes()
	case 0x28:
		cdb.allocationLength *= 512 // Number of blocks
		ans.data, err = cdb.parseRead()
	default:
		err = errors.New(fmt.Sprintf("Error parsing CDB: unsupported command code %x\n", cdb.opCode))
	}
	if err != nil {
		return err
	}
	// Truncating if needed
	if int(cdb.allocationLength) < len(ans.data) {
		ans.bhs.dataSegmentLength = cdb.allocationLength
	} else {
		ans.bhs.dataSegmentLength = uint32(len(ans.data))
		if int(cdb.allocationLength) > len(ans.data) { // Underflow
			ans.bhs.arg0[0] |= 0x03
			binary.BigEndian.PutUint32(ans.bhs.arg2[24:28], cdb.allocationLength-uint32(len(ans.data)))
		}
	}
	err = s.send(ans)
	if err != nil {
		return err
	}
	return nil
}

// https://docs.oracle.com/en/storage/tape-storage/storagetek-sl150-modular-tape-library/slorm/report-luns-a0h.html
func (cdb *CDB) parseReportLun() ([]byte, error) {
	data := make([]byte, 8+len(LUNS)*8)
	// LUN list length
	binary.BigEndian.PutUint32(data[0:4], uint32(len(LUNS)*8))
	i := 0
	for LUNId := range LUNS {
		data[8*(i+1)] = LUNId
		i++
	}
	return data, nil
}

// https://docs.oracle.com/en/storage/tape-storage/storagetek-sl150-modular-tape-library/slorm/inquiry-12h.html
func (cdb *CDB) parseInquiry() ([]byte, error) {
	var data []byte
	if cdb.arg[0] == 0 { // Product data
		data = make([]byte, DEVICE_PAGE_LEN)
		// Peripheral qualifier + device type
		data[0] = LUNS[cdb.LUNNumber]["deviceType"][0]
		// Version
		data[2] = 0x05
		// Response data format
		data[3] = 2
		// Additional length
		data[4] = 62
		// Vendor ID
		copy(data[8:], LUNS[cdb.LUNNumber]["vendorId"])
		// Product ID
		copy(data[16:], LUNS[cdb.LUNNumber]["productId"])
	} else { // Vital Product Data
		switch cdb.arg[1] { // Type of vital page
		case 0x00: // List of vital pages
			data = make([]byte, 4+len(VITAL_PAGES))
			for i, vitalPage := range VITAL_PAGES {
				data[4+i] = vitalPage
			}
		case 0x80: // Unit serial number page
			data = make([]byte, 12)
			data[3] = 8
			copy(data[4:], LUNS[cdb.LUNNumber]["productId"])
		case 0x83: // Device Identification
			data = make([]byte, 48)
			// Protocol id | code set
			data[4] = 2
			// PIV | Association | id type
			//data[5] = 1
			data[5] = (0b1 << 7) + 0x1
			// id length
			data[7] = 8
			copy(data[8:], LUNS[cdb.LUNNumber]["productId"])
			// https://github.com/fujita/tgt/blob/master/usr/spc.c#L162
			data[16] = 1
			data[17] = 3
			data[19] = 8
			data[20] = cdb.LUNNumber
			data[20] |= 3 << 4
			data[28] = 1
			data[29] = 3
			data[31] = 0x10
			// NAA_DESG_LEN_EXTD
			data[32] = cdb.LUNNumber
			data[32] &= 0x0F
			data[32] |= 0x6 << 4
			data[40] = cdb.LUNNumber
		case 0xb0:
			data = make([]byte, 12)
			// Maximum compare and write length
			data[5] = 0
			// Maximum transfer length
			binary.BigEndian.PutUint32(data[8:12], 0xFFFFFFFF)
		default:
			return nil, errors.New(fmt.Sprintf("Error parsing CDB: unsupported vital product page: %x\n", cdb.arg[1]))
		}
		data[1] = cdb.arg[1]
		// Data length in 2 bytes
		data[2] = byte((len(data) - 4) >> 8)
		data[3] = byte(len(data) - 4)
	}
	return data, nil
}

func (cdb *CDB) parseTestUnitReady() ([]byte, error) {
	return nil, nil
}

func (cdb *CDB) parseReadCapacity() ([]byte, error) {
	data := make([]byte, 32)
	// logical block address
	data[7] = 0xFF
	// Logical block length in bytes
	data[10] = 0x02
	// Logical blocks per physical block exponent
	data[13] = 0x03
	return data, nil
}

func (cdb *CDB) parseModeSense() ([]byte, error) {
	return nil, nil
}

func (cdb *CDB) parseReportOpcodes() ([]byte, error) {
	if cdb.arg[0] != 0x0C {
		return nil, errors.New(fmt.Sprintf("Error parsing REPORT OPCODES: expected %x, found %x\n", 0x0C, cdb.arg[0]))
	}
	var data []byte
	// Bitmask for opcodes
	switch cdb.arg[2] {
	case 0x12: // Inquiry
		data = make([]byte, 4+6)
		copy(data[5:], "\x01\xFF\xFF\xFF\x07")
	case 0x93: // Write same (16)
		data = make([]byte, 4+16)
		copy(data[5:], "\xF8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x07")
	case 0x41: // Write same (10)
		data = make([]byte, 4+10)
		copy(data[5:], "\xF8\xFF\xFF\xFF\xFF\x00\xFF\xFF\x07")
	default:
		return nil, errors.New(fmt.Sprintf("Error parsing REPORT OPCODES: unsupported comand %x\n", cdb.arg[2]))
	}
	data[1] = 0x03                // SUPPORT
	data[3] = byte(len(data)) - 4 // Bitmask length
	data[4] = cdb.arg[1]          // Opcode
	return data, nil
}

func (cdb *CDB) parseRead() ([]byte, error) {
	data := make([]byte, cdb.allocationLength)
	var i uint32
	for i = 0; i < cdb.allocationLength; i += 4 {
		copy(data[i:i+4], "DATA")
	}
	return data, nil
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
	ans.data[0] = (byte)(req.bhs.opcode)
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
	buf[0] = (byte)(p.bhs.opcode)
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
		return errors.New(fmt.Sprintf("Error sending BHS: expected %d bytes, sent %d bytes\n", 48, sendLen))
	}
	// Padding
	if p.bhs.dataSegmentLength%4 != 0 {
		pad := make([]byte, 4-p.bhs.dataSegmentLength%4)
		p.data = append(p.data, pad...)
		p.bhs.dataSegmentLength += 4 - p.bhs.dataSegmentLength%4
	}
	sendLen, err = s.conn.Write(p.data[0:p.bhs.dataSegmentLength])
	if err != nil {
		return err
	}
	if uint32(sendLen) != p.bhs.dataSegmentLength {
		return errors.New(fmt.Sprintf("Error sending data: expected %d bytes, sent %d bytes\n", p.bhs.dataSegmentLength, sendLen))
	}
	return nil
}
