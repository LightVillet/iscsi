package iscsi

import (
	"net"
)

type Config struct {
	CONN_HOST string
	CONN_PORT string
	CONN_TYPE string
}

type Server struct {
	cfg Config
	Listener net.Listener
}

func NewIscsiConn(cfg Config) (*Server, error) {
	server := &Server{cfg: cfg}
	return server, nil
}

func (s *Server) Start() error {
	l, err := net.Listen(s.cfg.CONN_TYPE, s.cfg.CONN_HOST + ":" + s.cfg.CONN_PORT)
	s.Listener = l
	return err
}

func (s *Server) Stop() error {
	return s.Listener.Close()
}
/*
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
*/
