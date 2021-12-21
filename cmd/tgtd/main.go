package main

import (
	"iscsi/iscsi"
	"iscsi/cmd/tgtd/serve"
	"fmt"
)

func main() {
	cfg := iscsi.Config{CONN_HOST: "127.0.0.1", CONN_PORT: "3260", CONN_TYPE: "tcp"}
	s, err := iscsi.NewIscsiConn(cfg)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	if err = s.Start(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	if err = serve.AcceptGor(s.Listener); err != nil {
		fmt.Printf("%s\n", err)
		return
	}
}
