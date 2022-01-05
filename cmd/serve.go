package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"tgtd/iscsi"

	"github.com/spf13/cobra"
)

var serveFlags struct {
	host string
	port string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Create an iSCSI server",
	Args:  cobra.ExactArgs(2),
	Run:   runTgtd,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&serveFlags.host, "host", "h", "127.0.0.1", "Connection host ip")
	serveCmd.Flags().StringVarP(&serveFlags.port, "port", "p", "3260", "Connection port")
}

func runTgtd(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := iscsi.NewIscsiServer(iscsi.Config{
		Host: serveFlags.host,
		Port: serveFlags.port,
	})
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	if err = s.Start(); err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	<-ctx.Done()

	s.Stop()
}
