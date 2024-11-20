package main

import (
	"flag"
	"fmt"
	"os"

	mynat "github.com/ek-170/myroute"
	"github.com/ek-170/myroute/pkg/logger"
)

func main() {
	var (
		// TODO for CHANGE-REQUEST implemented STUN server
		// server      = flag.String("s", "", "STUN server url. CHANGE-REQUEST Attribute must be implemented in server")
		targetIface = flag.String("i", "en0", "target network interface of inspection")
		verbose     = flag.Bool("v", false, "verbose")
		help        = flag.Bool("h", false, "command usage help")
	)

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// TODO remove panic and display error massage

	if *verbose {
		if err := logger.InitLogger(os.Stdout, logger.Text, logger.DebugStr); err != nil {
			panic(err)
		}
	}

	// if *server != nil {
	// mynat.DiagnoseWithSingleSTUN(*server, *targetIface)
	// } else {
	fmt.Println("STUN server is not specified")
	fmt.Println("use Google public STUN server")
	fmt.Println("this only EIM NAT or other can be determined, and can not know fileter type")
	if err := mynat.DiagnoseWithPublicSTUN(*targetIface); err != nil {
		fmt.Println(err)
	}
	// }
}
