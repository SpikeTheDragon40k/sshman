package main

import (
	"os"

	"github.com/sshman-org/sshman/app"
	"github.com/sshman-org/sshman/cmd"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	app.HardenProcess()
	os.Exit(cmd.Run(cmd.DefaultEnv(), os.Args, version))
}
