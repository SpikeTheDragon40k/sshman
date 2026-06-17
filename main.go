package main

import (
	"fmt"
	"os"

	"github.com/SpikeTheDragon40k/sshman/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:     "sshman",
		Usage:    "Manage SSH keys securely",
		Commands: cmd.Commands(),
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
