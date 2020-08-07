package main

import (
	"fmt"
	"os"

	"gopkg.in/rcon.v0"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Wrong number of args")
		os.Exit(1)
		return
	}

	addr := os.Args[1]
	pass := os.Args[2]
	cmd := os.Args[3]

	c, err := rcon.NewClient(addr, pass)
	if err != nil {
		fmt.Println("connection error:", err)
		return
	}

	resp, err := c.RunCommand(cmd)
	if err != nil {
		fmt.Println("command error:", err)
		return
	}

	fmt.Println(resp)
}
