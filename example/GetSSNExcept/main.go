package main

import (
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
)

func main() {
	sysid, err := gabh.GetSSNByNameExcept("ZwAllocateVirtualMemory", func(a string) string { return a })
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Get Sysid From SSN: %x\n", sysid)
}
