package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main() {

	e := gabh.PerunsFart()
	if e == nil {
		fmt.Println("PerunsFart unhook Success: ntdll.dll")
	} else {
		fmt.Println(e)
	}

	//NtDelayExecution
	sleep1, _, err := gabh.GetFuncPtr("ntdll.dll", "84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if err != nil {
		fmt.Println(err)
		return
	}
	times := -(3000 * 10000)

	fmt.Println("NtDelayExecution 3s ")
	syscall.Syscall(uintptr(sleep1), 2, 0, uintptr(unsafe.Pointer(&times)), 0)

}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
