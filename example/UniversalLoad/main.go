package main

import (
	"crypto/sha1"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main() {

	ntdll, _ := gabh.Universal(str2sha1)

	//str2sha1(NtDelayExecution)
	sleep, _ := ntdll.UniversalFindProc("84804f99e2c7ab8aee611d256a085cf4879c4be8")

	fmt.Printf("Universal Addr:0x%x\n", sleep)

	fmt.Println("Sleep for 3s")
	times := -(3000 * 10000)
	syscall.Syscall(sleep, 2, 0, uintptr(unsafe.Pointer(&times)), 0)

	sleep1 := syscall.NewLazyDLL("ntdll.dll").NewProc("NtDelayExecution")

	fmt.Printf("System Addr:0x%x\n", sleep1.Addr())
	fmt.Println("Sleep for 3s")

	syscall.Syscall(sleep1.Addr(), 2, 0, uintptr(unsafe.Pointer(&times)), 0)

}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
