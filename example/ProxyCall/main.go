package main

import (
	"bufio"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/proxycall"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	GetModuleHandleA := syscall.NewLazyDLL("kernel32").NewProc("GetModuleHandleA")
	name, _ := syscall.BytePtrFromString("wininet.dll")
	proxycall.ProxyCall(
		syscall.NewLazyDLL("kernel32").
			NewProc("LoadLibraryA").Addr(), //function Address
		uintptr(unsafe.Pointer(name)), //module name
	)
	dllAddr, _, _ := GetModuleHandleA.Call(uintptr(unsafe.Pointer(name)))
	fmt.Printf("Module Address: 0x%x\n", dllAddr)

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	var allocatedAddress uintptr
	allocatedsize := uintptr(100)

	proxycall.ProxyCall(
		syscall.NewLazyDLL("ntdll.dll").
			NewProc("NtAllocateVirtualMemory").Addr(), //function Address
		uintptr(0xffffffffffffffff),                //ProcessHandle
		uintptr(unsafe.Pointer(&allocatedAddress)), //*BaseAddress
		uintptr(0),                              //ZeroBits
		uintptr(unsafe.Pointer(&allocatedsize)), //RegionSize
		uintptr(0x00001000|0x00002000),          //AllocationType
		syscall.PAGE_EXECUTE_READWRITE,          //Protect
	)

	fmt.Printf("Allocate: 0x%x\n", allocatedAddress)
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

}
