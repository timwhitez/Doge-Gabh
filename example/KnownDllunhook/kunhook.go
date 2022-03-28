package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main() {

	dlls := []string{string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}),
		string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}),
		string([]byte{'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}),
	}

	e := gabh.KDllunhook(dlls)
	if e == nil {
		fmt.Println("Unhooked: ntdll.dll")
		fmt.Println("Unhooked: kernel32.dll")
		fmt.Println("Unhooked: kernelbase.dll")
	} else {
		panic(e)
	}

	//sha1(sleep)=c3ca5f787365eae0dea86250e27d476406956478
	sleep_ptr, _, err := gabh.DiskFuncPtr("kernel32.dll", "c3ca5f787365eae0dea86250e27d476406956478", str2sha1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("sleep 3s ")
	syscall.Syscall(uintptr(sleep_ptr), 1, 3000, 0, 0)

	//NtDelayExecution
	sleep1, _, err := gabh.MemFuncPtr("ntdll.dll", "84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
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
