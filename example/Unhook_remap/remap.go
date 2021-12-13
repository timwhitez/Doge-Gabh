package main

import (
	"crypto/sha1"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main(){

	unNt,e := gabh.ReMapNtdll()
	if e != nil{
		panic(e)
	}

	//NtDelayExecution
	NtDelayExecution_ptr,_,_ := unNt.GetFuncUnhook("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)

	times := -(10000 * 10000)

	fmt.Println("sleep 10s")
	syscall.Syscall(uintptr(NtDelayExecution_ptr),2,0,uintptr(unsafe.Pointer(&times)),0)

}



func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}