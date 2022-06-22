package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"github.com/timwhitez/Doge-Gabh/pkg/eggreplace"
	"reflect"
	"unsafe"
)


func main(){

	//NtDelayExecution HellsGate
	sleep1,e := gabh.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)
	if e != nil {
		panic(e)
	}


	fmt.Printf("0x%x\n",reflect.ValueOf(gabh.EggCall).Pointer())

	eggreplace.FindAndReplace(
		[]byte{0x65,0x67,0x67,0x63,0x61,0x6c,0x6c},
		[]byte{0x90,0x90,0x0f,0x05,0x90,0x90,0x90},
		reflect.ValueOf(gabh.EggCall).Pointer())


	fmt.Printf("%s: %x\n","NtDelayExecution Sysid",sleep1)
	times := -(3000 * 10000)

	gabh.EggCall(sleep1,0,uintptr(unsafe.Pointer(&times)))

}


func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
