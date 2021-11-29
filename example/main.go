package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main(){
	//sha1(sleep)=c3ca5f787365eae0dea86250e27d476406956478
	sleep_ptr,moduleN,err := gabh.GetFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e','l','3','2','.','d','l','l'}),"c3ca5f787365eae0dea86250e27d476406956478",str2sha1)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)

	//sha1(Sleep)=3cac34e674464c2b62286054cd9a2d2c81149efc
	sleep_ptr,moduleN,err = gabh.GetFuncPtr(string([]byte{'k', 'e', 'r', 'n', 'e','l','3','2','.','d','l','l'}),"3cac34e674464c2b62286054cd9a2d2c81149efc",str2sha1)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)



	//NtDelayExecution
	sleep1,e := gabh.NtdllHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Println(sleep1)
	times := -(3000 * 10000)

	//hellsgate syscall
	gabh.HgSyscall(sleep1,0,uintptr(unsafe.Pointer(&times)))
}



func str2sha1(s string) string{
	//s = strings.ToLower(s)
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
