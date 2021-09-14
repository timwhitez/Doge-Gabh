package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
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
}


func str2sha1(s string) string{
	//s = strings.ToLower(s)
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
