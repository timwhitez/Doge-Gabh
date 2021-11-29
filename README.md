# Doge-Gabh
GetProcAddressByHash on Disk

#### add directsyscall from bananaphone

```
package main
import (
	"crypto/sha1"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
)

func main(){
	//sha1(sleep)=c3ca5f787365eae0dea86250e27d476406956478
	sleep_ptr,moduleN,err := gabh.GetFuncPtr("kernel32.dll","c3ca5f787365eae0dea86250e27d476406956478",str2sha1)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)
	
	//sha256(sleep)=d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0
	sleep_ptr,moduleN,err = gabh.GetFuncPtr("kernel32.dll","d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0",Sha256Hex)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)
	
	//NtDelayExecution by HellsGate
	sleep1,e := gabh.NtdllHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Printf("%s: %x\n","NtDelayExecution Sysid",sleep1)
	times := -(3000 * 10000)

	//hellsgate syscall
	gabh.HgSyscall(sleep1,0,uintptr(unsafe.Pointer(&times)))
}


func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}


func Sha256Hex(s string)string{
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte)[]byte{
	digest:=sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}

```

asm_x64.s from https://github.com/C-Sto/BananaPhone


### ref
https://github.com/Binject/debug/

https://github.com/C-Sto/BananaPhone

