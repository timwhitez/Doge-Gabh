![Doge-Gabh](https://socialify.git.ci/timwhitez/Doge-Gabh/image?description=1&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars1.githubusercontent.com%2Fu%2F36320909&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)

- 🐸Frog For Automatic Scan

- 🐶Doge For Defense Evasion & Offensive Security

# Doge-Gabh
GetProcAddressByHash/remap/full dll unhooking/Tartaru's Gate/Spoofing Gate/universal/Perun's Fart/Spoofing-Gate/EGG/RecycledGate golang implementation


Doge-Gabh为集成 Windows ntdll动态调用,直接系统调用,api hash调用,dll脱钩的Golang组件包。

包含多种地狱之门方法，脱钩方法，直接系统调用方法，动态api hash调用方法，可以灵活的使用这些方式，从磁盘或内存中调用系统api。

这可以用于许多目的，例如 PE 解析、动态 API 调用、shellcode loader、进程注入和绕过API挂钩等。

集成多种地狱之门以及地狱之门衍生项目的golang实现:Hells Gate/HalosGate/Tartaru's Gate/Spoofing Gate/Doge-EGGCall/RecycledGate

项目名称Gabh原意仅为GetAddressByHash, 后延申为类似DInvoke的动态调用工具包。


注意，本工具仅用于实现api调用。具体调用者实现的功能以及危害与项目本体无关。

```
example文件夹有较多调用示例可供参考
```

## Functions
```
//getfunc addr by hash from memory
gabh.MemFuncPtr()

//getfunc addr by hash from disk
gabh.DiskFuncPtr()

//get remap ntdll
gabh.ReMapNtdll()

//get remap func addr
GetFuncUnhook()

//ntdll Tartaru's Gate/Halo's Gate
gabh.MemHgate()

gabh.DiskHgate()

//Tartaru's Gate/Halo's Gate call sysid
gabh.HgSyscall()

eggreplace.FindAndReplace()

//Tartaru's Gate/Halo's Gate call sysid more EGG
gabh.EggCall()

//Spoofing-Gate
gabh.SpfGate()


//get universal ntdll
gabh.Universal()

//get universal func addr
UniversalFindProc()

//full dll unhooking
gabh.FullUnhook()

//Perun's Fart unhooking ntdll
gabh.PerunsFart()

//full dll unhooking use cmd.exe type
gabh.CMDUnhook()

//get syscall;ret
gabh.GetRecyCall()

//recycled gate call
gabh.ReCycall()

```

## Usage
https://github.com/timwhitez/Doge-Gabh/tree/main/example

```
package main
import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

func main(){
	//
	//	get funcPtr Universal
	//
	ntdll, _ := gabh.Universal(str2sha1)

	//str2sha1(NtDelayExecution)
	sleep, _ := ntdll.UniversalFindProc("84804f99e2c7ab8aee611d256a085cf4879c4be8")

	fmt.Printf("Universal Addr:0x%x\n", sleep)

	fmt.Println("Sleep for 3s")
	times := -(3000 * 10000)
	syscall.Syscall(sleep, 2, 0, uintptr(unsafe.Pointer(&times)), 0)

	//
	//	get funcPtr by hash
	//
	//sha1(sleep)=c3ca5f787365eae0dea86250e27d476406956478
	sleep_ptr,moduleN,err := gabh.MemFuncPtr("kernel32.dll","c3ca5f787365eae0dea86250e27d476406956478",str2sha1)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)

	//sha256(sleep)=d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0
	sleep_ptr,moduleN,err = gabh.DiskFuncPtr("kernel32.dll","d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0",Sha256Hex)
	if err != nil{
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n",moduleN,sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr),1,1000,0,0)


	//
	//	get unhook ntdll funcPtr by hash
	//
	unNt,e := gabh.ReMapNtdll()
	if e != nil{
		panic(e)
	}
	
	times = -(3000 * 10000)
	//NtDelayExecution
	NtDelayExecution_ptr,_,_ := unNt.GetFuncUnhook("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)

	fmt.Printf("%s: %x\n","NtDelayExecution ptr ",NtDelayExecution_ptr)
	syscall.Syscall(uintptr(NtDelayExecution_ptr),2,0,uintptr(unsafe.Pointer(&times)),0)


	//
	//	get ntdll hellsgate Sysid by hash
	//
	//NtDelayExecution HellsGate
	sleep1,e := gabh.DiskHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8",str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Printf("%s: %x\n","NtDelayExecution Sysid",sleep1)


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

asm_x64.s mod from https://github.com/C-Sto/BananaPhone


### ref
https://github.com/timwhitez/Doge-ReMap

https://idiotc4t.com/defense-evasion/load-ntdll-too

https://github.com/Binject/debug/

https://github.com/C-Sto/BananaPhone

https://github.com/Binject/universal

https://github.com/trickster0/TartarusGate

https://github.com/plackyhacker/Peruns-Fart

https://github.com/TomOS3/UserModeUnhooking/blob/main/CustomCode/PerunsFart/PerunsFart.cpp

https://github.com/timwhitez/Spoofing-Gate

https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/

https://github.com/klezVirus/SysWhispers3

# 🚀Star Trend
[![Stargazers over time](https://starchart.cc/timwhitez/Doge-Gabh.svg)](https://starchart.cc/timwhitez/Doge-Gabh)


