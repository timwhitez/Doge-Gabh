package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"github.com/timwhitez/Doge-Gabh/pkg/eggreplace"
	"reflect"
	"syscall"
	"unsafe"
)

func main() {
	//sha1(sleep)=c3ca5f787365eae0dea86250e27d476406956478
	sleep_ptr, moduleN, err := gabh.DiskFuncPtr("kernel32.dll", "c3ca5f787365eae0dea86250e27d476406956478", str2sha1)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n", moduleN, sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr), 1, 1000, 0, 0)

	//sha256(sleep)=d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0
	sleep_ptr, moduleN, err = gabh.MemFuncPtr("kernel32.dll", "d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0", Sha256Hex)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n", moduleN, sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr), 1, 1000, 0, 0)

	times := -(3000 * 10000)

	//sha256(sleep)=d466bcf52eb6921b1e747e51bf2cc1441926455ba146ecc477bed1574e44f9c0
	sleep_ptr, moduleN, err = gabh.MemFuncPtr("ntdll.dll", "84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s: %x\n", moduleN, sleep_ptr)
	syscall.Syscall(uintptr(sleep_ptr), 2, 0, uintptr(unsafe.Pointer(&times)), 0)

	//NtDelayExecution HellsGate
	sleep1, e := gabh.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Printf("0x%x\n", reflect.ValueOf(gabh.EggCall).Pointer())

	//fmt.Print("Press 'Enter' to continue...")
	//bufio.NewReader(os.Stdin).ReadBytes('\n')

	eggreplace.FindAndReplace(
		[]byte{0x65, 0x67, 0x67, 0x63, 0x61, 0x6c, 0x6c},
		[]byte{0x90, 0x90, 0x0f, 0x05, 0x90, 0x90, 0x90},
		reflect.ValueOf(gabh.EggCall).Pointer())

	fmt.Printf("%s: %x\n", "NtDelayExecution Sysid", sleep1)

	//hellsgate syscall
	gabh.HgSyscall(sleep1, 0, uintptr(unsafe.Pointer(&times)))

	fmt.Printf("%s: %x\n", "NtDelayExecution Sysid", sleep1)

	gabh.EggCall(sleep1, 0, uintptr(unsafe.Pointer(&times)))

}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
