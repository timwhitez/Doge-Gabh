package eggreplace

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func FindAndReplace(egg []byte ,replace []byte,startAddress uintptr){

	var currentOffset = uintptr(0)
	current := make([]byte,7)
	var nBytesRead uintptr

	fmt.Printf("Starting search from: 0x%x\n", startAddress + currentOffset)

	for !(current[0] == 0xff && current[1] == 0xff && current[2] == 0xff && current[3] == 0x00 && current[4] == 0x00 && current[5] == 0x00 && current[6] == 0x00){
		currentOffset++
		currentAddress := startAddress + currentOffset
		//fmt.Printf("Searching at 0x%x\n", currentAddress)

		err := windows.ReadProcessMemory(0xffffffffffffffff,currentAddress,&current[0], 7, &nBytesRead)
		if err != nil {
			fmt.Println("[-] Error reading from memory")
			break
		}
		if (nBytesRead != 7) {
			fmt.Println("[-] Error reading from memory\n")
			break
		}

		if memcmp(unsafe.Pointer(&egg[0]), unsafe.Pointer(&current[0]), 7) == 0	{
			fmt.Printf("Found at 0x%x\n", currentAddress)
			windows.WriteProcessMemory(0xffffffffffffffff, currentAddress, &replace[0], 7, &nBytesRead)
			break
		}
	}
	fmt.Printf("Ended search at:   0x%x\n", startAddress + currentOffset)
	return
}

func memcmp(dest, src unsafe.Pointer, len uintptr) int {

	cnt := len >> 3
	var i uintptr = 0
	for i = 0; i < cnt; i++ {
		var pdest *uint64 = (*uint64)(unsafe.Pointer(uintptr(dest) + uintptr(8*i)))
		var psrc *uint64 = (*uint64)(unsafe.Pointer(uintptr(src) + uintptr(8*i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}

	left := len & 7
	for i = 0; i < left; i++ {
		var pdest *uint8 = (*uint8)(unsafe.Pointer(uintptr(dest) + uintptr(8*cnt+i)))
		var psrc *uint8 = (*uint8)(unsafe.Pointer(uintptr(src) + uintptr(8*cnt+i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}
	return 0
}

