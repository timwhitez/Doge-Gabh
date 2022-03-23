package main

import (
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

//from https://github.com/Mr-Un1k0d3r/EDRs
var hookedapi = []string{"NtAddBootEntry", "NtAdjustPrivilegesToken", "NtAlertResumeThread", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx", "NtAlpcConnectPort", "NtAreMappedFilesTheSame", "NtClose", "NtCreateFile", "NtCreateKey", "NtCreateMutant", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDelayExecution", "NtDeleteBootEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteValueKey", "NtDeviceIoControlFile", "NtDuplicateObject", "NtFreeVirtualMemory", "NtGdiBitBlt", "NtGetContextThread", "NtLoadDriver", "NtMapUserPhysicalPages", "NtMapViewOfSection", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtOpenCreateFile", "NtOpenFile", "NtOpenKey", "NtOpenKeyEx", "NtOpenProcess", "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtOpenThreadToken", "NtOpenThreadTokenEx", "NtProtectVirtualMemory", "NtQueryAttributesFile", "NtQueryFullAttributesFile", "NtQueryInformationProcess", "NtQueryInformationThread", "NtQueryInformationTokenTokenUser", "NtQuerySystemInformation", "NtQuerySystemInformationEx", "NtQueryVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtQueueApcThreadEx2", "NtReadVirtualMemory", "NtRenameKey", "NtResumeThread", "NtSetContextThread", "NtSetInformationFile", "NtSetInformationProcess", "NtSetInformationProcessCriticalProcess", "NtSetInformationThread", "NtSetInformationThreadCriticalThread", "NtSetInformationThreadHideFromDebugger", "NtSetInformationThreadImpersonationToken", "NtSetInformationThreadWow64Context", "NtSetInformationVirtualMemory", "NtSetValueKey", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateProcess", "NtTerminateThread", "NtUnmapViewOfSection", "NtUnmapViewOfSectionEx", "NtUserGetAsyncKeyState", "NtUserGetClipboardData", "NtUserSetWindowsHookEx", "NtWriteFile", "NtWriteVirtualMemory", "ZwAlertResumeThread", "ZwAllocateVirtualMemory", "ZwAllocateVirtualMemoryEx", "ZwAlpcConnectPort", "ZwAreMappedFilesTheSame", "ZwClose", "ZwCreateFile", "ZwCreateKey", "ZwCreateProcess", "ZwCreateProcessEx", "ZwCreateSection", "ZwCreateThread", "ZwCreateThreadEx", "ZwCreateUserProcess", "ZwDeleteFile", "ZwDeleteKey", "ZwDeleteValueKey", "ZwDeviceIoControlFile", "ZwDuplicateObject", "ZwFreeVirtualMemory", "ZwGetContextThread", "ZwLoadDriver", "ZwMapUserPhysicalPages", "ZwMapViewOfSection", "ZwMapViewOfSectionEx", "ZwOpenFile", "ZwOpenKey", "ZwOpenKeyEx", "ZwOpenProcess", "ZwProtectVirtualMemory", "ZwQueryAttributesFile", "ZwQueryFullAttributesFile", "ZwQueryInformationProcess", "ZwQueryInformationThread", "ZwQuerySystemInformation", "ZwQuerySystemInformationEx", "ZwQueryVirtualMemory", "ZwQueueApcThread", "ZwQueueApcThreadEx", "ZwReadVirtualMemory", "ZwRenameKey", "ZwResumeThread", "ZwSetContextThread", "ZwSetInformationFile", "ZwSetInformationProcess", "ZwSetInformationThread", "ZwSetValueKey", "ZwSuspendThread", "ZwTerminateProcess", "ZwTerminateThread", "ZwUnmapViewOfSection", "ZwUnmapViewOfSectionEx", "ZwWriteFile", "ZwWriteVirtualMemory"}
var hashhooked []string

var SW2_SEED = 0xA7A0175C

func SW2_ROR8(v uint32) uint32 {
	return v>>8 | v<<24
}
func SW2_HashSyscall(fname string) string {
	fn, _ := syscall.BytePtrFromString(fname)
	FunctionName := uintptr(unsafe.Pointer(fn))
	var Hash = uint32(SW2_SEED)
	for j := 0; j < len(fname); j++ {
		i := uintptr(j)
		PartialName := *(*uint16)(unsafe.Pointer(FunctionName + i))
		Hash ^= uint32(PartialName) + SW2_ROR8(Hash)
	}
	return fmt.Sprintf("%x", Hash)
}

func main() {
	// 初始化DW_SYSCALL_LIST ,SW2_HashSyscall可以换成其他加密函数
	var newWhisper = gabh.DWhisper(SW2_HashSyscall)
	if newWhisper == nil {
		return
	}

	for _, v := range hookedapi {
		hashhooked = append(hashhooked, SW2_HashSyscall(v))
	}

	//SW2_HashSyscall("NtDelayExecution")=4942059d
	sysid := newWhisper.GetSysid("4942059d")
	if sysid == 0 {
		return
	}

	fmt.Printf("NtDelayExecution sysid: 0x%x\n", sysid)
	var ti = -(5000 * 10000)

	//获取syscall;ret的地址
	callAddr := gabh.GetRecyCall("", hashhooked, SW2_HashSyscall)
	fmt.Printf("Syscall;ret Address: 0x%x\n", callAddr)

	//Call
	r, e1 := gabh.ReCycall(sysid, callAddr, uintptr(0), uintptr(unsafe.Pointer(&ti)))
	if e1 != nil {
		fmt.Printf("0x%x\n", r)
		fmt.Println(e1)
	}

}
