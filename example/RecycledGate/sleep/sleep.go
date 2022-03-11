package main

import (
	"crypto/sha1"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"unsafe"
)



func main() {

	//from https://github.com/Mr-Un1k0d3r/EDRs
	var hookedapi  =[]string{"NtAddBootEntry","NtAdjustPrivilegesToken","NtAlertResumeThread","NtAllocateVirtualMemory","NtAllocateVirtualMemoryEx","NtAlpcConnectPort","NtAreMappedFilesTheSame","NtClose","NtCreateFile","NtCreateKey","NtCreateMutant","NtCreateProcess","NtCreateProcessEx","NtCreateSection","NtCreateThread","NtCreateThreadEx","NtCreateUserProcess","NtDelayExecution","NtDeleteBootEntry","NtDeleteFile","NtDeleteKey","NtDeleteValueKey","NtDeviceIoControlFile","NtDuplicateObject","NtFreeVirtualMemory","NtGdiBitBlt","NtGetContextThread","NtLoadDriver","NtMapUserPhysicalPages","NtMapViewOfSection","NtMapViewOfSectionEx","NtModifyBootEntry","NtOpenCreateFile","NtOpenFile","NtOpenKey","NtOpenKeyEx","NtOpenProcess","NtOpenProcessToken","NtOpenProcessTokenEx","NtOpenThreadToken","NtOpenThreadTokenEx","NtProtectVirtualMemory","NtQueryAttributesFile","NtQueryFullAttributesFile","NtQueryInformationProcess","NtQueryInformationThread","NtQueryInformationTokenTokenUser","NtQuerySystemInformation","NtQuerySystemInformationEx","NtQueryVirtualMemory","NtQueueApcThread","NtQueueApcThreadEx","NtQueueApcThreadEx2","NtReadVirtualMemory","NtRenameKey","NtResumeThread","NtSetContextThread","NtSetInformationFile","NtSetInformationProcess","NtSetInformationProcessCriticalProcess","NtSetInformationThread","NtSetInformationThreadCriticalThread","NtSetInformationThreadHideFromDebugger","NtSetInformationThreadImpersonationToken","NtSetInformationThreadWow64Context","NtSetInformationVirtualMemory","NtSetValueKey","NtSuspendThread","NtSystemDebugControl","NtTerminateProcess","NtTerminateThread","NtUnmapViewOfSection","NtUnmapViewOfSectionEx","NtUserGetAsyncKeyState","NtUserGetClipboardData","NtUserSetWindowsHookEx","NtWriteFile","NtWriteVirtualMemory","ZwAlertResumeThread","ZwAllocateVirtualMemory","ZwAllocateVirtualMemoryEx","ZwAlpcConnectPort","ZwAreMappedFilesTheSame","ZwClose","ZwCreateFile","ZwCreateKey","ZwCreateProcess","ZwCreateProcessEx","ZwCreateSection","ZwCreateThread","ZwCreateThreadEx","ZwCreateUserProcess","ZwDeleteFile","ZwDeleteKey","ZwDeleteValueKey","ZwDeviceIoControlFile","ZwDuplicateObject","ZwFreeVirtualMemory","ZwGetContextThread","ZwLoadDriver","ZwMapUserPhysicalPages","ZwMapViewOfSection","ZwMapViewOfSectionEx","ZwOpenFile","ZwOpenKey","ZwOpenKeyEx","ZwOpenProcess","ZwProtectVirtualMemory","ZwQueryAttributesFile","ZwQueryFullAttributesFile","ZwQueryInformationProcess","ZwQueryInformationThread","ZwQuerySystemInformation","ZwQuerySystemInformationEx","ZwQueryVirtualMemory","ZwQueueApcThread","ZwQueueApcThreadEx","ZwReadVirtualMemory","ZwRenameKey","ZwResumeThread","ZwSetContextThread","ZwSetInformationFile","ZwSetInformationProcess","ZwSetInformationThread","ZwSetValueKey","ZwSuspendThread","ZwTerminateProcess","ZwTerminateThread","ZwUnmapViewOfSection","ZwUnmapViewOfSectionEx","ZwWriteFile","ZwWriteVirtualMemory"}

	var hashhooked []string

	for _,v := range hookedapi{
		hashhooked = append(hashhooked,str2sha1(v))
		//it also support lower case
		//hashhooked = append(hashhooked,str2sha1(strings.ToLower(v)))
	}



	//NtDelayExecution HellsGate
	sleep1, e := gabh.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if e != nil {
		panic(e)
	}

	fmt.Printf("%s: %x\n", "NtDelayExecution Sysid", sleep1)
	times := -(5000 * 10000)

	//hellsgate syscall

	//fmt.Print("Press 'Enter' to continue...")
	//bufio.NewReader(os.Stdin).ReadBytes('\n')



	//hash("NtDelayExecution")
	//strings.ToLower(hash("NtDelayExecution"))
	//hash(strings.ToLower("NtDelayExecution"))
	//strings.ToLower(hash(strings.ToLower("NtDelayExecution")))


	//callAddr := recycled.GetCall("",nil,nil)
	//callAddr := recycled.GetCall(str2sha1("NtDelayExecution"),nil,str2sha1)
	callAddr := gabh.GetRecyCall("",hashhooked,str2sha1)

	r, e1 := gabh.ReCycall(sleep1, callAddr, 0, uintptr(unsafe.Pointer(&times)))
	if e1 != nil{
		fmt.Println(r)
		fmt.Println(e1)
	}

}


func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
