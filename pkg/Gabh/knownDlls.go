package gabh

import (
	"fmt"
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

func kdllload(DLLname string) (uintptr, uintptr, uintptr) {
	ntPathW := "\\" + string([]byte{'K', 'n', 'o', 'w', 'n', 'D', 'l', 'l', 's'}) + "\\" + DLLname
	ntPath, _ := windows.NewNTUnicodeString(ntPathW)

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Attributes = 0x00000040
	objectAttributes.ObjectName = ntPath
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))

	//NtOpenSection
	NOS_ptr, _, e := MemFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "bdbea867842342052be06c259d49d535626c924b", str2sha1)
	if e != nil {
		//fmt.Println(e)
		return 0, 0, 0
	}
	var hKnownDll uintptr

	r, _, _ := syscall.Syscall(uintptr(NOS_ptr), 3, uintptr(unsafe.Pointer(&hKnownDll)), uintptr(0x0004), uintptr(unsafe.Pointer(&objectAttributes)))
	if r != 0 {

		return 0, 0, 0
	}

	var pCleanNtdll uintptr
	var sztViewSize uintptr

	//zwmapviewofsection = da39da04447a22b747ac8e86b4773bbd6ea96f9b
	ZMVS_ptr, _, _ := MemFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "da39da04447a22b747ac8e86b4773bbd6ea96f9b", str2sha1)

	//status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	syscall.Syscall12(uintptr(ZMVS_ptr), 10, hKnownDll, uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&pCleanNtdll)), 0, 0, 0, uintptr(unsafe.Pointer(&sztViewSize)), 1, 0, syscall.PAGE_READONLY, 0, 0)

	return pCleanNtdll, sztViewSize, hKnownDll
}

func kdllunload(pCleanNtdll uintptr, hKnownDll uintptr) {

	//NtUnmapViewOfSection = bab64ab3009f237d28c9dc1ed3707190336fae77
	ZMVS_ptr, _, _ := MemFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "bab64ab3009f237d28c9dc1ed3707190336fae77", str2sha1)

	//status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	syscall.Syscall(uintptr(ZMVS_ptr), 2, uintptr(0xffffffffffffffff), pCleanNtdll, 0)

	syscall.CloseHandle(syscall.Handle(hKnownDll))

}

func KDllunhook(DLLname []string) error {
	for _, d := range DLLname {
		if strings.Contains(d, "\\") {
			d = strings.Split(d, "\\")[len(strings.Split(d, "\\"))-1]
		}
		if strings.Contains(d, "/") {
			d = strings.Split(d, "/")[len(strings.Split(d, "/"))-1]
		}
		addrMod, modSize, khndl := kdllload(d)
		if addrMod == 0 || modSize == 0 {
			return fmt.Errorf("Get KnownDll error ")
		}
		rr := rawreader.New(addrMod, int(modSize))
		file, e := pe.NewFileFromMemory(rr)
		if e != nil {
			return e
		}
		dll, err := file.Bytes()
		if err != nil {
			return err
		}
		x := file.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
		bytes := dll[x.Offset:x.Size]
		loaddll, error2 := windows.LoadDLL(d)
		if error2 != nil {
			return error2
		}
		handle := loaddll.Handle
		dllBase := uintptr(handle)
		dllOffset := uint(dllBase) + uint(x.VirtualAddress)
		var oldfartcodeperms uintptr
		regionsize := uintptr(len(bytes))
		handlez := uintptr(0xffffffffffffffff)
		runfunc := npvm(
			handlez,
			(*uintptr)(unsafe.Pointer(&dllOffset)),
			&regionsize,
			syscall.PAGE_EXECUTE_READWRITE,
			&oldfartcodeperms,
		)
		if runfunc != 0 {
			panic(runfunc)
		}

		for i := 0; i < len(bytes); i++ {
			loc := uintptr(dllOffset + uint(i))
			mem := (*[1]byte)(unsafe.Pointer(loc))
			(*mem)[0] = bytes[i]
		}

		runfunc = npvm(
			handlez,
			(*uintptr)(unsafe.Pointer(&dllOffset)),
			&regionsize,
			oldfartcodeperms,
			&oldfartcodeperms,
		)
		if runfunc != 0 {
			panic(runfunc)
		}
		file.Close()
		kdllunload(addrMod, khndl)
	}
	return nil
}
