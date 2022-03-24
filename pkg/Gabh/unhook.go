package gabh

import (
	"bytes"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"os/exec"
	"syscall"
	"unsafe"
)

func FullUnhook(DLLname []string) error {
	for _, d := range DLLname {
		dll, err := ioutil.ReadFile(d)
		if err != nil {
			return err
		}
		file, error1 := pe.Open(d)
		if error1 != nil {
			return error1
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
	}
	return nil
}

func CMDUnhook(DLLname []string) error {
	for _, d := range DLLname {
		cmd := exec.Command("cmd.exe", "/c", "type "+d)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		mdbyte, e := cmd.Output()
		if e != nil {
			return e
		}
		file, error1 := pe.NewFile(bytes.NewReader(mdbyte))
		if error1 != nil {
			return error1
		}
		x := file.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
		bytes := mdbyte[x.Offset:x.Size]
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
	}
	return nil
}

func npvm(processHandle uintptr, baseAddress, regionSize *uintptr, NewProtect uintptr, oldprotect *uintptr) uint32 {
	//NtProtectVirtualMemory
	sysid, _ := DiskHgate("646bd5afa7b482fdd90fb8f2eefe1301a867d7b9", str2sha1)
	if sysid == 0 {
		return 0
	}
	errcode := hgSyscall(
		sysid,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)

	return errcode
}
