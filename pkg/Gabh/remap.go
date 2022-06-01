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

func ReMapNtdll() (*unNtd, error) {
	var uNTD = &unNtd{}

	//ntcreatefile = ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5
	NCF_ptr, _, e := DiskFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5", str2sha1)
	if e != nil {
		//fmt.Println(e)
		return uNTD, fmt.Errorf("NtCreateFile Err")
	}

	var hNtdllfile uintptr

	ntPathW := "\\??\\C:\\Windows\\System32\\" + string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	ntPath, _ := windows.NewNTUnicodeString(ntPathW)

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	objectAttributes.ObjectName = ntPath
	objectAttributes.Attributes = 0x00000040

	var ioStatusBlock windows.IO_STATUS_BLOCK

	//status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	syscall.Syscall12(uintptr(NCF_ptr), 11, uintptr(unsafe.Pointer(&hNtdllfile)), uintptr(0x80|syscall.GENERIC_READ|syscall.SYNCHRONIZE), uintptr(unsafe.Pointer(&objectAttributes)), uintptr(unsafe.Pointer(&ioStatusBlock)), 0, 0, syscall.FILE_SHARE_READ, uintptr(0x00000001), uintptr(0x00000040|0x00000020), 0, 0, 0)

	//ntcreatesection = 747d342b80e4c1c9d4d3dcb4ee2da24dcce27801
	NCS_ptr, _, _ := DiskFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "747d342b80e4c1c9d4d3dcb4ee2da24dcce27801", str2sha1)

	var handleNtdllSection uintptr
	//status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	syscall.Syscall9(uintptr(NCS_ptr), 7, uintptr(unsafe.Pointer(&handleNtdllSection)), uintptr(0x000F0000|0x4|0x1), 0, 0, syscall.PAGE_READONLY, uintptr(0x1000000), hNtdllfile, 0, 0)

	//zwmapviewofsection = da39da04447a22b747ac8e86b4773bbd6ea96f9b
	ZMVS_ptr, _, _ := DiskFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "da39da04447a22b747ac8e86b4773bbd6ea96f9b", str2sha1)

	var unhookedBaseAddress uintptr
	var size uintptr
	//status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	syscall.Syscall12(uintptr(ZMVS_ptr), 10, handleNtdllSection, uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&unhookedBaseAddress)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 1, 0, syscall.PAGE_READONLY, 0, 0)

	uNTD.pModule = unhookedBaseAddress
	uNTD.size = size
	return uNTD, nil

}

//returns a pointer to the function (Virtual Address)
func (u *unNtd) GetFuncUnhook(funcnamehash string, hash func(string) string) (uint64, string, error) {
	rr := rawreader.New(u.pModule, int(u.size))
	p, e := pe.NewFileFromMemory(rr)
	defer p.Close()
	if e != nil {
		return 0, "", e
	}

	ex, e := p.Exports()
	if e != nil {
		return 0, "", e
	}

	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcnamehash) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcnamehash) {
			return uint64(u.pModule) + uint64(exp.VirtualAddress), exp.Name, nil
		}
	}
	return 0, "", fmt.Errorf("could not find function!!! ")
}
