package gabh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Binject/debug/pe"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func dllExports(dllname string)(*pe.File, error) {
	l := string([]byte{'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\'})+dllname
	p, e := pe.Open(l)
	if e != nil {
		return nil, e
	}
	return p, nil
}

func UTF16PtrFromString(s string) (*uint16, error) {
	a, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return &a[0], nil
}

func UTF16FromString(s string) ([]uint16, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return nil, syscall.EINVAL
		}
	}
	return utf16.Encode([]rune(s + "\x00")), nil
}

//GetFuncPtr returns a pointer to the function (Virtual Address)
func GetFuncPtr(moduleName string , funcnamehash string,hash func(string)string) (uint64, string, error) {
	//Get dll module BaseAddr
	k32 := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e','l','3','2'	}))
	GMEx := k32.NewProc(string([]byte{'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','E','x','W' }))
	var phModule uintptr
	cname, _ := UTF16PtrFromString(moduleName)
	r1,_,err := GMEx.Call(0,uintptr(unsafe.Pointer(cname)),uintptr(unsafe.Pointer(&phModule)))
	if r1 != 1 || phModule == 0{
		syscall.LoadLibrary(moduleName)
		r1,_,err = GMEx.Call(0,uintptr(unsafe.Pointer(cname)),uintptr(unsafe.Pointer(&phModule)))
		if r1 != 1 || phModule == 0 {
			return 0, "", err
		}
	}
	//get dll exports
	pef,err := dllExports(moduleName)
	if err != nil{
		return 0,"",err
	}
	ex,err := pef.Exports()
	if err != nil{
		return 0,"",err
	}

	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcnamehash) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcnamehash) {
			return uint64(phModule) + uint64(exp.VirtualAddress), exp.Name,nil
		}
	}
	return 0,"", fmt.Errorf("could not find function!!! ")
}

//NtdllHgate takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func NtdllHgate(funcname string,hash func(string)string) (uint16, error) {
	return getSysIDFromDisk(funcname, 0, false,hash)
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string, ord uint32, useOrd bool,hash func(string)string) (uint16, error) {
	l := string([]byte{'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l'})
	p, e := pe.Open(l)
	if e != nil {
		return 0, e
	}
	ex, e := p.Exports()
	for _, exp := range ex {
		if (useOrd && exp.Ordinal == ord) || // many bothans died for this feature
			strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname)  {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			return sysIDFromRawBytes(buff)
		}
	}
	return 0, errors.New("Could not find sID")
}

//rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

//sysIDFromRawBytes takes a byte slice and determines if there is a sysID in the expected location. Returns a MayBeHookedError if the signature does not match.
func sysIDFromRawBytes(b []byte) (uint16, error) {
	return binary.LittleEndian.Uint16(b[4:8]), nil
}

//HgSyscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func HgSyscall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
	errcode = hgSyscall(callid, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)

