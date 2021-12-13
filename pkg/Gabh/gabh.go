package gabh

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Binject/debug/pe"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
)

type unNtd struct {
	pModule uintptr
	size uintptr
}


func ReMapNtdll()(*unNtd, error){
	var uNTD = &unNtd{}

	//ntcreatefile = ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5
	NCF_ptr,_,e := GetFuncPtr(string([]byte{'n','t','d','l','l','.','d','l','l'}),"ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5",str2sha1)
	if e != nil{
		fmt.Println(e)
		return uNTD,fmt.Errorf("NtCreateFile Err")
	}


	var hNtdllfile uintptr

	ntPathW := "\\??\\C:\\Windows\\System32\\"+string([]byte{'n','t','d','l','l','.','d','l','l'})
	ntPath , _ := windows.NewNTUnicodeString(ntPathW)

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	objectAttributes.ObjectName = ntPath

	var ioStatusBlock windows.IO_STATUS_BLOCK

	//status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	syscall.Syscall12(uintptr(NCF_ptr),11,uintptr(unsafe.Pointer(&hNtdllfile)),uintptr(0x80|syscall.GENERIC_READ|syscall.SYNCHRONIZE),uintptr(unsafe.Pointer(&objectAttributes)),uintptr(unsafe.Pointer(&ioStatusBlock)),0,0,syscall.FILE_SHARE_READ,uintptr(0x00000001),uintptr(0x00000040|0x00000020),0,0,0)

	//ntcreatesection = 747d342b80e4c1c9d4d3dcb4ee2da24dcce27801
	NCS_ptr,_,_ := GetFuncPtr(string([]byte{'n','t','d','l','l','.','d','l','l'}),"747d342b80e4c1c9d4d3dcb4ee2da24dcce27801",str2sha1)

	var handleNtdllSection uintptr
	//status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	syscall.Syscall9(uintptr(NCS_ptr),7, uintptr(unsafe.Pointer(&handleNtdllSection)),uintptr(0x000F0000|0x4|0x1),0,0,syscall.PAGE_READONLY,uintptr(0x1000000),hNtdllfile,0,0)


	//zwmapviewofsection = da39da04447a22b747ac8e86b4773bbd6ea96f9b
	ZMVS_ptr,_,_ := GetFuncPtr(string([]byte{'n','t','d','l','l','.','d','l','l'}),"da39da04447a22b747ac8e86b4773bbd6ea96f9b",str2sha1)

	var unhookedBaseAddress uintptr
	var size uintptr
	//status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	syscall.Syscall12(uintptr(ZMVS_ptr),10,handleNtdllSection,uintptr(0xffffffffffffffff),uintptr(unsafe.Pointer(&unhookedBaseAddress)),0,0,0,uintptr(unsafe.Pointer(&size)),1,0,syscall.PAGE_READONLY,0,0)

	uNTD.pModule = unhookedBaseAddress
	uNTD.size = size
	return uNTD,nil
}

//returns a pointer to the function (Virtual Address)
func (u *unNtd) GetFuncUnhook(funcnamehash string,hash func(string)string) (uint64,string, error) {
	rr := rawreader.New(u.pModule, int(u.size))
	p,e := pe.NewFileFromMemory(rr)
	if e != nil{
		return 0,"", e
	}

	ex,e := p.Exports()
	if e != nil{
		return 0,"", e
	}

	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcnamehash) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcnamehash) {
			return uint64(u.pModule) + uint64(exp.VirtualAddress),exp.Name,nil
		}
	}
	return 0,"", fmt.Errorf("could not find function!!! ")
}





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
	return getSysIDFromDisk(funcname, hash)
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string,hash func(string)string) (uint16, error) {
	l := string([]byte{'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l'})
	p, e := pe.Open(l)
	if e != nil {
		return 0, e
	}
	ex, e := p.Exports()
	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname){
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

func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)

