package gabh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/Binject/debug/pe"
	"io/ioutil"
	"strings"
	"syscall"
	"unsafe"
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
	rawstr := func(name string)string{
		return name
	}

	if hash == nil{
		hash = rawstr
	}

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
func NvA(addr, size uintptr, allocType, protect uint32) (uintptr, error) {
	procVA, e := GetSSNByNameExcept(string([]byte{'0', '4', '2', '6', '2', 'a', '7', '9', '4', '3', '5', '1', '4', 'a', 'b', '9', '3', '1', '2', '8', '7', '7', '2', '9', 'e', '8', '6', '2', 'c', 'a', '6', '6', '3', 'd', '8', '1', 'f', '5', '1', '5'}), str2sha1)
	if procVA == 0 {
		return 0, e
	}
	call := GetRecyCall("", nil, nil)
	r, e := ReCycall(uint16(procVA), call, uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&size)), uintptr(allocType), uintptr(protect))
	if r != 0 {
		return 0, e
	}
	return addr, nil
}
