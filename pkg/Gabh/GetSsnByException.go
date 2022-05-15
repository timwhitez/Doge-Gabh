package gabh

import (
	"fmt"
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"strings"
	"unsafe"
)

type IMAGE_RUNTIME_FUNCTION_ENTRY struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnwindInfoAddress uint32
}

func GetSSNByNameExcept(fname string, hash func(string) string) (uintptr, error) {
	Ntd, _, _ := gMLO(1)
	ntHeader := ntH(Ntd)
	if ntHeader == nil {
		return 0, fmt.Errorf(string([]byte{'g', 'e', 't', ' ', 'n', 't', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'e', 'r', 'r'}))
	}
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return 0, fmt.Errorf(string([]byte{'g', 'e', 't', ' ', 'm', 'o', 'd', 'u', 'l', 'e', ' ', 's', 'i', 'z', 'e', ' ', 'e', 'r', 'r'}))
	}
	//fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	rr := rawreader.New(Ntd, int(modSize))
	p, e := pe.NewFileFromMemory(rr)
	defer p.Close()
	if e != nil {
		return 0, e
	}

	ex, e := p.Exports()
	if e != nil {
		return 0, e
	}

	rva := p.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress
	rtf := getrtf(Ntd, uintptr(rva), 0)
	ssn := uintptr(0)
	for i := 0; getrtf(Ntd, uintptr(rva), uintptr(i)).BeginAddress != 0; i++ {
		rtf = getrtf(Ntd, uintptr(rva), uintptr(i))
		for _, exp := range ex {
			if exp.VirtualAddress == rtf.BeginAddress {
				if strings.ToLower(hash(exp.Name)) == strings.ToLower(fname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(fname) {
					return ssn, nil
				}
				if strings.Contains(exp.Name, string([]byte{'Z', 'w'})) {
					ssn++
				}
			}
		}

	}
	return 0, fmt.Errorf(string([]byte{'d', 'i', 'd', 'n', '\'', 't', ' ', 'f', 'i', 'n', 'd', ' ', 'i', 't'}))
}

func getrtf(dllBase uintptr, rva uintptr, i uintptr) *IMAGE_RUNTIME_FUNCTION_ENTRY {
	return (*IMAGE_RUNTIME_FUNCTION_ENTRY)(unsafe.Pointer(dllBase + rva + i))
}
