package gabh

import (
	"fmt"
	"strings"
	"unsafe"
)

type IMAGE_RUNTIME_FUNCTION_ENTRY struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnwindInfoAddress uint32
}

func GetSSNByNameExcept(fname string, hash func(string) string) (uintptr, error) {
	rawstr := func(name string)string{
		return name
	}

	if hash == nil{
		hash = rawstr
	}

	Ntd, _ := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'}))
	if Ntd == 0 {
		return 0, nil
	}
	ntHeader := ntH(Ntd)
	if ntHeader == nil {
		return 0, fmt.Errorf(string([]byte{'g', 'e', 't', ' ', 'n', 't', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'e', 'r', 'r'}))
	}

	ex := GetExport(Ntd)

	rva := ntHeader.OptionalHeader.DataDirectory[3].VirtualAddress
	rtf := getrtf(Ntd, uintptr(rva), 0)
	ssn := uintptr(0)
	for i := 0; getrtf(Ntd, uintptr(rva), uintptr(i)).BeginAddress != 0; i++ {
		rtf = getrtf(Ntd, uintptr(rva), uintptr(i))
		for _, exp := range ex {
			if uint32(exp.VirtualAddress-Ntd) == rtf.BeginAddress {
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
