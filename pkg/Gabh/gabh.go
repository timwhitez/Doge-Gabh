package gabh

import (
	"fmt"
	"github.com/Binject/debug/pe"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func dllExports(dllname string)(*pe.File, error) {
	l := string([]byte{'c',':','/','w','i','n','d','o','w','s','/','s','y','s','t','e','m','3','2','/'})+dllname
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
		if hash(exp.Name) == strings.ToLower(funcnamehash) || hash(strings.ToLower(exp.Name)) == strings.ToLower(funcnamehash) {
			return uint64(phModule) + uint64(exp.VirtualAddress), exp.Name,nil
		}
	}
	return 0,"", fmt.Errorf("could not find function!!! ")
}
