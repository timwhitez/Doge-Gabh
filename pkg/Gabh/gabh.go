package gabh

import (
	"fmt"
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
)

//MemFuncPtr returns a pointer to the function (Virtual Address)
func MemFuncPtr(moduleName string, funcnamehash string, hash func(string) string) (uint64, string, error) {
	fakeModule1, _ := inMemLoads("kern3l32")
	fakeModule2, _ := inMemLoads("ntd1l")
	var phModule uintptr

	if fakeModule1 != 0 || fakeModule2 != 0 {
		return DiskFuncPtr(moduleName, funcnamehash, hash)
	} else {
		//Get dll module BaseAddr
		phModule, _ = inMemLoads(moduleName)
	}

	if phModule == 0 {
		phndl, _ := syscall.LoadLibrary(moduleName)
		phModule = uintptr(phndl)
		if phModule == 0 {
			return 0, "", fmt.Errorf("Can't Load %s" + moduleName)
		}
	}
	//get dll exports
	pef, err := dllMemExports(moduleName)
	defer pef.Close()
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
	phModule, _ := inMemLoads(moduleName)

	if phModule == 0 {
		syscall.LoadLibrary(moduleName)
		phModule, _ = inMemLoads(moduleName)
		if phModule == 0 {
			return 0, "", fmt.Errorf("Can't Load %s" + moduleName)
		}
	}
	//get dll exports
	pef, err := dllExports(moduleName)
	defer pef.Close()
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
	r1, r2 := inMemLoads(dllname)
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
func inMemLoads(modulename string) (uintptr, uintptr) {
	s, si, p := gMLO(0)
	start := p
	i := 1
	if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
		return s, si
	}
	for {
		s, si, p = gMLO(i)
		if p != "" {
			if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
				return s, si
			}
		}
		if p == start {
			break
		}
		i++
	}
	return 0, 0
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

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)
