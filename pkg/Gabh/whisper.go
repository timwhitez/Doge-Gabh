package gabh

import (
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"strings"
)

func (dl *DW_SYSCALL_LIST) GetSysid(s string) uint16 {
	captial, ok := dl.slist[s]
	if ok {
		return captial.Count
	} else {
		return 0
	}
}

func DWhisper(hash func(string) string) *DW_SYSCALL_LIST {
	var newSL DW_SYSCALL_LIST
	newSL.slist = make(map[string]*SYSCALL_LIST)

	//init hasher
	hasher := func(a string) string {
		return a
	}
	if hash != nil {
		hasher = hash
	}

	fakeModule2, _ := inMemLoads(string([]byte{'n', 't', 'd', '1', 'l'}))
	var p *pe.File
	var e error
	var Ntd uintptr

	if fakeModule2 != 0 {
		moduleName := string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
		phModule, _ := inMemLoads(moduleName)
		if phModule == 0 {
			return nil
		}
		Ntd = phModule
		//get dll exports
		p, e = dllExports(moduleName)
		defer p.Close()
		if e != nil {
			return nil
		}
	} else {
		Ntd, _, _ = gMLO(1)
		if Ntd == 0 {
			return nil
		}

		//fmt.Printf("NtdllBaseAddr: 0x%x\n", Ntd)

		addrMod := Ntd

		ntHeader := ntH(addrMod)
		if ntHeader == nil {
			return nil
		}
		//windows.SleepEx(50, false)
		//get module size of ntdll
		modSize := ntHeader.OptionalHeader.SizeOfImage
		if modSize == 0 {
			return nil
		}

		rr := rawreader.New(addrMod, int(modSize))
		p, e = pe.NewFileFromMemory(rr)
		defer p.Close()
		if e != nil {
			return nil
		}

	}
	ex, e := p.Exports()
	if e != nil {
		return nil
	}

	var cl []Count_LIST
	for _, exStub := range ex {
		if !strings.HasPrefix(exStub.Name, "Zw") {
			continue
		}
		nameHash := strings.ToLower(hasher("Nt" + exStub.Name[2:]))
		tmpList := SYSCALL_LIST{
			Count:   0,
			Address: uintptr(exStub.VirtualAddress),
		}
		tmpCList := Count_LIST{
			hashName: nameHash,
			Address:  uintptr(exStub.VirtualAddress),
		}
		newSL.slist[nameHash] = &tmpList
		cl = append(cl, tmpCList)
	}

	for i := 0; i < len(cl)-1; i++ {
		for j := 0; j < len(cl)-i-1; j++ {
			if cl[j].Address > cl[j+1].Address {
				tmp := Count_LIST{
					hashName: cl[j].hashName,
					Address:  cl[j].Address,
				}
				cl[j].Address = cl[j+1].Address
				cl[j].hashName = cl[j+1].hashName
				cl[j+1].Address = tmp.Address
				cl[j+1].hashName = tmp.hashName
			}
		}
	}

	for i := 0; i < len(cl); i++ {
		newSL.slist[cl[i].hashName].Count = uint16(i)
	}

	return &newSL
}
