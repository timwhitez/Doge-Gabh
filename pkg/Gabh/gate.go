package gabh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
	"math/rand"
	"sort"
	"strings"
	"time"
	"unsafe"
)

//================RecycledGate================

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetRecyCall(tarApi string, blacklist []string, hash func(string) string) uintptr {
	//init hasher
	hasher := func(a string) string {
		return a
	}
	if hash != nil {
		hasher = hash
	}

	//tolower
	if blacklist != nil && tarApi == "" {
		for i, v := range blacklist {
			blacklist[i] = strings.ToLower(v)
		}
	}
	var Ntd uintptr

	Ntd, _ = inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'}))
	if Ntd == 0 {
		return 0
	}
	ex := GetExport(Ntd)

	rand.Seed(time.Now().UnixNano())
	for i := range ex {
		j := rand.Intn(i + 1)
		ex[i], ex[j] = ex[j], ex[i]
	}

	for i := 0; i < len(ex); i++ {
		exp := ex[i]
		if tarApi != "" {
			if strings.ToLower(hasher(exp.Name)) == strings.ToLower(tarApi) || strings.ToLower(hasher(strings.ToLower(exp.Name))) == strings.ToLower(tarApi) {
				//fmt.Println("Syscall API: " + exp.Name)
				if *(*byte)(unsafe.Pointer(exp.VirtualAddress + 18)) == 0x0f &&
					*(*byte)(unsafe.Pointer(exp.VirtualAddress + 19)) == 0x05 &&
					*(*byte)(unsafe.Pointer(exp.VirtualAddress + 20)) == 0xc3 {
					//fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
					return exp.VirtualAddress + uintptr(18)
				}
			}
		} else {
			if strings.HasPrefix(exp.Name, string([]byte{'N', 't'})) || strings.HasPrefix(exp.Name, string([]byte{'Z', 'w'})) {
				if !contains(blacklist, strings.ToLower(hasher(exp.Name))) && !contains(blacklist, strings.ToLower(hasher(strings.ToLower(exp.Name)))) {
					//fmt.Println("Syscall API: " + exp.Name)
					if *(*byte)(unsafe.Pointer(exp.VirtualAddress + 18)) == 0x0f &&
						*(*byte)(unsafe.Pointer(exp.VirtualAddress + 19)) == 0x05 &&
						*(*byte)(unsafe.Pointer(exp.VirtualAddress + 20)) == 0xc3 {
						//fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
						return exp.VirtualAddress + uintptr(18)
					}
				}
			}
		}
	}
	return 0
}

//ReCycall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func ReCycall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32, err error) {

	errcode = reCycall(callid, syscallA, argh...)

	if errcode != 0 {
		err = fmt.Errorf("err")
	}
	return errcode, err
}

//reCycall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func reCycall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32)

//================RecycledGate================

//================SpfGate================

type SPFG struct {
	Fakename string
	Pointer  uintptr
	Fakeid   uint16
	Realid   uint16
}

func (f *SPFG) Recover() {
	var sysid uint16
	sysid = f.Realid
	windows.WriteProcessMemory(0xffffffffffffffff, f.Pointer+4, (*byte)(unsafe.Pointer(&sysid)), 2, nil)
}

func strin(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

func SpfGate(sysid uint16, none []string) (*SPFG, error) {
	newfcg := new(SPFG)
	apilen := len(apiconst)
	newfcg.Fakeid = sysid

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s) // initialize local pseudorandom generator
	i := 0

	for {
		i++
		idx := r.Intn(len(apiconst))
		for strin(apiconst[idx], none) {
			idx = r.Intn(len(apiconst))
		}

		api64, _, _ := MemFuncPtr(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}), str2sha1(apiconst[idx]), str2sha1)
		if api64 == 0 {
			if i >= apilen {
				break
			}
			continue
		}
		tmpApi := uintptr(api64)

		if *(*byte)(unsafe.Pointer(tmpApi)) == 0x4c &&
			*(*byte)(unsafe.Pointer(tmpApi + 1)) == 0x8b &&
			*(*byte)(unsafe.Pointer(tmpApi + 2)) == 0xd1 &&
			*(*byte)(unsafe.Pointer(tmpApi + 3)) == 0xb8 &&
			*(*byte)(unsafe.Pointer(tmpApi + 6)) == 0x00 &&
			*(*byte)(unsafe.Pointer(tmpApi + 7)) == 0x00 {
			newfcg.Realid = uint16(*(*byte)(unsafe.Pointer(tmpApi + 4))) | uint16(*(*byte)(unsafe.Pointer(tmpApi + 5)))<<8
			windows.WriteProcessMemory(0xffffffffffffffff, tmpApi+4, (*byte)(unsafe.Pointer(&sysid)), 2, nil)
			newfcg.Pointer = tmpApi
			newfcg.Fakename = apiconst[idx]
			return newfcg, nil
		}

		if i >= apilen {
			break
		}
	}
	return newfcg, fmt.Errorf("tmpApi found Err")
}

//================SpfGate================

//================HalosGate================

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
	//get ntdll handle
	Ntd, _ := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'}))
	if Ntd == 0 {
		return 0, nil
	}
	ex := GetExport(Ntd)
	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname) {
			buff := make([]byte, 10)
			if exp.VirtualAddress <= Ntd {
				return 0, nil
			}
			Memcpy(uintptr(unsafe.Pointer(&buff[0])), uintptr(exp.VirtualAddress), 10)
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
			} else {
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

			return getSysIDFromDisk(funcname, hash)
		}
	}
	return getSysIDFromDisk(funcname, hash)
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string, hash func(string) string) (uint16, error) {
	l := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	p, e := pe.Open(l)
	defer p.Close()
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
			} else {
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

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)

//================HalosGate================

//================EggHunter================

//EggCall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func EggCall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
	errcode = eggCall(callid, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func eggCall(callid uint16, argh ...uintptr) (errcode uint32)

//================EggHunter================
