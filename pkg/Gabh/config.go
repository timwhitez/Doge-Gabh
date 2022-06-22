package gabh

import (
	"crypto/sha1"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

type (
	DWORD     uint32
	ULONGLONG uint64
	WORD      uint16
	BYTE      uint8
	LONG      uint32
)

const (
	MEM_COMMIT  = 0x001000
	MEM_RESERVE = 0x002000
	IDX         = 32
)

type unNtd struct {
	pModule uintptr
	size    uintptr
}

// Library - describes a loaded library
type Library struct {
	Name        string
	BaseAddress uintptr
	Exports     map[string]uint64
}

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
)

type _IMAGE_FILE_HEADER struct {
	Machine              WORD
	NumberOfSections     WORD
	TimeDateStamp        DWORD
	PointerToSymbolTable DWORD
	NumberOfSymbols      DWORD
	SizeOfOptionalHeader WORD
	Characteristics      WORD
}

type IMAGE_FILE_HEADER _IMAGE_FILE_HEADER

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}
type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_NT_HEADERS64 struct {
	Signature      DWORD
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
type IMAGE_NT_HEADERS64 _IMAGE_NT_HEADERS64
type IMAGE_NT_HEADERS IMAGE_NT_HEADERS64
type _IMAGE_DOS_HEADER struct { // DOS .EXE header
	E_magic    WORD     // Magic number
	E_cblp     WORD     // Bytes on last page of file
	E_cp       WORD     // Pages in file
	E_crlc     WORD     // Relocations
	E_cparhdr  WORD     // Size of header in paragraphs
	E_minalloc WORD     // Minimum extra paragraphs needed
	E_maxalloc WORD     // Maximum extra paragraphs needed
	E_ss       WORD     // Initial (relative) SS value
	E_sp       WORD     // Initial SP value
	E_csum     WORD     // Checksum
	E_ip       WORD     // Initial IP value
	E_cs       WORD     // Initial (relative) CS value
	E_lfarlc   WORD     // File address of relocation table
	E_ovno     WORD     // Overlay number
	E_res      [4]WORD  // Reserved words
	E_oemid    WORD     // OEM identifier (for E_oeminfo)
	E_oeminfo  WORD     // OEM information; E_oemid specific
	E_res2     [10]WORD // Reserved words
	E_lfanew   LONG     // File address of new exe header
}

type IMAGE_DOS_HEADER _IMAGE_DOS_HEADER

type SYSCALL_LIST struct {
	Count   uint16
	Address uintptr
}

type Count_LIST struct {
	hashName string
	Address  uintptr
}

type DW_SYSCALL_LIST struct {
	slist map[string]*SYSCALL_LIST
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

// Export - describes a single export entry
type Export struct {
	Name           string
	VirtualAddress uintptr
}
type imageExportDir struct {
	_, _                  uint32
	_, _                  uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func GetExport(pModuleBase uintptr) []Export {
	var exports []Export
	var pImageNtHeaders = ntH(pModuleBase)
	//IMAGE_NT_SIGNATURE
	if pImageNtHeaders.Signature != 0x00004550 {
		return nil
	}
	var pImageExportDirectory *imageExportDir

	pImageExportDirectory = ((*imageExportDir)(unsafe.Pointer(uintptr(pModuleBase + uintptr(pImageNtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)))))

	pdwAddressOfFunctions := pModuleBase + uintptr(pImageExportDirectory.AddressOfFunctions)
	pdwAddressOfNames := pModuleBase + uintptr(pImageExportDirectory.AddressOfNames)

	pwAddressOfNameOrdinales := pModuleBase + uintptr(pImageExportDirectory.AddressOfNameOrdinals)

	for cx := uintptr(0); cx < uintptr((pImageExportDirectory).NumberOfNames); cx++ {
		var export Export
		pczFunctionName := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfNames + cx*4)))
		pFunctionAddress := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfFunctions + uintptr(*(*uint16)(unsafe.Pointer(pwAddressOfNameOrdinales + cx*2)))*4)))
		export.Name = windows.BytePtrToString((*byte)(unsafe.Pointer(pczFunctionName)))
		export.VirtualAddress = uintptr(pFunctionAddress)
		exports = append(exports, export)
	}

	return exports
}

func Memcpy(dst, src, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*uint8)(unsafe.Pointer(dst + i)) = *(*uint8)(unsafe.Pointer(src + i))
	}
}
