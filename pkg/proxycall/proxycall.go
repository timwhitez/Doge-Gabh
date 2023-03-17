package proxycall

import (
	"reflect"
	"syscall"
	"unsafe"
)

type ProxyArgs struct {
	Addr    uintptr
	ArgsLen uintptr
	Args1   uintptr
	Args2   uintptr
	Args3   uintptr
	Args4   uintptr
	Args5   uintptr
	Args6   uintptr
	Args7   uintptr
	Args8   uintptr
	Args9   uintptr
	Args10  uintptr
}

func ProxyCall(Addr uintptr, Args ...uintptr) {
	Args0 := proxySetargs(Addr, Args...)
	ProxyCallWithStruct(Args0)
}

func ProxyCallWithStruct(Args0 uintptr) {
	tag := []byte{0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0}
	addr := reflect.ValueOf(proxyTag).Pointer()
	//fmt.Printf("Function Addr: 0x%x\n", addr)
	BaseAddr := addr
	addr = findTag(tag, BaseAddr)
	//fmt.Printf("EggTag Addr: 0x%x\n", addr)

	pTpAllocWork := syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k'}))
	pTpPostWork := syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k'}))
	pTpReleaseWork := syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k'}))

	WorkReturn := uintptr(0)

	pTpAllocWork.Call(uintptr(unsafe.Pointer(&WorkReturn)), addr, Args0, 0)
	pTpPostWork.Call(WorkReturn)
	pTpReleaseWork.Call(WorkReturn)

	syscall.WaitForSingleObject(0xffffffffffffffff, 0x100)
}

func proxySetargs(Addr uintptr, Args ...uintptr) uintptr {
	newArgs := ProxyArgs{}
	newArgs.Addr = Addr
	if Args == nil {
		newArgs.ArgsLen = 0
		return uintptr(unsafe.Pointer(&newArgs))
	}
	if len(Args) > 10 {
		panic("Too much args")
	}
	len0 := len(Args)
	newArgs.ArgsLen = uintptr(len0)

	//使用反射遍历赋值
	pArgs := &newArgs
	value := reflect.ValueOf(pArgs).Elem()
	for i := 0; i < len0; i++ {
		if value.Field(i).CanSet() {
			ptr := unsafe.Pointer(value.Field(i + 2).UnsafeAddr())
			*(*uintptr)(ptr) = Args[i]
		}
	}
	return uintptr(unsafe.Pointer(&newArgs))
}

func findTag(egg []byte, startAddress uintptr) uintptr {
	var currentOffset = uintptr(0)
	currentAddress := startAddress
	for {
		currentOffset++
		currentAddress = startAddress + currentOffset
		if memcmp(unsafe.Pointer(&egg[0]), unsafe.Pointer(currentAddress), 7) == 0 {
			return currentAddress + 7
		}
	}
}

func memcmp(dest, src unsafe.Pointer, len uintptr) int {
	cnt := len >> 3
	var i uintptr = 0
	for i = 0; i < cnt; i++ {
		var pdest *uint64 = (*uint64)(unsafe.Pointer(uintptr(dest) + uintptr(8*i)))
		var psrc *uint64 = (*uint64)(unsafe.Pointer(uintptr(src) + uintptr(8*i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}

	left := len & 7
	for i = 0; i < left; i++ {
		var pdest *uint8 = (*uint8)(unsafe.Pointer(uintptr(dest) + uintptr(8*cnt+i)))
		var psrc *uint8 = (*uint8)(unsafe.Pointer(uintptr(src) + uintptr(8*cnt+i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}
	return 0
}

func proxyTag() {
	proxyC()
}

func proxyC()
