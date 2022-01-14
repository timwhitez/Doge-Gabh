//based on https://golang.org/src/runtime/sys_windows_amd64.s
#define maxargs 16
//func Syscall(callid uint16, argh ...uintptr) (uint32, error)
TEXT ·hgSyscall(SB), $0-56
	NOP
	XORQ AX,AX
	NOP
	MOVW callid+0(FP), AX
	NOP
	PUSHQ CX
	NOP
	//put variadic size into CX
	MOVQ argh_len+16(FP),CX
	NOP
	//put variadic pointer into SI
	MOVQ argh_base+8(FP),SI
	NOP
	// SetLastError(0).
	MOVQ	0x30(GS), DI
	NOP
	MOVL	$0, 0x68(DI)
	NOP
	SUBQ	$(maxargs*8), SP	// room for args
	NOP
	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	NOP
	JLE	loadregs
	// Check we have enough room for args.
	CMPL	CX, $maxargs
	NOP
	JLE	2(PC)
	INT	$3			// not enough room -> crash
	NOP
	// Copy args to the stack.
	MOVQ	SP, DI
	NOP
	CLD
	NOP
	REP; MOVSQ
	NOP
	MOVQ	SP, SI
	NOP
	//move the stack pointer????? why????
	SUBQ	$8, SP
	NOP
loadregs:
	// Load first 4 args into correspondent registers.
	//交换位置免杀
	MOVQ	8(SI), DX
	NOP

	MOVQ	24(SI), R9
	NOP

	MOVQ	0(SI), CX
	NOP

	MOVQ	16(SI), R8
	NOP
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
	MOVQ	CX, X0
	NOP
	MOVQ	DX, X1
	NOP
	MOVQ	R8, X2
	NOP
	MOVQ	R9, X3
	NOP
	//MOVW callid+0(FP), AX
	MOVQ CX, R10
	NOP
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET


//func getModuleLoadedOrder(i int) (start uintptr, size uintptr)
TEXT ·getMLO(SB), $0-32
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	NOP
	//PEB->LDR
	MOVQ 0x18(AX),AX
	NOP

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX
	NOP

	//loop things
	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	NOP
	JE endloop
	NOP
	//Flink (get next element)
	MOVQ (AX),AX
	NOP
	INCQ R10
	JMP startloop
endloop:
	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)

	MOVQ 0x30(AX),CX
	NOP
	MOVQ CX, size+16(FP)
	NOP


	MOVQ 0x20(AX),CX
	NOP
    MOVQ CX, start+8(FP)
    NOP


	MOVQ AX,CX
	NOP
	ADDQ $0x38,CX
	NOP
	MOVQ CX, modulepath+24(FP)
	//SYSCALL
	RET

