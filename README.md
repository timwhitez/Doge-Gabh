# Doge-Gabh

![Doge-Gabh](https://socialify.git.ci/timwhitez/Doge-Gabh/image?description=1&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars1.githubusercontent.com%2Fu%2F36320909&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)

- 🐸Frog For Automatic Scan

- 🐶Doge For Defense Evasion & Offensive Security


## 项目简介 (Project Introduction)

Doge-Gabh 是一个集成了 Windows ntdll 动态调用、直接系统调用、API hash 调用和 DLL 脱钩的 Golang 组件包。该项目提供了多种地狱之门方法、脱钩方法、直接系统调用方法和动态 API hash 调用方法，使用户能够灵活地从磁盘或内存中调用系统 API。

Doge-Gabh is a Golang component package that integrates Windows ntdll dynamic calls, direct system calls, API hash calls, and DLL unhooking. This project provides various Hell's Gate methods, unhooking methods, direct system call methods, and dynamic API hash call methods, allowing users to flexibly call system APIs from disk or memory.

主要用途包括但不限于：
Main uses include but are not limited to:
- PE 解析 (PE parsing)
- 动态 API 调用 (Dynamic API calls)
- Shellcode 加载器 (Shellcode loader)
- 进程注入 (Process injection)
- 绕过 API 挂钩 (Bypassing API hooks)

项目名称 Gabh 原意为 GetAddressByHash，后来扩展为类似 DInvoke 的动态调用工具包。

The project name Gabh originally stood for GetAddressByHash, later expanded to become a dynamic calling toolkit similar to DInvoke.

**注意：本工具仅用于实现 API 调用。具体调用者实现的功能以及可能造成的影响与项目本体无关。**

**Note: This tool is only for implementing API calls. The specific functions implemented by the caller and any potential impacts are not related to the project itself.**

## 主要特性 (Main Features)

1. 集成多种地狱之门及其衍生项目的 Golang 实现：
   Golang implementation of various Hell's Gate and its derivative projects:
   - Hell's Gate
   - Halo's Gate
   - Tartaru's Gate
   - Spoofing Gate
   - Doge-EGGCall
   - RecycledGate

2. 集成 syswhisper 实现
   Integrated syswhisper implementation

3. 提供多种获取函数地址和系统调用的方法：
   Provides various methods for obtaining function addresses and system calls:
   - 通过 hash 从内存获取函数地址 (Get function address from memory by hash)
   - 通过 hash 从磁盘获取函数地址 (Get function address from disk by hash)
   - 重映射 ntdll (Remap ntdll)
   - 获取重映射后的函数地址 (Get function address after remapping)
   - Tartaru's Gate/Halo's Gate 调用 (Tartaru's Gate/Halo's Gate call)
   - Spoofing-Gate
   - 通用 ntdll 获取 (Universal ntdll acquisition)
   - 全 DLL 脱钩 (Full DLL unhooking)
   - Perun's Fart 脱钩 ntdll (Perun's Fart ntdll unhooking)
   - CMD 类型的全 DLL 脱钩 (CMD-type full DLL unhooking)
   - Recycled Gate 调用 (Recycled Gate call)
   - RefleXXion
   - 代理调用 (Proxy call)

## 安装 (Installation)

```
go get github.com/timwhitez/Doge-Gabh
```

## 主要功能 (Main Functions)

```go
// 从内存中通过 hash 获取函数地址
// Get function address from memory by hash
gabh.MemFuncPtr()

// 从磁盘中通过 hash 获取函数地址
// Get function address from disk by hash
gabh.DiskFuncPtr()

// 获取重映射的 ntdll
// Get remapped ntdll
gabh.ReMapNtdll()

// 获取重映射后的函数地址
// Get function address after remapping
GetFuncUnhook()

// ntdll Tartaru's Gate/Halo's Gate
gabh.MemHgate()
gabh.DiskHgate()

// Tartaru's Gate/Halo's Gate 调用系统 ID
// Tartaru's Gate/Halo's Gate call system ID
gabh.HgSyscall()

// EGG 替换
// EGG replacement
eggreplace.FindAndReplace()

// Tartaru's Gate/Halo's Gate 调用系统 ID（更多 EGG）
// Tartaru's Gate/Halo's Gate call system ID (more EGG)
gabh.EggCall()

// Spoofing-Gate
gabh.SpfGate()

// 获取通用 ntdll
// Get universal ntdll
gabh.Universal()

// 获取通用函数地址
// Get universal function address
UniversalFindProc()

// 全 DLL 脱钩
// Full DLL unhooking
gabh.FullUnhook()

// Perun's Fart 脱钩 ntdll
// Perun's Fart ntdll unhooking
gabh.PerunsFart()

// CMD 类型的全 DLL 脱钩
// CMD-type full DLL unhooking
gabh.CMDUnhook()

// 获取 syscall;ret
// Get syscall;ret
gabh.GetRecyCall()

// Recycled Gate 调用
// Recycled Gate call
gabh.ReCycall()

// 初始化 DW_SYSCALL_LIST
// Initialize DW_SYSCALL_LIST
var newWhisper = gabh.DWhisper()

// 从 DW_SYSCALL_LIST 获取系统 ID
// Get system ID from DW_SYSCALL_LIST
sysid := newWhisper.GetSysid("4942059d")

// RefleXXion
gabh.KDllunhook()

// 通过名称获取 SSN（排除某些情况）
// Get SSN by name (excluding certain cases)
gabh.GetSSNByNameExcept()

// 代理调用
// Proxy call
proxycall.ProxyCall()
```

## 使用示例 (Usage Example)

项目的 `example` 文件夹中包含了多个使用示例，涵盖了各种功能的调用方法。以下是一个基本的使用示例：

The `example` folder in the project contains multiple usage examples covering various function call methods. Here's a basic usage example:

```go
package main

import (
    "fmt"
    "syscall"
    "unsafe"
    gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
)

func main() {
    // 使用 Universal 方法获取函数指针
    // Use Universal method to get function pointer
    ntdll, _ := gabh.Universal(str2sha1)
    sleep, _ := ntdll.UniversalFindProc("84804f99e2c7ab8aee611d256a085cf4879c4be8")
    fmt.Printf("Universal Addr:0x%x\n", sleep)

    fmt.Println("Sleep for 3s")
    times := -(3000 * 10000)
    syscall.Syscall(sleep, 2, 0, uintptr(unsafe.Pointer(&times)), 0)

    // 使用 MemFuncPtr 通过 hash 获取函数指针
    // Use MemFuncPtr to get function pointer by hash
    sleep_ptr, moduleN, err := gabh.MemFuncPtr("kernel32.dll", "c3ca5f787365eae0dea86250e27d476406956478", str2sha1)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Printf("%s: %x\n", moduleN, sleep_ptr)
    syscall.Syscall(uintptr(sleep_ptr), 1, 1000, 0, 0)

    // 使用 HellsGate 获取系统调用 ID
    // Use HellsGate to get system call ID
    sleep1, e := gabh.DiskHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
    if e != nil {
        panic(e)
    }
    fmt.Printf("%s: %x\n", "NtDelayExecution Sysid", sleep1)

    // 使用 HellsGate 进行系统调用
    // Use HellsGate for system call
    gabh.HgSyscall(sleep1, 0, uintptr(unsafe.Pointer(&times)))
}

// 辅助函数：将字符串转换为 SHA1 哈希
// Helper function: Convert string to SHA1 hash
func str2sha1(s string) string {
    // 实现略 (Implementation omitted)
}
```

更多详细示例请参考项目的 `example` 文件夹。
For more detailed examples, please refer to the `example` folder in the project.

## 项目结构 (Project Structure)

- `pkg/`: 核心功能包 (Core function package)
- `example/`: 使用示例 (Usage examples)
  - CMDUnhook
  - EggCall
  - FullUnhook
  - GetSSNExcept
  - KnownDllunhook
  - PerunsFart
  - ProxyCall
  - RecycledGate
  - SpfGate
  - Unhook_remap
  - UniversalLoad
  - Whisper
  - shellcodecalc
  - sleep
  - testhook

## 参考资料 (References)

- [Doge-ReMap](https://github.com/timwhitez/Doge-ReMap)
- [Load NTDLL Too](https://idiotc4t.com/defense-evasion/load-ntdll-too)
- [Binject/debug](https://github.com/Binject/debug/)
- [BananaPhone](https://github.com/C-Sto/BananaPhone)
- [Binject/universal](https://github.com/Binject/universal)
- [TartarusGate](https://github.com/trickster0/TartarusGate)
- [Perun's Fart](https://github.com/plackyhacker/Peruns-Fart)
- [UserModeUnhooking](https://github.com/TomOS3/UserModeUnhooking)
- [Spoofing-Gate](https://github.com/timwhitez/Spoofing-Gate)
- [NoSysWhisper](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- [RecycledGate](https://github.com/thefLink/RecycledGate)
- [Doge-RecycledGate](https://github.com/timwhitez/Doge-RecycledGate)
- [Doge-Whisper](https://github.com/timwhitez/Doge-Whisper)
- [Freshycalls](https://github.com/Crummie5/Freshycalls)
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [Bypassing User Mode Hooks and Direct Invocation of System Calls for Red Teams](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

## 🚀Star Trend
[![Stargazers over time](https://starchart.cc/timwhitez/Doge-Gabh.svg)](https://starchart.cc/timwhitez/Doge-Gabh)

## 致谢 (Acknowledgements)

感谢 JetBrains 为 Doge-Gabh 项目提供 Goland IDE 开源许可证。
Thanks to JetBrains for providing the Goland IDE open source license for the Doge-Gabh project.

<p align="center">
  <img alt="JetBrains Logo" src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.svg" height="20%" width="20%">
  <img alt="GoLand Logo" src="https://resources.jetbrains.com/storage/products/company/brand/logos/GoLand_icon.svg" height="20%" width="20%">
</p>
 
## 免责声明 (Disclaimer)

本项目仅供学习和研究使用。使用者应当遵守所有适用的法律法规，不得将本项目用于任何非法目的。作者对使用者的任何行为不承担任何责任。

This project is for learning and research purposes only. Users should comply with all applicable laws and regulations and must not use this project for any illegal purposes. The author bears no responsibility for any actions taken by users.
