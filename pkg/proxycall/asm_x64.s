
TEXT ·proxyC(SB), $0-16
    NOP
    NOP
    NOP
    NOP

    //EGG-Start
    BYTE $0x60
    BYTE $0x70
    BYTE $0x80
    BYTE $0x90
    BYTE $0xA0
    BYTE $0xB0
    BYTE $0xC0
    //EGG-End

    //Func-Start
    BYTE $0x48
    BYTE $0x89
    BYTE $0xD3
    BYTE $0x48
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x8B
    BYTE $0x03
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x00
    BYTE $0x0F
    BYTE $0x86
    BYTE $0x41
    BYTE $0x01
    BYTE $0x00
    BYTE $0x00
    BYTE $0x48
    BYTE $0x8B
    BYTE $0x4B
    BYTE $0x10
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x01
    BYTE $0x0F
    BYTE $0x86
    BYTE $0x32
    BYTE $0x01
    BYTE $0x00
    BYTE $0x00
    BYTE $0x48
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x18
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x02
    BYTE $0x0F
    BYTE $0x86
    BYTE $0x23
    BYTE $0x01
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x43
    BYTE $0x20
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x03
    BYTE $0x0F
    BYTE $0x86
    BYTE $0x14
    BYTE $0x01
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x4B
    BYTE $0x28
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x04
    BYTE $0x0F
    BYTE $0x86
    BYTE $0x05
    BYTE $0x01
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x05
    BYTE $0x0F
    BYTE $0x86
    BYTE $0xEE
    BYTE $0x00
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x06
    BYTE $0x0F
    BYTE $0x86
    BYTE $0xCE
    BYTE $0x00
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x07
    BYTE $0x0F
    BYTE $0x86
    BYTE $0xA5
    BYTE $0x00
    BYTE $0x00
    BYTE $0x00
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x48
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x08
    BYTE $0x76
    BYTE $0x77
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x50
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x48
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x48
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x09
    BYTE $0x76
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x58
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x50
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x50
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x48
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x48
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x40
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x38
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x8B
    BYTE $0x53
    BYTE $0x30
    BYTE $0x4C
    BYTE $0x89
    BYTE $0x54
    BYTE $0x24
    BYTE $0x28
    BYTE $0x4D
    BYTE $0x31
    BYTE $0xD2
    BYTE $0x48
    BYTE $0x83
    BYTE $0x7B
    BYTE $0x08
    BYTE $0x0A
    BYTE $0x76
    BYTE $0x00
    BYTE $0xFF
    BYTE $0xE0
    //Func-End

    NOP
    NOP
    NOP
    NOP