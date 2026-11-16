OPTION CASEMAP:NONE

EXTERN EnsureMsimg32Loaded:PROC
EXTERN g_pfn_vSetDdrawflag:QWORD
EXTERN g_pfn_AlphaBlend:QWORD
EXTERN g_pfn_DllInitialize:QWORD
EXTERN g_pfn_GradientFill:QWORD
EXTERN g_pfn_TransparentBlt:QWORD

.code

; Macro to lazily resolve real C:\Windows\System32\msimg32.dll if called before InitInstance,
; preserving all volatile argument registers (RCX, RDX, R8, R9, XMM0..XMM3) and jumping tail-call cleanly.
DEFINE_FORWARD_THUNK MACRO FuncName, TargetPtr
PUBLIC FuncName
FuncName PROC FRAME
    mov rax, qword ptr [TargetPtr]
    test rax, rax
    jz short slow_&FuncName
    jmp rax
slow_&FuncName:
    sub rsp, 68h
    .allocstack 68h
    .endprolog
    mov qword ptr [rsp + 20h], rcx
    mov qword ptr [rsp + 28h], rdx
    mov qword ptr [rsp + 30h], r8
    mov qword ptr [rsp + 38h], r9
    movups xmmword ptr [rsp + 40h], xmm0
    movups xmmword ptr [rsp + 50h], xmm1
    call EnsureMsimg32Loaded
    mov rcx, qword ptr [rsp + 20h]
    mov rdx, qword ptr [rsp + 28h]
    mov r8,  qword ptr [rsp + 30h]
    mov r9,  qword ptr [rsp + 38h]
    movups xmm0, xmmword ptr [rsp + 40h]
    movups xmm1, xmmword ptr [rsp + 50h]
    add rsp, 68h
    mov rax, qword ptr [TargetPtr]
    test rax, rax
    jz short fail_&FuncName
    jmp rax
fail_&FuncName:
    xor eax, eax
    ret
FuncName ENDP
ENDM

DEFINE_FORWARD_THUNK Forward_vSetDdrawflag, g_pfn_vSetDdrawflag
DEFINE_FORWARD_THUNK Forward_AlphaBlend,    g_pfn_AlphaBlend
DEFINE_FORWARD_THUNK Forward_DllInitialize, g_pfn_DllInitialize
DEFINE_FORWARD_THUNK Forward_GradientFill,  g_pfn_GradientFill
DEFINE_FORWARD_THUNK Forward_TransparentBlt, g_pfn_TransparentBlt

END
