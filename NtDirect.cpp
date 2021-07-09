//
// Created by merca on 5/7/2019.
//

#include <cstdint>
#include "NtDirect.h"

#include <libloaderapi.h>
#include <cstdio>

// Some Minimal NT Stuff
#define MEM_RELEASE   0x8000
#define MEM_COMMIT    0x1000
#define MEM_RESERVE   0x2000

#define PAGE_EXECUTE_READWRITE   0x40
#define PAGE_EXECUTE_READ        0x20
#define PAGE_EXECUTE             0x10

// #define WIN7
#ifdef WIN7
    #define SYSCALL_CODE_NTALLOCATE_VIRTUAL_MEMORY 0x15
    #define SYSCALL_CODE_NTFREE_VIRTUAL_MEMORY     0x1B
    #define SYSCALL_CODE_NTPROTECT_VIRTUAL_MEMORY  0x4D
    #define SYSCALL_CODE_NTREAD_VIRTUAL_MEMORY     0x3C
    #define SYSCALL_CODE_NTADJUST_PRIVS_TOKEN      0x3E
    #define SYSCALL_CODE_NTOPEN_PROCESS_TOKEN      0xF9
#else // WIN10 Current -- Obviously this might change
    #define SYSCALL_CODE_NTALLOCATE_VIRTUAL_MEMORY 0x18
    #define SYSCALL_CODE_NTFREE_VIRTUAL_MEMORY     0x1E
    #define SYSCALL_CODE_NTPROTECT_VIRTUAL_MEMORY  0x50
    #define SYSCALL_CODE_NTREAD_VIRTUAL_MEMORY     0x3F
    #define SYSCALL_CODE_NTADJUST_PRIVS_TOKEN      0x41
    #define SYSCALL_CODE_NTOPEN_PROCESS_TOKEN      0x122
#endif


#define STR(x) #x
#define XSTR(s) STR(s)

NAKED NTSTATUS NTAPI iNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect){
    __asm__(
        "  mov %rcx,%r10 \n"
        "mov $" XSTR(SYSCALL_CODE_NTALLOCATE_VIRTUAL_MEMORY)",%eax \n"
        "syscall \n"
        "  ret	\n"
    );
}

NAKED NTSTATUS NTAPI iNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection){
    __asm__(
    "  mov %rcx,%r10 \n"
    "mov $" XSTR(SYSCALL_CODE_NTPROTECT_VIRTUAL_MEMORY)",%eax \n"
    "syscall \n"
    "  ret	\n"
    );
}

NAKED NTSTATUS NTAPI iNtFreeVirtualMemory(HANDLE  ProcessHandle,PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType){
    __asm__(
    "  mov %rcx,%r10 \n"
    "mov $" XSTR(SYSCALL_CODE_NTFREE_VIRTUAL_MEMORY)",%eax \n"
    "syscall \n"
    "  ret	\n"
    );
}

NAKED NTSTATUS NTAPI iNtReadVirtualMemory(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded){
    __asm__(
    "  mov %rcx,%r10 \n"
    "mov $" XSTR(SYSCALL_CODE_NTREAD_VIRTUAL_MEMORY)",%eax \n"
    "syscall \n"
    "  ret	\n"
    );
}

NAKED NTSTATUS NTAPI iNtAdjustPrivilegesToken(HANDLE TokenHandle,BOOLEAN DisableAllPrivileges,void* TokenPrivileges,ULONG PreviousPrivilegesLength,void* PreviousPrivileges,PULONG RequiredLength ){
    __asm__(
    "  mov %rcx,%r10 \n"
    "mov $" XSTR(SYSCALL_CODE_NTADJUST_PRIVS_TOKEN)",%eax \n"
    "syscall \n"
    "  ret	\n"
    );
}

NAKED NTSTATUS NTAPI iNtOpenProcessToken(HANDLE ProcessHandle, uint32_t DesiredAccess,PHANDLE TokenHandle){
    __asm__(
    "  mov %rcx,%r10 \n"
    "mov $" XSTR(SYSCALL_CODE_NTOPEN_PROCESS_TOKEN)",%eax \n"
    "syscall \n"
    "  ret	\n"
    );
}



// Direct ntdll call Framework.

NtRedirect::NtRedirect(const char* func_name,void* redirect_function_address,void** real_function_address){
    this->allocated_length = 0;
    this->redirect_address = redirect_function_address;
    this->real_ptr = *real_function_address;
    this->ntdll_library_function_address = nullptr;
    memset(this->backup_bytes,0x00,sizeof(this->backup_bytes));

    // Patch the function prologue with our redirected address.
    // If we didn't give a real_function_address, the hook will create a trampoline for us from the original.
    // Otherwise, the hook will assume we will use our own real function (direct or otherwise).
    this->valid = this->install_hook(func_name);
    if(this->valid){
        if(!*real_function_address){
            *real_function_address = this->real_ptr;
        }
    }

}

NtRedirect::~NtRedirect() {
    // Wipe any allocated trampoline function.
    this->valid = false;
this->redirect_address = nullptr;
this->real_ptr = nullptr;
this->remove_hook();
memset(this->backup_bytes,0x00,sizeof(this->backup_bytes));
    if(this->allocated_address != nullptr && this->allocated_length > 0){
        ULONG old_access;
        // Set the Page to Writable
        iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &this->allocated_address, &this->allocated_length, PAGE_EXECUTE_READWRITE, (PULONG)&old_access);
        // Wipe the Memory
        memset(this->allocated_address,0x00,this->allocated_length);
        // Free the Memory
        iNtFreeVirtualMemory((HANDLE)-1, &this->allocated_address, &this->allocated_length, MEM_RELEASE);
        this->allocated_address = nullptr;
        this->allocated_length = 0;
    }
}

bool NtRedirect::remove_hook() {
    size_t stub_size = NTDLL_STUB_SIZE;
    ULONG old_access;
    PVOID pvFunctionAddress = (PVOID)this->ntdll_library_function_address; // used for virtual memory operations
    iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &pvFunctionAddress, &stub_size, PAGE_EXECUTE_READWRITE, (PULONG)&old_access);
    memcpy(this->ntdll_library_function_address,this->backup_bytes,NTDLL_STUB_SIZE);
    iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &pvFunctionAddress, &stub_size, old_access, (PULONG)&old_access);
    return true;
}

bool NtRedirect::install_hook(const char* func_name){
    unsigned char jmp_to_code[16] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,0x90,0x90,0x90,0x90};
    size_t hook_size = sizeof(jmp_to_code);
    memcpy(jmp_to_code+2,&this->redirect_address,sizeof(void*));
    size_t stolen_bytes_size = NTDLL_STUB_SIZE;
    // Resolve the function address we're targeting.
    // TODO: Do this in an embedded way.
    this->ntdll_library_function_address = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), func_name);
    if (this->ntdll_library_function_address == nullptr) { return false; }
    PVOID pvFunctionAddress = (PVOID)this->ntdll_library_function_address; // used for virtual memory operations

    ULONG old_access_protection_ntdll = 0;

    // Set Read/Write to Area we need to modify.
    if(iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, (PVOID*)&pvFunctionAddress, (PSIZE_T)&hook_size, PAGE_EXECUTE_READWRITE, (PULONG)&old_access_protection_ntdll)){ return false; }

    // Copy the original bytes to our backup buffer.
    memcpy(this->backup_bytes,this->ntdll_library_function_address,NTDLL_STUB_SIZE);

    // If a trampoline is necessary, write the backup now.
    if(this->real_ptr == nullptr){
        ULONG old_access_protection_trampoline;

        if(iNtAllocateVirtualMemory(CURRENT_PROCESS_HANDLE, &this->real_ptr, 0,   (PSIZE_T)&stolen_bytes_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)){return false;};
        this->allocated_address = this->real_ptr;
        this->allocated_length = stolen_bytes_size;
        // Copy the stolen bytes from target address to our trampoline.
        memcpy(this->real_ptr, this->ntdll_library_function_address, NTDLL_STUB_SIZE);

        // Reprotect the page.
        iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE,  &this->real_ptr, (PSIZE_T)&hook_size, PAGE_EXECUTE, (PULONG)&old_access_protection_trampoline);

    }

    // Finally, overwrite the prologue with our patched jump.
    memcpy(this->ntdll_library_function_address,jmp_to_code,sizeof(jmp_to_code));

    // Re-protect the memory of the function we hooked and the trampoline function.
    iNtProtectVirtualMemory(CURRENT_PROCESS_HANDLE, &pvFunctionAddress, (PSIZE_T)&hook_size, old_access_protection_ntdll, (PULONG)&old_access_protection_ntdll);

    return true;
}
