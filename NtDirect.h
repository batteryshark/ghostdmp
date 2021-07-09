//
// Created by merca on 5/7/2019.
//

#ifndef GHOSTDMP_NTDIRECT_H
#define GHOSTDMP_NTDIRECT_H

#define NTDLL_STUB_SIZE 21
#define NAKED __attribute__((naked))
#include <ntdef.h>
#include <cstdlib>

#define CURRENT_PROCESS_HANDLE (HANDLE)-1


class NtRedirect {
public:
    unsigned char backup_bytes[NTDLL_STUB_SIZE];
    void* ntdll_library_function_address;
    void* redirect_address;
    void* real_ptr;
    void* allocated_address;
    size_t allocated_length;
    bool valid;
    NtRedirect(const char* func_name, void* redirect_function_address,void** real_function_address);
    ~NtRedirect();
    bool remove_hook();
    bool install_hook(const char* func_name);
};

NAKED NTSTATUS NTAPI iNtReadVirtualMemory(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);
NAKED NTSTATUS NTAPI iNtAdjustPrivilegesToken(HANDLE TokenHandle,BOOLEAN DisableAllPrivileges,void* TokenPrivileges,ULONG PreviousPrivilegesLength,void* PreviousPrivileges,PULONG RequiredLength);
NAKED NTSTATUS NTAPI iNtOpenProcessToken(HANDLE ProcessHandle, uint32_t DesiredAccess,PHANDLE TokenHandle);
#endif //GHOSTDMP_NTDIRECT_H
