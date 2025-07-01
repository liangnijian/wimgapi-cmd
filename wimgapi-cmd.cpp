#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <strsafe.h>

enum
{
    WIM_MSG = WM_APP + 0x1476,
    WIM_MSG_TEXT,
    WIM_MSG_PROGRESS,
    WIM_MSG_PROCESS,
    WIM_MSG_SCANNING,
    WIM_MSG_SETRANGE,
    WIM_MSG_SETPOS,
    WIM_MSG_STEPIT,
    WIM_MSG_COMPRESS,
    WIM_MSG_ERROR,
    WIM_MSG_ALIGNMENT,
    WIM_MSG_RETRY,
    WIM_MSG_SPLIT,
    WIM_MSG_FILEINFO,
    WIM_MSG_INFO,
    WIM_MSG_WARNING,
    WIM_MSG_CHK_PROCESS,
    WIM_MSG_WARNING_OBJECTID,
    WIM_MSG_STALE_MOUNT_DIR,
    WIM_MSG_STALE_MOUNT_FILE,
    WIM_MSG_MOUNT_CLEANUP_PROGRESS,
    WIM_MSG_CLEANUP_SCANNING_DRIVE,
    WIM_MSG_IMAGE_ALREADY_MOUNTED,
    WIM_MSG_CLEANUP_UNMOUNTING_IMAGE,
    WIM_MSG_QUERY_ABORT,
    WIM_MSG_IO_RANGE_START_REQUEST_LOOP,
    WIM_MSG_IO_RANGE_END_REQUEST_LOOP,
    WIM_MSG_IO_RANGE_REQUEST,
    WIM_MSG_IO_RANGE_RELEASE,
    WIM_MSG_VERIFY_PROGRESS,
    WIM_MSG_COPY_BUFFER,
    WIM_MSG_METADATA_EXCLUDE,
    WIM_MSG_GET_APPLY_ROOT,
    WIM_MSG_MDPAD,
    WIM_MSG_STEPNAME,
    WIM_MSG_PERFILE_COMPRESS,
    WIM_MSG_CHECK_CI_EA_PREREQUISITE_NOT_MET,
    WIM_MSG_JOURNALING_ENABLED
};

// WIM消息回调返回码
#define WIM_MSG_SUCCESS          ERROR_SUCCESS
#define WIM_MSG_DONE             0xFFFFFFF0
#define WIM_MSG_SKIP_ERROR       0xFFFFFFFE
#define WIM_MSG_ABORT_IMAGE      0xFFFFFFFF

typedef DWORD(WINAPI* WIM_MSG_CALLBACK)(
    DWORD  dwMessageId,
    WPARAM wParam,
    LPARAM lParam,
    PVOID  pvUserData
    );

// 定义wimgapi.dll函数指针
typedef HANDLE(WINAPI* WIMCreateFilePtr)(
    _In_      PCWSTR pszWimPath,
    _In_      DWORD  dwDesiredAccess,
    _In_      DWORD  dwCreationDisposition,
    _In_      DWORD  dwFlagsAndAttributes,
    _In_      DWORD  dwCompressionType,
    _Out_opt_ PDWORD pdwCreationResult
    );

typedef HANDLE(WINAPI* WIMLoadImagePtr)(
    _In_ HANDLE hWim,
    _In_ DWORD  dwImageIndex
    );

typedef BOOL(WINAPI* WIMApplyImagePtr)(
    _In_      HANDLE hImage,
    _In_opt_  PCWSTR pszPath,
    _In_      DWORD  dwApplyFlags
    );

typedef DWORD(WINAPI* WIMGetImageCountPtr)(
    _In_ HANDLE hWim
    );

typedef BOOL(WINAPI* WIMGetImageInformationPtr)(
    _In_  HANDLE hWim,
    _Out_ PVOID* ppvImageInfo,
    _Out_ PDWORD pcbImageInfo
    );

typedef DWORD(WINAPI* WIMRegisterMessageCallbackPtr)(
    _In_opt_ HANDLE hWim,
    _In_    FARPROC fpMessageProc,
    _In_opt_ PVOID  pvUserData
    );

typedef DWORD(WINAPI* WIMUnregisterMessageCallbackPtr)(
    _In_opt_ HANDLE hWim,
    _In_     FARPROC fpMessageProc
    );

typedef BOOL(WINAPI* WIMCloseHandlePtr)(
    _In_ HANDLE hObject
    );

typedef BOOL(WINAPI* WIMSetTemporaryPathPtr)(
    _In_ HANDLE hWim,
    _In_ PCWSTR pszPath
    );

// 全局函数指针
WIMCreateFilePtr pfnWIMCreateFile = NULL;
WIMLoadImagePtr pfnWIMLoadImage = NULL;
WIMApplyImagePtr pfnWIMApplyImage = NULL;
WIMGetImageCountPtr pfnWIMGetImageCount = NULL;
WIMGetImageInformationPtr pfnWIMGetImageInformation = NULL;
WIMRegisterMessageCallbackPtr pfnWIMRegisterMessageCallback = NULL;
WIMUnregisterMessageCallbackPtr pfnWIMUnregisterMessageCallback = NULL;
WIMCloseHandlePtr pfnWIMCloseHandle = NULL;
WIMSetTemporaryPathPtr pfnWIMSetTemporaryPath = NULL;

// 加载wimgapi.dll
HMODULE LoadWimgapiDLL() {
    WCHAR dllPath[MAX_PATH] = { 0 };

    // 尝试从当前目录加载
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    WCHAR* lastBackslash = wcsrchr(dllPath, L'\\');
    if (lastBackslash) {
        wcscpy_s(lastBackslash + 1, MAX_PATH - (lastBackslash - dllPath + 1), L"wimgapi.dll");
        HMODULE hDll = LoadLibraryW(dllPath);
        if (hDll) return hDll;
    }

    // 尝试从System32加载
    UINT sysDirLen = GetSystemDirectoryW(dllPath, MAX_PATH);
    if (sysDirLen > 0 && sysDirLen < MAX_PATH) {
        if (FAILED(StringCchCatW(dllPath, MAX_PATH, L"\\wimgapi.dll"))) {
            return NULL;
        }
        return LoadLibraryW(dllPath);
    }

    return NULL;
}

// 初始化函数指针
BOOL InitWimgapiFunctions(HMODULE hDll) {
    if (!hDll) return FALSE;

    pfnWIMCreateFile = (WIMCreateFilePtr)GetProcAddress(hDll, "WIMCreateFile");
    pfnWIMLoadImage = (WIMLoadImagePtr)GetProcAddress(hDll, "WIMLoadImage");
    pfnWIMApplyImage = (WIMApplyImagePtr)GetProcAddress(hDll, "WIMApplyImage");
    pfnWIMGetImageCount = (WIMGetImageCountPtr)GetProcAddress(hDll, "WIMGetImageCount");
    pfnWIMGetImageInformation = (WIMGetImageInformationPtr)GetProcAddress(hDll, "WIMGetImageInformation");
    pfnWIMRegisterMessageCallback = (WIMRegisterMessageCallbackPtr)GetProcAddress(hDll, "WIMRegisterMessageCallback");
    pfnWIMUnregisterMessageCallback = (WIMUnregisterMessageCallbackPtr)GetProcAddress(hDll, "WIMUnregisterMessageCallback");
    pfnWIMCloseHandle = (WIMCloseHandlePtr)GetProcAddress(hDll, "WIMCloseHandle");
    pfnWIMSetTemporaryPath = (WIMSetTemporaryPathPtr)GetProcAddress(hDll, "WIMSetTemporaryPath");

    if (!pfnWIMCreateFile) wprintf(L"Failed to load WIMCreateFile\n");
    if (!pfnWIMLoadImage) wprintf(L"Failed to load WIMLoadImage\n");
    if (!pfnWIMApplyImage) wprintf(L"Failed to load WIMApplyImage\n");
    if (!pfnWIMGetImageCount) wprintf(L"Failed to load WIMGetImageCount\n");
    if (!pfnWIMGetImageInformation) wprintf(L"Failed to load WIMGetImageInformation\n");
    if (!pfnWIMCloseHandle) wprintf(L"Failed to load WIMCloseHandle\n");
    if (!pfnWIMSetTemporaryPath) wprintf(L"Failed to load WIMSetTemporaryPath\n");

    return pfnWIMCreateFile && pfnWIMLoadImage && pfnWIMApplyImage &&
        pfnWIMGetImageCount && pfnWIMGetImageInformation &&
        pfnWIMCloseHandle && pfnWIMSetTemporaryPath;
}

// 安全释放内存
template<typename T>
inline void SafeFree(T*& p) {
    if (p) {
        LocalFree(p);
        p = NULL;
    }
}

// 安全输出宽字符串到控制台
void SafeWriteConsole(LPCWSTR str) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) return;

    DWORD written = 0;
    WriteConsoleW(hConsole, str, wcslen(str), &written, NULL);
}

// 格式化并输出带变量的宽字符串
void SafePrintf(LPCWSTR format, ...) {
    va_list args;
    va_start(args, format);

    WCHAR buffer[1024];
    if (SUCCEEDED(StringCchVPrintfW(buffer, _countof(buffer), format, args))) {
        SafeWriteConsole(buffer);
    }

    va_end(args);
}

// 进度回调函数
DWORD WINAPI ProgressCallback(DWORD dwMessageId, WPARAM wParam, LPARAM lParam, PVOID pvUserData) {
    //std::cout << dwMessageId << std::endl;
    if (dwMessageId == WIM_MSG_PROGRESS) {
        DWORD dwPercent = (DWORD)wParam;
        SafePrintf(L"Installing... %lu%%\r", dwPercent);
    }
    return 0;
}

// 安装镜像
BOOL InstallImage(LPCWSTR wimPath, DWORD imageIndex, LPCWSTR installPath) {
    DWORD creationResult = 0;
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING, 0, 0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    BOOL bResult = FALSE;
    WCHAR tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath)) {
        if (!pfnWIMSetTemporaryPath(hWim, tempPath)) {
            SafePrintf(L"Warning: Failed to set temporary path. Error: %lu\n", GetLastError());
        }
    }

    HANDLE hImage = pfnWIMLoadImage(hWim, imageIndex);
    if (hImage == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to load image. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // 修复：注册全局进度回调函数（将第一个参数改为NULL）
    pfnWIMRegisterMessageCallback(hWim, (FARPROC)ProgressCallback, NULL);

    if (pfnWIMApplyImage(hImage, installPath, 0x00000100)) {
        SafePrintf(L"\nImage applied successfully\n");
        bResult = TRUE;
    }
    else {
        SafePrintf(L"\nImage application failed. Error: %lu\n", GetLastError());
    }

    // 注销全局进度回调函数（将第一个参数改为NULL）
    pfnWIMUnregisterMessageCallback(NULL, (FARPROC)ProgressCallback);

    pfnWIMCloseHandle(hImage);

CLEANUP:
    pfnWIMCloseHandle(hWim);
    return bResult;
}

// 获取镜像数量
DWORD GetImageCount(LPCWSTR wimPath) {
    DWORD creationResult = 0;
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING, 0, 0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\n", GetLastError());
        return 0;
    }

    DWORD count = pfnWIMGetImageCount(hWim);
    SafePrintf(L"Image count: %lu\n", count);

    pfnWIMCloseHandle(hWim);
    return count;
}

// 从XML字符串中提取信息
LPWSTR ExtractInfo(LPCWSTR xml, LPCWSTR tag) {
    WCHAR startTag[128] = { 0 };
    WCHAR endTag[128] = { 0 };
    swprintf_s(startTag, _countof(startTag), L"<%s>", tag);
    swprintf_s(endTag, _countof(endTag), L"</%s>", tag);

    LPCWSTR start = wcsstr(xml, startTag);
    if (!start) {
        WCHAR attrTag[128] = { 0 };
        swprintf_s(attrTag, _countof(attrTag), L"<%s ", tag);
        start = wcsstr(xml, attrTag);
        if (!start) return NULL;

        start = wcschr(start, L'>');
        if (!start) return NULL;
        start++;
    }
    else {
        start += wcslen(startTag);
    }

    LPCWSTR end = wcsstr(start, endTag);
    if (!end) return NULL;

    size_t len = end - start;
    LPWSTR result = (LPWSTR)LocalAlloc(LPTR, (len + 1) * sizeof(WCHAR));
    if (result) {
        wcsncpy_s(result, len + 1, start, len);
    }
    return result;
}

// 获取格式化版本号
LPWSTR GetFormattedVersion(LPCWSTR xml) {
    LPWSTR major = ExtractInfo(xml, L"MAJOR");
    LPWSTR minor = ExtractInfo(xml, L"MINOR");
    LPWSTR build = ExtractInfo(xml, L"BUILD");
    LPWSTR spbuild = ExtractInfo(xml, L"SPBUILD");

    if (!major || !minor || !build) {
        SafeFree(major);
        SafeFree(minor);
        SafeFree(build);
        SafeFree(spbuild);
        return ExtractInfo(xml, L"BUILD");
    }

    size_t len = wcslen(major) + wcslen(minor) + wcslen(build) + 3;
    if (spbuild && wcscmp(spbuild, L"0") != 0) {
        len += wcslen(spbuild) + 1;
    }

    LPWSTR version = (LPWSTR)LocalAlloc(LPTR, len * sizeof(WCHAR));
    if (version) {
        swprintf_s(version, len, L"%s.%s.%s", major, minor, build);
        if (spbuild && wcscmp(spbuild, L"0") != 0) {
            wcscat_s(version, len, L".");
            wcscat_s(version, len, spbuild);
        }
    }

    SafeFree(major);
    SafeFree(minor);
    SafeFree(build);
    SafeFree(spbuild);

    return version;
}

// 将架构数字转换为字符串
LPCWSTR GetArchitectureString(LPCWSTR arch) {
    if (!arch) return L"Unknown";
    if (wcscmp(arch, L"0") == 0) return L"x86";
    if (wcscmp(arch, L"9") == 0) return L"x64";
    if (wcscmp(arch, L"5") == 0) return L"ARM";
    if (wcscmp(arch, L"12") == 0) return L"ARM64";
    return L"Unknown";
}

// 获取镜像信息
void GetImageInfo(LPCWSTR wimPath, DWORD imageIndex) {
    DWORD creationResult = 0;
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING, 0, 0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\n", GetLastError());
        return;
    }

    PVOID pvImageInfo = NULL;
    DWORD cbImageInfo = 0;
    if (!pfnWIMGetImageInformation(hWim, &pvImageInfo, &cbImageInfo)) {
        SafePrintf(L"Failed to get image information. Error: %lu\n", GetLastError());
        pfnWIMCloseHandle(hWim);
        return;
    }

    LPCWSTR xmlInfo = (LPCWSTR)pvImageInfo;

    // 根据镜像索引查找特定镜像信息
    WCHAR imageTag[128] = { 0 };
    swprintf_s(imageTag, _countof(imageTag), L"<IMAGE INDEX=\"%lu\"", imageIndex);

    // 在整个XML中查找指定镜像的标签
    LPCWSTR imageStart = wcsstr(xmlInfo, imageTag);
    if (!imageStart) {
        SafePrintf(L"Image index %lu not found in WIM file\n", imageIndex);
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }

    // 查找IMAGE结束标签
    LPCWSTR imageEnd = wcsstr(imageStart, L"</IMAGE>");
    if (!imageEnd) {
        SafePrintf(L"Malformed XML: IMAGE tag not closed for index %lu\n", imageIndex);
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }

    // 提取镜像内容（跳过开始标签）
    LPCWSTR contentStart = wcschr(imageStart, L'>');
    if (!contentStart) {
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }
    contentStart++;  // 跳过'>'字符

    // 计算内容长度
    DWORD contentLen = (DWORD)(imageEnd - contentStart);
    LPWSTR imageContent = (LPWSTR)LocalAlloc(LPTR, (contentLen + 1) * sizeof(WCHAR));
    if (!imageContent) {
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }
    wcsncpy_s(imageContent, contentLen + 1, contentStart, contentLen);

    // 从镜像内容中提取信息
    LPWSTR name = ExtractInfo(imageContent, L"NAME");
    LPWSTR lang = ExtractInfo(imageContent, L"LANGUAGE");
    LPWSTR arch = ExtractInfo(imageContent, L"ARCH");
    LPWSTR version = GetFormattedVersion(imageContent);

    // 输出镜像信息
    SafePrintf(L"Image Information (Index %lu):\n", imageIndex);
    if (name) SafePrintf(L"  Name: %s\n", name);
    if (version) SafePrintf(L"  Version: %s\n", version);
    if (lang) SafePrintf(L"  Language: %s\n", lang);
    if (arch) SafePrintf(L"  Architecture: %s\n", GetArchitectureString(arch));

    // 清理资源
    SafeFree(name);
    SafeFree(lang);
    SafeFree(arch);
    SafeFree(version);
    LocalFree(imageContent);
    LocalFree(pvImageInfo);
    pfnWIMCloseHandle(hWim);
}

// 显示帮助信息
void ShowHelp() {
    const wchar_t* helpText = L"Usage: wimgapi-cmd.exe [options]\n"
        L"Options:\n"
        L"  -install <image_path> <image_index> <install_path> : Install image to target path\n"
        L"  -info <image_path> : Show number of images in WIM file\n"
        L"  -info <image_path> <image_index> : Show image information\n"
        L"  help or /? : Display this help message\n";

    SafeWriteConsole(helpText);
}

int wmain(int argc, wchar_t* argv[]) {
    HMODULE hWimgapi = LoadWimgapiDLL();
    if (!hWimgapi || !InitWimgapiFunctions(hWimgapi)) {
        SafePrintf(L"Failed to load wimgapi.dll. Error: %lu\n", GetLastError());
        return 1;
    }

    if (argc < 2) {
        ShowHelp();
        return 1;
    }

    if (_wcsicmp(argv[1], L"-install") == 0 && argc == 5) {
        if (!InstallImage(argv[2], _wtoi(argv[3]), argv[4])) {
            return 1;
        }
    }
    else if (_wcsicmp(argv[1], L"-info") == 0) {
        if (argc == 3) {
            GetImageCount(argv[2]);
        }
        else if (argc == 4) {
            GetImageInfo(argv[2], _wtoi(argv[3]));
        }
        else {
            ShowHelp();
            return 1;
        }
    }
    else if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"/?") == 0) {
        ShowHelp();
    }
    else {
        SafeWriteConsole(L"Invalid command or parameters.\n");
        ShowHelp();
        return 1;
    }

    FreeLibrary(hWimgapi);
    return 0;
}
