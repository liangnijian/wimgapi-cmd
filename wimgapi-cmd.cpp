#include <Windows.h>
#include <strsafe.h>
#include <string>

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

typedef HANDLE(WINAPI* WIMCaptureImagePtr)(
    _In_ HANDLE  hWim,
    _In_ PCWSTR  pszPath,
    _In_ DWORD   dwCaptureFlags
    );

typedef BOOL(WINAPI* WIMSetImageInformationPtr)(
    _In_ HANDLE hWim,
    _In_ PVOID  pvImageInfo,
    _In_ DWORD  cbImageInfo
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
WIMCaptureImagePtr pfnWIMCaptureImage = NULL;
WIMSetImageInformationPtr pfnWIMSetImageInformation = NULL;

// 全局变量：检测输出是否为控制台
static bool g_IsConsole = false;
static DWORD g_dwLastProgressPercent = (DWORD)-1; // 上一次进度百分比

// 加载wimgapi.dll
HMODULE LoadWimgapiDLL() {
    WCHAR dllPath[MAX_PATH] = { 0 };

    // 尝试从System32加载
    UINT sysDirLen = GetSystemDirectoryW(dllPath, MAX_PATH);
    if (sysDirLen > 0 && sysDirLen < MAX_PATH) {
        if (SUCCEEDED(StringCchCatW(dllPath, MAX_PATH, L"\\wimgapi.dll"))) {
            return LoadLibraryW(dllPath);
        }
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
    pfnWIMCaptureImage = (WIMCaptureImagePtr)GetProcAddress(hDll, "WIMCaptureImage");
    pfnWIMSetImageInformation = (WIMSetImageInformationPtr)GetProcAddress(hDll, "WIMSetImageInformation");

    return pfnWIMCreateFile && pfnWIMLoadImage && pfnWIMApplyImage &&
        pfnWIMGetImageCount && pfnWIMGetImageInformation &&
        pfnWIMCloseHandle && pfnWIMSetTemporaryPath &&
        pfnWIMCaptureImage && pfnWIMSetImageInformation;
}

// 安全释放内存
template<typename T>
inline void SafeFree(T*& p) {
    if (p) {
        LocalFree(p);
        p = NULL;
    }
}

// 安全输出宽字符串（统一转换为UTF-8输出）
void SafeWriteConsole(LPCWSTR str) {
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOutput == INVALID_HANDLE_VALUE) return;

    // 转换为 UTF-8 输出
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    if (utf8Size <= 0) return;

    CHAR* utf8Buffer = (CHAR*)LocalAlloc(LPTR, utf8Size);
    if (!utf8Buffer) return;

    if (WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8Buffer, utf8Size, NULL, NULL) > 0) {
        DWORD written = 0;
        WriteFile(hOutput, utf8Buffer, utf8Size - 1, &written, NULL);
    }

    LocalFree(utf8Buffer);
}

// 格式化并输出宽字符串
void SafePrintf(LPCWSTR format, ...) {
    va_list args;
    va_start(args, format);

    WCHAR buffer[2048];
    if (SUCCEEDED(StringCchVPrintfW(buffer, _countof(buffer), format, args))) {
        SafeWriteConsole(buffer);
    }
    va_end(args);
}

// 进度回调函数
DWORD WINAPI ProgressCallback(DWORD dwMessageId, WPARAM wParam, LPARAM, PVOID) {
    if (dwMessageId == WIM_MSG_PROGRESS) {
        DWORD dwPercent = (DWORD)wParam;
        if (dwPercent != g_dwLastProgressPercent) {
            g_dwLastProgressPercent = dwPercent;
            if (g_IsConsole) {
                // 控制台环境：使用\r覆盖当前行
                SafePrintf(L"Progress: %lu%%\r", dwPercent);
                // 100%完成后添加换行
                if (dwPercent == 100) {
                    SafeWriteConsole(L"\n");
                }
            }
            else {
                // 非控制台环境：使用换行输出
                SafePrintf(L"Progress: %lu%%\r\n", dwPercent);
            }
        }
    }
    return WIM_MSG_SUCCESS;
}

// 安装镜像
BOOL InstallImage(LPCWSTR wimPath, DWORD imageIndex, LPCWSTR installPath) {
    g_dwLastProgressPercent = (DWORD)-1;  // 重置进度记录

    DWORD creationResult = 0;
    // 使用验证标志打开WIM文件 (修复高压缩比问题)
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING,
        0x20000000, // WIM_FLAG_VERIFY
        0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\r\n", GetLastError());
        return FALSE;
    }

    // 设置临时目录
    WCHAR tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        pfnWIMSetTemporaryPath(hWim, tempPath);
    }

    // 加载映像
    HANDLE hImage = pfnWIMLoadImage(hWim, imageIndex);
    if (hImage == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Loading image failed. Error: %lu\r\n", GetLastError());
        pfnWIMCloseHandle(hWim);
        return FALSE;
    }

    // 注册进度回调
    pfnWIMRegisterMessageCallback(hWim, (FARPROC)ProgressCallback, NULL);

    SafePrintf(L"Progress: 0%%\r");

    // 应用映像
    BOOL bResult = FALSE;
    if (pfnWIMApplyImage(hImage, installPath, 0x00000100)) {
        SafePrintf(L"Image installation successful\r\n");
        bResult = TRUE;
    }
    else {
        SafePrintf(L"Image application failed. Error: %lu\r\n", GetLastError());
    }

    // 清理资源
    pfnWIMUnregisterMessageCallback(hWim, (FARPROC)ProgressCallback);
    pfnWIMCloseHandle(hImage);
    pfnWIMCloseHandle(hWim);
    return bResult;
}

// 获取镜像数量
DWORD GetImageCount(LPCWSTR wimPath) {
    DWORD creationResult = 0;
    // 使用验证标志打开WIM文件 (修复高压缩比问题)
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING,
        0x20000000, // WIM_FLAG_VERIFY
        0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\r\n", GetLastError());
        return 0;
    }

    DWORD count = pfnWIMGetImageCount(hWim);
    SafePrintf(L"Image count: %lu\r\n", count);

    pfnWIMCloseHandle(hWim);
    return count;
}

// 从XML字符串中提取信息
LPWSTR ExtractInfo(LPCWSTR xml, LPCWSTR tag) {
    WCHAR startTag[128] = { 0 };
    WCHAR endTag[128] = { 0 };
    swprintf_s(startTag, L"<%s>", tag);
    swprintf_s(endTag, L"</%s>", tag);

    LPCWSTR start = wcsstr(xml, startTag);
    if (!start) return NULL;
    start += wcslen(startTag);

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
    // 使用验证标志打开WIM文件 (修复高压缩比问题)
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING,
        0x20000000, // WIM_FLAG_VERIFY
        0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\r\n", GetLastError());
        return;
    }

    PVOID pvImageInfo = NULL;
    DWORD cbImageInfo = 0;
    if (!pfnWIMGetImageInformation(hWim, &pvImageInfo, &cbImageInfo)) {
        SafePrintf(L"Failed to get image info. Error: %lu\r\n", GetLastError());
        pfnWIMCloseHandle(hWim);
        return;
    }

    // 在整个XML中查找指定镜像
    LPCWSTR xmlInfo = (LPCWSTR)pvImageInfo;
    WCHAR imageTag[128];
    swprintf_s(imageTag, L"<IMAGE INDEX=\"%lu\"", imageIndex);
    LPCWSTR imageStart = wcsstr(xmlInfo, imageTag);
    if (!imageStart) {
        SafePrintf(L"Image index %lu not found\r\n", imageIndex);
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }

    // 提取镜像内容
    LPCWSTR contentStart = wcschr(imageStart, L'>');
    if (!contentStart) {
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }
    contentStart++;

    LPCWSTR contentEnd = wcsstr(contentStart, L"</IMAGE>");
    if (!contentEnd) {
        LocalFree(pvImageInfo);
        pfnWIMCloseHandle(hWim);
        return;
    }

    size_t contentLen = contentEnd - contentStart;
    LPWSTR imageXml = (LPWSTR)LocalAlloc(LPTR, (contentLen + 1) * sizeof(WCHAR));
    if (imageXml) {
        wcsncpy_s(imageXml, contentLen + 1, contentStart, contentLen);

        // 提取信息
        LPWSTR name = ExtractInfo(imageXml, L"DISPLAYNAME");
        if (!name) name = ExtractInfo(imageXml, L"NAME");
        LPWSTR version = GetFormattedVersion(imageXml);
        LPWSTR lang = ExtractInfo(imageXml, L"LANGUAGE");
        LPWSTR arch = ExtractInfo(imageXml, L"ARCH");
        LPWSTR byte = ExtractInfo(imageXml, L"TOTALBYTES");

        // 输出镜像信息
        SafePrintf(L"Image Information (Index %lu):\r\n", imageIndex);
        if (name) SafePrintf(L"  Name: %s\r\n", name);
        if (version) SafePrintf(L"  Version: %s\r\n", version);
        if (lang) SafePrintf(L"  Language: %s\r\n", lang);
        if (arch) SafePrintf(L"  Architecture: %s\r\n", GetArchitectureString(arch));
        if (byte) SafePrintf(L"  Byte: %s\r\n", byte);

        // 清理资源
        SafeFree(name);
        SafeFree(version);
        SafeFree(lang);
        SafeFree(arch);
        SafeFree(byte);
        LocalFree(imageXml);
    }

    LocalFree(pvImageInfo);
    pfnWIMCloseHandle(hWim);
}

// 设置镜像元数据
BOOL SetImageMetadata(HANDLE hWim, DWORD imageIndex, LPCWSTR imageName) {
    PVOID pvImageInfo = NULL;
    DWORD cbImageInfo = 0;
    if (!pfnWIMGetImageInformation(hWim, &pvImageInfo, &cbImageInfo)) {
        return FALSE;
    }

    // 转换为可修改的字符串
    std::wstring xmlInfo((LPCWSTR)pvImageInfo);
    LocalFree(pvImageInfo);

    // 构建目标镜像标签
    WCHAR imageTag[128];
    swprintf_s(imageTag, L"<IMAGE INDEX=\"%lu\"", imageIndex);
    size_t imageStart = xmlInfo.find(imageTag);
    if (imageStart == std::wstring::npos) {
        return FALSE;
    }

    // 查找IMAGE结束位置
    size_t imageEnd = xmlInfo.find(L"</IMAGE>", imageStart);
    if (imageEnd == std::wstring::npos) {
        return FALSE;
    }
    imageEnd += wcslen(L"</IMAGE>");

    // 提取镜像XML片段
    std::wstring imageXml = xmlInfo.substr(imageStart, imageEnd - imageStart);

    // 更新名称和描述
    size_t namePos = imageXml.find(L"<NAME>");
    if (namePos != std::wstring::npos) {
        size_t nameEnd = imageXml.find(L"</NAME>", namePos);
        if (nameEnd != std::wstring::npos) {
            imageXml.replace(namePos + 6, nameEnd - namePos - 6, imageName);
        }
    }
    else {
        size_t insertPos = imageXml.find(L'>') + 1;
        imageXml.insert(insertPos, L"<NAME>" + std::wstring(imageName) + L"</NAME>\r\n");
    }

    // 替换回原始XML
    xmlInfo.replace(imageStart, imageEnd - imageStart, imageXml);

    // 设置回WIM文件
    return pfnWIMSetImageInformation(hWim, (PVOID)xmlInfo.c_str(),
        (DWORD)(xmlInfo.size() * sizeof(WCHAR)));
}

// 备份系统镜像
BOOL PackImage(LPCWSTR compression, LPCWSTR sourcePath, LPCWSTR backupPath, LPCWSTR imageName) {
    g_dwLastProgressPercent = (DWORD)-1;

    // 压缩类型映射
    static const struct {
        LPCWSTR name;
        DWORD type;
    } compressionMap[] = {
        {L"none",  0},  // WIM_COMPRESS_NONE
        {L"xpress",1},  // WIM_COMPRESS_XPRESS
        {L"lzx",   2},  // WIM_COMPRESS_LZX
        {L"lzms",  3},  // WIM_COMPRESS_LZMS
        {NULL, 0}
    };

    DWORD compressionType = (DWORD)-1;
    for (int i = 0; compressionMap[i].name; i++) {
        if (_wcsicmp(compression, compressionMap[i].name) == 0) {
            compressionType = compressionMap[i].type;
            break;
        }
    }

    if (compressionType == (DWORD)-1) {
        SafePrintf(L"Invalid compression: %s\r\nValid: none, xpress, lzx, lzms\r\n", compression);
        return FALSE;
    }

    // 检查文件是否存在
    BOOL fileExists = (GetFileAttributesW(backupPath) != INVALID_FILE_ATTRIBUTES);
    DWORD creationDisposition = fileExists ? OPEN_EXISTING : CREATE_ALWAYS;

    // 对于现有文件使用验证标志 (修复高压缩比问题)
    DWORD flags = 0;
    if (fileExists) {
        flags = 0x20000000; // WIM_FLAG_VERIFY
    }

    DWORD creationResult = 0;
    HANDLE hWim = pfnWIMCreateFile(
        backupPath,
        GENERIC_READ | GENERIC_WRITE,
        creationDisposition,
        flags,
        fileExists ? 0 : compressionType,
        &creationResult
    );

    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to %s backup file. Error: %lu\r\n",
            fileExists ? L"open" : L"create", GetLastError());
        return FALSE;
    }

    // 设置临时目录
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    pfnWIMSetTemporaryPath(hWim, tempPath);

    // 注册进度回调
    pfnWIMRegisterMessageCallback(hWim, (FARPROC)ProgressCallback, NULL);

    SafePrintf(L"Progress: 0%%\r");

    // 捕获镜像
    HANDLE hImage = pfnWIMCaptureImage(hWim, sourcePath, 0);

    BOOL bResult = FALSE;
    if (hImage != INVALID_HANDLE_VALUE) {
        // 设置镜像元数据
        DWORD imageCount = pfnWIMGetImageCount(hWim);
        if (imageCount > 0) {
            SetImageMetadata(hWim, imageCount, imageName);
        }

        bResult = TRUE;
        pfnWIMCloseHandle(hImage);
        SafePrintf(L"Image backup successful\r\n");
    }
    else {
        SafePrintf(L"Backup failed. Error: %lu\r\n", GetLastError());
    }

    // 清理资源
    pfnWIMUnregisterMessageCallback(hWim, (FARPROC)ProgressCallback);
    pfnWIMCloseHandle(hWim);
    return bResult;
}

// 显示帮助信息
void ShowHelp() {
    const wchar_t* helpText = L"Usage: wimgapi-cmd.exe [options]\r\n"
        L"Options:\r\n"
        L"  -install <image_path> <image_index> <install_path> : Install image to target path\r\n"
        L"  -info <image_path> : Show number of images in WIM file\r\n"
        L"  -info <image_path> <image_index> : Show image information\r\n"
        L"  -pack <compression_level> <source_path> <backup_path> <image_name> : Backup system\r\n"
        L"      compression_level: none, xpress, lzx, lzms\r\n"
        L"      source_path: C:\\\r\n"
        L"      backup_path: D:\\backup.wim or D:\\backup.esd\r\n"
        L"      image_name: Name for the backup image (used for all metadata fields)\r\n"
        L"  Note: If backup_path exists, a new image will be added to it instead of overwriting\r\n"
        L"  help or /? : Display this help message\r\n";

    SafeWriteConsole(helpText);
}

int wmain(int argc, wchar_t* argv[]) {
    // 设置控制台编码为UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // 检测输出类型（用于进度显示）
    g_IsConsole = (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR);

    // 加载wimgapi.dll
    HMODULE hWimgapi = LoadWimgapiDLL();
    if (!hWimgapi || !InitWimgapiFunctions(hWimgapi)) {
        SafePrintf(L"Failed to load wimgapi.dll. Error: %lu\r\n", GetLastError());
        return 1;
    }

    // 命令解析
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
    else if (_wcsicmp(argv[1], L"-pack") == 0 && argc == 6) {
        if (!PackImage(argv[2], argv[3], argv[4], argv[5])) {
            return 1;
        }
    }
    else if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"/?") == 0) {
        ShowHelp();
    }
    else {
        SafePrintf(L"Invalid command\r\n");
        ShowHelp();
        return 1;
    }

    FreeLibrary(hWimgapi);
    return 0;
}
