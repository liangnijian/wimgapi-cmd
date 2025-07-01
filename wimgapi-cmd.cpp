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
WIMCaptureImagePtr pfnWIMCaptureImage = NULL; // 修正为3个参数
WIMSetImageInformationPtr pfnWIMSetImageInformation = NULL; // 新增函数指针

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
    pfnWIMCaptureImage = (WIMCaptureImagePtr)GetProcAddress(hDll, "WIMCaptureImage"); // 修正为3个参数
    pfnWIMSetImageInformation = (WIMSetImageInformationPtr)GetProcAddress(hDll, "WIMSetImageInformation"); // 新增函数

    if (!pfnWIMCreateFile) wprintf(L"Failed to load WIMCreateFile\n");
    if (!pfnWIMLoadImage) wprintf(L"Failed to load WIMLoadImage\n");
    if (!pfnWIMApplyImage) wprintf(L"Failed to load WIMApplyImage\n");
    if (!pfnWIMGetImageCount) wprintf(L"Failed to load WIMGetImageCount\n");
    if (!pfnWIMGetImageInformation) wprintf(L"Failed to load WIMGetImageInformation\n");
    if (!pfnWIMCloseHandle) wprintf(L"Failed to load WIMCloseHandle\n");
    if (!pfnWIMSetTemporaryPath) wprintf(L"Failed to load WIMSetTemporaryPath\n");
    if (!pfnWIMCaptureImage) wprintf(L"Failed to load WIMCaptureImage\n");
    if (!pfnWIMSetImageInformation) wprintf(L"Failed to load WIMSetImageInformation\n");

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
    if (dwMessageId == WIM_MSG_PROGRESS) {
        DWORD dwPercent = (DWORD)wParam;
        SafePrintf(L"\rProgress: %lu%%", dwPercent);
    }
    return 0;
}

// 安装镜像
BOOL InstallImage(LPCWSTR wimPath, DWORD imageIndex, LPCWSTR installPath) {
    // 打开WIM文件
    DWORD creationResult = 0;
    HANDLE hWim = pfnWIMCreateFile(wimPath, GENERIC_READ, OPEN_EXISTING, 0, 0, &creationResult);
    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to open WIM file. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // 设置临时目录
    BOOL bResult = FALSE;
    WCHAR tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath)) {
        if (!pfnWIMSetTemporaryPath(hWim, tempPath)) {
            SafePrintf(L"Setting temporary directory failed. Error: %lu\n", GetLastError());
        }
    }

    // 加载映像
    HANDLE hImage = pfnWIMLoadImage(hWim, imageIndex);
    if (hImage == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Loading image failed. Error: %lu\n", GetLastError());
        goto CLEANUP;
    }

    // 注册进度回调
    pfnWIMRegisterMessageCallback(hWim, (FARPROC)ProgressCallback, NULL);

    SafePrintf(L"Apply the %s to %s\n", (LPCWSTR)wimPath, (LPCWSTR)installPath);
    SafePrintf(L"Progress: 0%%");

    // 应用映像
    if (pfnWIMApplyImage(hImage, installPath, 0x00000100)) {
        SafePrintf(L"\nImage applied successfully\n");
        bResult = TRUE;
    }
    else {
        SafePrintf(L"\nImage application failed. Error: %lu\n", GetLastError());
    }

    // 注销进度回调
    pfnWIMUnregisterMessageCallback(hWim, (FARPROC)ProgressCallback);

    // 关闭映像句柄
CLEANUP:
    pfnWIMCloseHandle(hImage);
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
        SafePrintf(L"Image information acquisition failed. Error: %lu\n", GetLastError());
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

// 设置镜像元数据
BOOL SetImageMetadata(HANDLE hWim, DWORD imageIndex, LPCWSTR imageName, LPCWSTR description) {
    // 获取整个WIM的XML信息
    PVOID pvImageInfo = NULL;
    DWORD cbImageInfo = 0;
    pfnWIMGetImageInformation(hWim, &pvImageInfo, &cbImageInfo);

    // 转换为可修改的字符串
    std::wstring xmlInfo((LPCWSTR)pvImageInfo);
    LocalFree(pvImageInfo);

    // 构建目标镜像标签
    WCHAR imageTag[128] = { 0 };
    swprintf_s(imageTag, _countof(imageTag), L"<IMAGE INDEX=\"%lu\"", imageIndex);

    // 查找目标镜像位置
    size_t imageStart = xmlInfo.find(imageTag);

    // 查找IMAGE结束位置
    size_t imageEnd = xmlInfo.find(L"</IMAGE>", imageStart);

    imageEnd += wcslen(L"</IMAGE>");

    // 提取镜像XML片段
    std::wstring imageXml = xmlInfo.substr(imageStart, imageEnd - imageStart);

    // 查找并替换或添加元数据
    auto UpdateOrAddTag = [&](const std::wstring& tag, const std::wstring& value) {
        size_t startTagPos = imageXml.find(L"<" + tag + L">");
        size_t endTagPos = imageXml.find(L"</" + tag + L">", startTagPos);

        if (startTagPos != std::wstring::npos && endTagPos != std::wstring::npos) {
            // 替换现有值
            size_t contentStart = startTagPos + tag.length() + 2;
            size_t contentLen = endTagPos - contentStart;
            imageXml.replace(contentStart, contentLen, value);
        }
        else {
            // 添加新标签
            size_t insertPos = imageXml.find(L'>') + 1;
            std::wstring newTag = L"<" + tag + L">" + value + L"</" + tag + L">\n";
            imageXml.insert(insertPos, newTag);
        }
        };

    // 更新映像名称、映像说明、显示名称、显示说明
    if (imageName && wcslen(imageName) > 0) {
        UpdateOrAddTag(L"NAME", imageName);
        UpdateOrAddTag(L"DESCRIPTION", imageName);
        UpdateOrAddTag(L"DISPLAYNAME", imageName);
        UpdateOrAddTag(L"DISPLAYDESCRIPTION", imageName);
    }

    // 替换XML中的镜像片段
    xmlInfo.replace(imageStart, imageEnd - imageStart, imageXml);

    // 设置回WIM文件
    if (!pfnWIMSetImageInformation(hWim, (PVOID)xmlInfo.c_str(), (DWORD)((xmlInfo.length() + 1) * sizeof(WCHAR)))) {
        SafePrintf(L"Failed to set image information. Error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// 备份系统镜像
BOOL PackImage(LPCWSTR compression, LPCWSTR sourcePath, LPCWSTR backupPath, LPCWSTR imageName) {
    // 解析压缩等级
    DWORD compressionType = 0;
    if (_wcsicmp(compression, L"none") == 0) {
        compressionType = 0;
    }
    else if (_wcsicmp(compression, L"fast") == 0) {
        compressionType = 1;
    }
    else if (_wcsicmp(compression, L"max") == 0) {
        compressionType = 2;
    }
    else {
        SafePrintf(L"Invalid compression level: %s\n", compression);
        return FALSE;
    }

    // 获取后缀名，如果是esd就加大剂量
    LPCWSTR ext = wcsrchr(backupPath, L'.');
    if (ext && _wcsicmp(ext, L".esd") == 0) {
        if (_wcsicmp(compression, L"none") == 0) {
            compressionType = 1;
        }
        else if (_wcsicmp(compression, L"fast") == 0) {
            compressionType = 2;
        }
        else if (_wcsicmp(compression, L"max") == 0) {
            compressionType = 3;
        }
    }

    // 检查备份文件是否存在
    DWORD fileAttrib = GetFileAttributesW(backupPath);
    BOOL fileExists = (fileAttrib != INVALID_FILE_ATTRIBUTES && !(fileAttrib & FILE_ATTRIBUTE_DIRECTORY));

    // 设置WIM创建参数
    DWORD creationDisposition = fileExists ? OPEN_EXISTING : CREATE_ALWAYS;
    DWORD creationResult = 0;

    // 打开或创建WIM文件
    HANDLE hWim = pfnWIMCreateFile(
        backupPath,
        GENERIC_READ | GENERIC_WRITE,
        creationDisposition,
        0,
        // 如果文件已存在，忽略压缩类型参数（使用原有压缩类型）
        fileExists ? 0 : compressionType,
        &creationResult
    );

    if (hWim == INVALID_HANDLE_VALUE) {
        SafePrintf(L"Failed to %s backup file. Error: %lu\n",
            fileExists ? L"open" : L"create", GetLastError());
        return FALSE;
    }

    // 提示用户操作类型
    if (fileExists) {
        SafePrintf(L"Adding new image to existing file: %s\n", backupPath);
    }
    else {
        SafePrintf(L"Creating new backup file: %s\n", backupPath);
    }

    // 设置临时目录
    WCHAR tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath)) {
        if (!pfnWIMSetTemporaryPath(hWim, tempPath)) {
            SafePrintf(L"Setting temporary directory failed. Error: %lu\n", GetLastError());
            return FALSE;
        }
    }

    // 注册进度回调
    pfnWIMRegisterMessageCallback(hWim, (FARPROC)ProgressCallback, NULL);

    SafePrintf(L"Starting backup from %s to %s\n", sourcePath, backupPath);
    SafePrintf(L"Progress: 0%%");

    // 捕获映像
    HANDLE hImage = pfnWIMCaptureImage(
        hWim,               // WIM句柄
        sourcePath,         // 源路径
        0                   // 捕获标志
    );

    BOOL bResult = FALSE;

    if (hImage != INVALID_HANDLE_VALUE) {
        // 获取新映像的索引
        DWORD imageCount = pfnWIMGetImageCount(hWim);

        // 设置映像元数据
        if (imageCount > 0) {
            SetImageMetadata(hWim, imageCount, imageName, imageName);
        }

        SafePrintf(L"\nImage backup successful\n");
        bResult = TRUE;
        pfnWIMCloseHandle(hImage);
    }
    else {
        SafePrintf(L"\nImage backup failed. Error: %lu\n", GetLastError());
    }

    // 注销回调
    pfnWIMUnregisterMessageCallback(hWim, (FARPROC)ProgressCallback);

    // 关闭WIM句柄
    pfnWIMCloseHandle(hWim);
    return bResult;
}

// 显示帮助信息
void ShowHelp() {
    const wchar_t* helpText = L"Usage: wimgapi-cmd.exe [options]\n"
        L"Options:\n"
        L"  -install <image_path> <image_index> <install_path> : Install image to target path\n"
        L"  -info <image_path> : Show number of images in WIM file\n"
        L"  -info <image_path> <image_index> : Show image information\n"
        L"  -pack <compression_level> <source_path> <backup_path> <image_name> : Backup system\n"
        L"      compression_level: none, fast, max\n"
        L"      source_path: e.g. C:\n"
        L"      backup_path: e.g. D:\\backup.wim or D:\\backup.esd\n"
        L"      image_name: Name for the backup image (used for all metadata fields)\n"
        L"  Note: If backup_path exists, a new image will be added to it instead of overwriting\n"
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
    else if (_wcsicmp(argv[1], L"-pack") == 0 && argc == 6) {
        if (!PackImage(argv[2], argv[3], argv[4], argv[5])) {
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
