const std = @import("std");
pub const w = std.os.windows;

pub const BOOL = w.BOOL;
pub const DWORD = w.DWORD;
pub const WORD = w.WORD;
pub const HANDLE = w.HANDLE;
pub const HWND = ?*anyopaque;
pub const HMODULE = w.HMODULE;
pub const HRESULT = i32;
pub const LPVOID = w.LPVOID;
pub const LPCVOID = w.LPCVOID;
pub const LPCWSTR = w.LPCWSTR;
pub const LPWSTR = w.LPWSTR;
pub const PSID = ?*anyopaque;
pub const PSECURITY_DESCRIPTOR = ?*anyopaque;
pub const PACL = ?*anyopaque;
pub const SIZE_T = w.SIZE_T;
pub const ULONG_PTR = usize;
pub const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(std.math.maxInt(usize));

pub const TRUE: BOOL = BOOL.TRUE;
pub const FALSE: BOOL = BOOL.FALSE;

pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_ALREADY_EXISTS: DWORD = 183;
pub const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
pub const ERROR_BROKEN_PIPE: DWORD = 109;
pub const WAIT_TIMEOUT: DWORD = 258;
pub const STILL_ACTIVE: DWORD = 259;

pub const MAX_PATH: usize = 260;

pub const GENERIC_READ: DWORD = 0x80000000;
pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const GENERIC_EXECUTE: DWORD = 0x20000000;
pub const GENERIC_ALL: DWORD = 0x10000000;
pub const FILE_SHARE_READ: DWORD = 0x00000001;
pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
pub const FILE_SHARE_DELETE: DWORD = 0x00000004;
pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x00000010;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;
pub const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x00000400;
pub const INVALID_FILE_ATTRIBUTES: DWORD = 0xFFFFFFFF;
pub const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;

pub const PIPE_ACCESS_DUPLEX: DWORD = 0x00000003;
pub const FILE_FLAG_FIRST_PIPE_INSTANCE: DWORD = 0x00080000;
pub const FILE_FLAG_OVERLAPPED: DWORD = 0x40000000;
pub const PIPE_TYPE_BYTE: DWORD = 0x00000000;
pub const PIPE_READMODE_BYTE: DWORD = 0x00000000;
pub const PIPE_TYPE_MESSAGE: DWORD = 0x00000004;
pub const PIPE_READMODE_MESSAGE: DWORD = 0x00000002;
pub const PIPE_WAIT: DWORD = 0x00000000;
pub const PIPE_REJECT_REMOTE_CLIENTS: DWORD = 0x00000008;

pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;
pub const CREATE_NO_WINDOW: DWORD = 0x08000000;
pub const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;

pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x00020002;
pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x00020007;
pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x00020009;
pub const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002000E;
pub const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: DWORD = 0x00000001;

pub const MITIGATION_DEP_ENABLE: u64 = 0x01;
pub const MITIGATION_SEHOP_ENABLE: u64 = 0x04;
pub const MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 0x1 << 8;
pub const MITIGATION_HEAP_TERMINATE_ALWAYS_ON: u64 = 0x1 << 12;
pub const MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 0x1 << 16;
pub const MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 0x1 << 20;
pub const MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 0x1 << 32;
pub const MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 = 0x1 << 36;
pub const MITIGATION_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64 = 0x1 << 28;
pub const MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x1 << 44;
pub const MITIGATION_FONT_DISABLE_ALWAYS_ON: u64 = 0x1 << 48;
pub const MITIGATION2_CET_USER_SHADOW_STACKS_ALWAYS_ON: u64 = 0x1 << 28;

pub const ProcessUserShadowStackPolicy: i32 = 15;
pub const ProcessUserPointerAuthPolicy: i32 = 17;

pub const JobObjectBasicAccountingInformation: i32 = 1;
pub const JobObjectAssociateCompletionPortInformation: i32 = 7;
pub const JobObjectExtendedLimitInformation: i32 = 9;
pub const JobObjectCpuRateControlInformation: i32 = 15;

pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x00000008;
pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: DWORD = 0x00000100;
pub const JOB_OBJECT_LIMIT_JOB_MEMORY: DWORD = 0x00000200;
pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: DWORD = 0x00000400;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;

pub const JOB_OBJECT_CPU_RATE_CONTROL_ENABLE: DWORD = 0x1;
pub const JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP: DWORD = 0x4;

pub const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: usize = 4;
pub const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: usize = 9;
pub const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: usize = 10;

pub const TOKEN_QUERY: DWORD = 0x0008;
pub const TOKEN_DUPLICATE: DWORD = 0x0002;
pub const TOKEN_ASSIGN_PRIMARY: DWORD = 0x0001;
pub const TOKEN_ADJUST_DEFAULT: DWORD = 0x0080;
pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const DISABLE_MAX_PRIVILEGE: DWORD = 0x1;
pub const TokenUser: i32 = 1;
pub const TokenIntegrityLevel: i32 = 25;
pub const WinLowLabelSid: i32 = 66;
pub const SE_GROUP_INTEGRITY: DWORD = 0x00000020;
pub const SE_GROUP_INTEGRITY_ENABLED: DWORD = 0x00000040;

pub const SDDL_REVISION_1: DWORD = 1;
pub const SE_FILE_OBJECT: i32 = 1;
pub const SE_KERNEL_OBJECT: i32 = 6;
pub const DACL_SECURITY_INFORMATION: DWORD = 0x00000004;
pub const PROTECTED_DACL_SECURITY_INFORMATION: DWORD = 0x80000000;

pub const TRUSTEE_IS_SID: i32 = 0;
pub const TRUSTEE_IS_WELL_KNOWN_GROUP: i32 = 5;
pub const NO_MULTIPLE_TRUSTEE: i32 = 0;
pub const SET_ACCESS: i32 = 2;
pub const REVOKE_ACCESS: i32 = 4;
pub const NO_INHERITANCE: DWORD = 0x0;
pub const SUB_CONTAINERS_AND_OBJECTS_INHERIT: DWORD = 0x3;

pub const PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE: DWORD = 44;

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD,
    lpSecurityDescriptor: PSECURITY_DESCRIPTOR,
    bInheritHandle: BOOL,
};

pub const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?LPWSTR = null,
    lpDesktop: ?LPWSTR = null,
    lpTitle: ?LPWSTR = null,
    dwX: DWORD = 0,
    dwY: DWORD = 0,
    dwXSize: DWORD = 0,
    dwYSize: DWORD = 0,
    dwXCountChars: DWORD = 0,
    dwYCountChars: DWORD = 0,
    dwFillAttribute: DWORD = 0,
    dwFlags: DWORD = 0,
    wShowWindow: WORD = 0,
    cbReserved2: WORD = 0,
    lpReserved2: ?*u8 = null,
    hStdInput: ?HANDLE = null,
    hStdOutput: ?HANDLE = null,
    hStdError: ?HANDLE = null,
};

pub const STARTUPINFOEXW = extern struct {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: ?*anyopaque,
};

pub const PROCESS_INFORMATION = extern struct {
    hProcess: ?HANDLE,
    hThread: ?HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

pub const SECURITY_CAPABILITIES = extern struct {
    AppContainerSid: PSID,
    Capabilities: ?*SID_AND_ATTRIBUTES,
    CapabilityCount: DWORD,
    Reserved: DWORD,
};

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: PSID,
    Attributes: DWORD,
};

pub const TOKEN_MANDATORY_LABEL = extern struct {
    Label: SID_AND_ATTRIBUTES,
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
};

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: SIZE_T,
    MaximumWorkingSetSize: SIZE_T,
    ActiveProcessLimit: DWORD,
    Affinity: ULONG_PTR,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: SIZE_T,
    JobMemoryLimit: SIZE_T,
    PeakProcessMemoryUsed: SIZE_T,
    PeakJobMemoryUsed: SIZE_T,
};

pub const JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = extern struct {
    TotalUserTime: i64,
    TotalKernelTime: i64,
    ThisPeriodTotalUserTime: i64,
    ThisPeriodTotalKernelTime: i64,
    TotalPageFaultCount: DWORD,
    TotalProcesses: DWORD,
    ActiveProcesses: DWORD,
    TotalTerminatedProcesses: DWORD,
};

pub const JOBOBJECT_ASSOCIATE_COMPLETION_PORT = extern struct {
    CompletionKey: ?*anyopaque,
    CompletionPort: HANDLE,
};

pub const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = extern struct {
    ControlFlags: DWORD,
    CpuRate: DWORD,
};

pub const TRUSTEE_W = extern struct {
    pMultipleTrustee: ?*TRUSTEE_W,
    MultipleTrusteeOperation: i32,
    TrusteeForm: i32,
    TrusteeType: i32,
    ptstrName: ?*anyopaque,
};

pub const EXPLICIT_ACCESS_W = extern struct {
    grfAccessPermissions: DWORD,
    grfAccessMode: i32,
    grfInheritance: DWORD,
    Trustee: TRUSTEE_W,
};

pub const SYSTEM_INFO = extern struct {
    wProcessorArchitecture: WORD,
    wReserved: WORD,
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: ?*anyopaque,
    lpMaximumApplicationAddress: ?*anyopaque,
    dwActiveProcessorMask: ULONG_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
};

pub const OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: DWORD,
    dwMajorVersion: DWORD,
    dwMinorVersion: DWORD,
    dwBuildNumber: DWORD,
    dwPlatformId: DWORD,
    szCSDVersion: [128]u16,
};

pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;
pub extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
pub extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.winapi) ?*anyopaque;
pub extern "kernel32" fn GetNativeSystemInfo(lpSystemInfo: *SYSTEM_INFO) callconv(.winapi) void;
pub extern "kernel32" fn IsWow64Process2(hProcess: HANDLE, pProcessMachine: *WORD, pNativeMachine: ?*WORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn IsProcessorFeaturePresent(ProcessorFeature: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetProcessMitigationPolicy(hProcess: HANDLE, MitigationPolicy: i32, lpBuffer: LPVOID, dwLength: SIZE_T) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateFileW(lpFileName: LPCWSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: ?*SECURITY_ATTRIBUTES, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: ?HANDLE) callconv(.winapi) HANDLE;
pub extern "kernel32" fn GetFileAttributesW(lpFileName: LPCWSTR) callconv(.winapi) DWORD;
pub extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreatePipe(hReadPipe: *HANDLE, hWritePipe: *HANDLE, lpPipeAttributes: ?*SECURITY_ATTRIBUTES, nSize: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn SetHandleInformation(hObject: HANDLE, dwMask: DWORD, dwFlags: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn CreateNamedPipeW(lpName: LPCWSTR, dwOpenMode: DWORD, dwPipeMode: DWORD, nMaxInstances: DWORD, nOutBufferSize: DWORD, nInBufferSize: DWORD, nDefaultTimeOut: DWORD, lpSecurityAttributes: ?*SECURITY_ATTRIBUTES) callconv(.winapi) HANDLE;

pub extern "kernel32" fn CreateJobObjectW(lpJobAttributes: ?*SECURITY_ATTRIBUTES, lpName: ?LPCWSTR) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn SetInformationJobObject(hJob: HANDLE, JobObjectInformationClass: i32, lpJobObjectInformation: LPCVOID, cbJobObjectInformationLength: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn QueryInformationJobObject(hJob: ?HANDLE, JobObjectInformationClass: i32, lpJobObjectInformation: LPVOID, cbJobObjectInformationLength: DWORD, lpReturnLength: ?*DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) callconv(.winapi) BOOL;
pub extern "kernel32" fn TerminateJobObject(hJob: HANDLE, uExitCode: DWORD) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateIoCompletionPort(FileHandle: HANDLE, ExistingCompletionPort: ?HANDLE, CompletionKey: ULONG_PTR, NumberOfConcurrentThreads: DWORD) callconv(.winapi) ?HANDLE;
pub extern "kernel32" fn GetQueuedCompletionStatus(CompletionPort: HANDLE, lpNumberOfBytesTransferred: *DWORD, lpCompletionKey: *ULONG_PTR, lpOverlapped: *?*anyopaque, dwMilliseconds: DWORD) callconv(.winapi) BOOL;

pub extern "kernel32" fn InitializeProcThreadAttributeList(lpAttributeList: ?*anyopaque, dwAttributeCount: DWORD, dwFlags: DWORD, lpSize: *SIZE_T) callconv(.winapi) BOOL;
pub extern "kernel32" fn UpdateProcThreadAttribute(lpAttributeList: *anyopaque, dwFlags: DWORD, Attribute: ULONG_PTR, lpValue: ?*const anyopaque, cbSize: SIZE_T, lpPreviousValue: ?*anyopaque, lpReturnSize: ?*SIZE_T) callconv(.winapi) BOOL;
pub extern "kernel32" fn DeleteProcThreadAttributeList(lpAttributeList: *anyopaque) callconv(.winapi) void;

pub extern "kernel32" fn CreateProcessW(lpApplicationName: ?LPCWSTR, lpCommandLine: ?LPWSTR, lpProcessAttributes: ?*SECURITY_ATTRIBUTES, lpThreadAttributes: ?*SECURITY_ATTRIBUTES, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: ?LPCVOID, lpCurrentDirectory: ?LPCWSTR, lpStartupInfo: *STARTUPINFOW, lpProcessInformation: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
pub extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(.winapi) DWORD;
pub extern "kernel32" fn TerminateProcess(hProcess: HANDLE, uExitCode: DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *DWORD) callconv(.winapi) BOOL;
pub extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
pub extern "kernel32" fn LoadLibraryW(lpLibFileName: LPCWSTR) callconv(.winapi) ?HMODULE;
pub extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) BOOL;

pub extern "advapi32" fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetTokenInformation(TokenHandle: HANDLE, TokenInformationClass: i32, TokenInformation: ?LPVOID, TokenInformationLength: DWORD, ReturnLength: *DWORD) callconv(.winapi) BOOL;
pub extern "advapi32" fn SetTokenInformation(TokenHandle: HANDLE, TokenInformationClass: i32, TokenInformation: LPCVOID, TokenInformationLength: DWORD) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateRestrictedToken(ExistingTokenHandle: HANDLE, Flags: DWORD, DisableSidCount: DWORD, SidsToDisable: ?*anyopaque, DeletePrivilegeCount: DWORD, PrivilegesToDelete: ?*anyopaque, RestrictedSidCount: DWORD, SidsToRestrict: ?*anyopaque, NewTokenHandle: *HANDLE) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateProcessAsUserW(hToken: ?HANDLE, lpApplicationName: ?LPCWSTR, lpCommandLine: ?LPWSTR, lpProcessAttributes: ?*SECURITY_ATTRIBUTES, lpThreadAttributes: ?*SECURITY_ATTRIBUTES, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: ?LPCVOID, lpCurrentDirectory: ?LPCWSTR, lpStartupInfo: *STARTUPINFOW, lpProcessInformation: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
pub extern "advapi32" fn CreateWellKnownSid(WellKnownSidType: i32, DomainSid: PSID, pSid: PSID, cbSid: *DWORD) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertSidToStringSidW(Sid: PSID, StringSid: *LPWSTR) callconv(.winapi) BOOL;
pub extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor: LPCWSTR, StringSDRevision: DWORD, SecurityDescriptor: *PSECURITY_DESCRIPTOR, SecurityDescriptorSize: ?*DWORD) callconv(.winapi) BOOL;
pub extern "advapi32" fn GetSecurityDescriptorDacl(pSecurityDescriptor: PSECURITY_DESCRIPTOR, lpbDaclPresent: *BOOL, pDacl: *PACL, lpbDaclDefaulted: *BOOL) callconv(.winapi) BOOL;
pub extern "advapi32" fn SetNamedSecurityInfoW(pObjectName: LPWSTR, ObjectType: i32, SecurityInfo: DWORD, psidOwner: PSID, psidGroup: PSID, pDacl: PACL, pSacl: PACL) callconv(.winapi) DWORD;
pub extern "advapi32" fn GetNamedSecurityInfoW(pObjectName: LPCWSTR, ObjectType: i32, SecurityInfo: DWORD, ppsidOwner: ?*PSID, ppsidGroup: ?*PSID, ppDacl: ?*PACL, ppSacl: ?*PACL, ppSecurityDescriptor: *PSECURITY_DESCRIPTOR) callconv(.winapi) DWORD;
pub extern "advapi32" fn SetSecurityInfo(handle: HANDLE, ObjectType: i32, SecurityInfo: DWORD, psidOwner: PSID, psidGroup: PSID, pDacl: PACL, pSacl: PACL) callconv(.winapi) DWORD;
pub extern "advapi32" fn SetEntriesInAclW(cCountOfExplicitEntries: DWORD, pListOfExplicitEntries: *EXPLICIT_ACCESS_W, OldAcl: PACL, NewAcl: *PACL) callconv(.winapi) DWORD;
pub extern "advapi32" fn FreeSid(pSid: PSID) callconv(.winapi) ?*anyopaque;

pub extern "userenv" fn CreateAppContainerProfile(pszAppContainerName: LPCWSTR, pszDisplayName: LPCWSTR, pszDescription: LPCWSTR, pCapabilities: ?*anyopaque, dwCapabilityCount: DWORD, ppSidAppContainerSid: *PSID) callconv(.winapi) HRESULT;
pub extern "userenv" fn DeriveAppContainerSidFromAppContainerName(pszAppContainerName: LPCWSTR, ppsidAppContainerSid: *PSID) callconv(.winapi) HRESULT;
pub extern "userenv" fn DeleteAppContainerProfile(pszAppContainerName: LPCWSTR) callconv(.winapi) HRESULT;

pub extern "ntdll" fn RtlGetVersion(lpVersionInformation: *OSVERSIONINFOW) callconv(.winapi) i32;
