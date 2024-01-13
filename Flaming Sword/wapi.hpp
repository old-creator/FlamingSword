#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <sddl.h>

//consts
#define NT_SUCCESS(status) ((status) >= 0)
#define SeTcbPrivilege 7
#define SeDebugPrivilege 20
#define SeImpersonatePrivilege 29

//main.cpp functions
HANDLE GetTrustedInstallerToken();
bool ImpersonateTcbToken();
bool EnablePrivilege(bool impersonating, int privilege_value);
void RunCommandLine(HANDLE token);

//Kernel32
CHAR strkernel32[] = { 'k' ,'e' ,'r' ,'n' ,'e' ,'l' ,'3' ,'2' ,'.' ,'d' ,'l' ,'l', '\00' };
HMODULE MyKernel32 = GetModuleHandleA(strkernel32);

//advapi32.dll
WCHAR stradvapi32[] = { 'A' ,'d' ,'v' ,'a' ,'p' ,'i' ,'3' ,'2' ,'.' ,'d' ,'l' ,'l', '\0' };;
HMODULE MyAdvapi32 = LoadLibraryW(stradvapi32);

//ntdll.dll
CHAR strntdll[] = { 'n' ,'t' ,'d' ,'l' ,'l' ,'.' ,'d' ,'l' ,'l', '\00' };
HMODULE MyNtdll = GetModuleHandleA(strntdll);

//RtlAdjustPrivilege
typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(int Privilege, bool Enable, bool ThreadPrivilege, bool* Previous);
CHAR strrtladjpriv[] = { 'R' ,'t' ,'l' ,'A' ,'d' ,'j' ,'u' ,'s' ,'t' ,'P' ,'r' ,'i' ,'v' ,'i' ,'l' ,'e' ,'g' ,'e', '\00' };
_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(MyNtdll, strrtladjpriv);

// LogonUserExExW
typedef BOOL(WINAPI* _LogonUserExExW)(
	_In_      LPTSTR        lpszUsername,
	_In_opt_  LPTSTR        lpszDomain,
	_In_opt_  LPTSTR        lpszPassword,
	_In_      DWORD         dwLogonType,
	_In_      DWORD         dwLogonProvider,
	_In_opt_  PTOKEN_GROUPS pTokenGroups,
	_Out_opt_ PHANDLE       phToken,
	_Out_opt_ PSID* ppLogonSid,
	_Out_opt_ PVOID* ppProfileBuffer,
	_Out_opt_ LPDWORD       pdwProfileLength,
	_Out_opt_ PQUOTA_LIMITS pQuotaLimits
	);
CHAR strlogonusrex[] = { 'L' ,'o' ,'g' ,'o' ,'n' ,'U' ,'s' ,'e' ,'r' ,'E' ,'x' ,'E' ,'x' ,'W', '\00' };
_LogonUserExExW LogonUserExExW = (_LogonUserExExW)GetProcAddress(MyAdvapi32, strlogonusrex);

//CloseHandle
typedef BOOL(WINAPI* _CloseHandle)(
	_In_ HANDLE hObject
);
CHAR strclosehandle[] = { 'C' ,'l' ,'o' ,'s' ,'e' ,'H' ,'a' ,'n' ,'d' ,'l' ,'e', '\00' };
_CloseHandle MyCloseHandle = (_CloseHandle)GetProcAddress(MyKernel32, strclosehandle);

//IsDebuggerPresent
typedef BOOL(WINAPI* _IsDebuggerPresent)();
CHAR strisdbg[] = { 'I' ,'s' ,'D' ,'e' ,'b' ,'u' ,'g' ,'g' ,'e' ,'r' ,'P' ,'r' ,'e' ,'s' ,'e' ,'n' ,'t', '\00' };
_IsDebuggerPresent MyIsDebuggerPresent = (_IsDebuggerPresent)GetProcAddress(MyKernel32, strisdbg);

//Process32FirstW
typedef BOOL(WINAPI* _Process32FirstW)(
	_In_      HANDLE            hSnapshot,
	_Out_ LPPROCESSENTRY32W lppe
);
CHAR strproc32first[] = { 'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'3' ,'2' ,'F' ,'i' ,'r' ,'s' ,'t' ,'W', '\00' };
_Process32FirstW MyProcess32FirstW = (_Process32FirstW)GetProcAddress(MyKernel32, strproc32first);

//Process32NextW
typedef BOOL(WINAPI* _Process32NextW)(
	_In_  HANDLE            hSnapshot,
	_Out_ LPPROCESSENTRY32W lppe
);
CHAR strproc32next[] = { 'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'3' ,'2' ,'N' ,'e' ,'x' ,'t' ,'W', '\00' };
_Process32NextW MyProcess32NextW = (_Process32NextW)GetProcAddress(MyKernel32, strproc32next);

//GetLastError
typedef DWORD(WINAPI* _GetLastError)();
CHAR strgetlasterror[] = { 'G' ,'e' ,'t' ,'L' ,'a' ,'s' ,'t' ,'E' ,'r' ,'r' ,'o' ,'r', '\00' };
_GetLastError MyGetLastError = (_GetLastError)GetProcAddress(MyKernel32, strgetlasterror);

//CreateToolhelp32Snapshot
typedef HANDLE(WINAPI* _CreateToolhelp32Snapshot)(
	_In_ DWORD dwFlags,
	_In_ DWORD th32ProcessID
);
CHAR strhelp32snapshot[] = { 'C' ,'r' ,'e' ,'a' ,'t' ,'e' ,'T' ,'o' ,'o' ,'l' ,'h' ,'e' ,'l' ,'p' ,'3' ,'2' ,'S' ,'n' ,'a' ,'p' ,'s' ,'h' ,'o' ,'t', '\00' };
_CreateToolhelp32Snapshot MyCreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(MyKernel32, strhelp32snapshot);

//OpenProcess
typedef HANDLE(WINAPI* _OpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL  bInheritHandle,
	_In_ DWORD dwProcessId
);
CHAR stropenproc[] = { 'O' ,'p' ,'e' ,'n' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s', '\00' };
_OpenProcess MyOpenProcess = (_OpenProcess)GetProcAddress(MyKernel32, stropenproc);

//GetModuleHandleW
typedef HMODULE(WINAPI* _GetModuleHandleW)(
	_In_opt_ LPCWSTR lpModuleName
);
CHAR strgetmodhandle[] = { 'G' ,'e' ,'t' ,'M' ,'o' ,'d' ,'u' ,'l' ,'e' ,'H' ,'a' ,'n' ,'d' ,'l' ,'e' ,'W', '\00' };
_GetModuleHandleW MyGetModuleHandleW = (_GetModuleHandleW)GetProcAddress(MyKernel32, strgetmodhandle);

//LocalAlloc
typedef HLOCAL(WINAPI* _LocalAlloc)(
	_In_ UINT   uFlags,
	_In_ SIZE_T uBytes
);
CHAR strlocalalloc[] = { 'L' ,'o' ,'c' ,'a' ,'l' ,'A' ,'l' ,'l' ,'o' ,'c', '\00' };
_LocalAlloc MyLocalAlloc = (_LocalAlloc)GetProcAddress(MyKernel32, strlocalalloc);

//InitializeSListHead
typedef void(WINAPI* _InitializeSListHead)(
	_Out_ PSLIST_HEADER ListHead
);
CHAR strinitlshead[] = { 'I' ,'n' ,'i' ,'t' ,'i' ,'a' ,'l' ,'i' ,'z' ,'e' ,'S' ,'L' ,'i' ,'s' ,'t' ,'H' ,'e' ,'a' ,'d', '\00' };
_InitializeSListHead MyInitializeSListHead = (_InitializeSListHead)GetProcAddress(MyKernel32, strinitlshead);

//GetSystemTimeAsFileTime
typedef void(WINAPI* _GetSystemTimeAsFileTime)(
	_Out_ LPFILETIME lpSystemTimeAsFileTime
);
CHAR strsystimeasfile[] = { 'G' ,'e' ,'t' ,'S' ,'y' ,'s' ,'t' ,'e' ,'m' ,'T' ,'i' ,'m' ,'e' ,'A' ,'s' ,'F' ,'i' ,'l' ,'e' ,'T' ,'i' ,'m' ,'e', '\00' };
_GetSystemTimeAsFileTime MyGetSystemTimeAsFileTime = (_GetSystemTimeAsFileTime)GetProcAddress(MyKernel32, strsystimeasfile);

//GetCurrentThreadId
typedef DWORD(WINAPI* _GetCurrentThreadId)();
CHAR strgetcurrthid[] = { 'G' ,'e' ,'t' ,'C' ,'u' ,'r' ,'r' ,'e' ,'n' ,'t' ,'T' ,'h' ,'r' ,'e' ,'a' ,'d' ,'I' ,'d', '\00' };
_GetCurrentThreadId MyGetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(MyKernel32, strgetcurrthid);

//GetCurrentProcessId
typedef DWORD(WINAPI* _GetCurrentProcessId)();
CHAR strgetcurrprid[] = { 'G' ,'e' ,'t' ,'C' ,'u' ,'r' ,'r' ,'e' ,'n' ,'t' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'I' ,'d', '\00' };
_GetCurrentProcessId MyGetCurrentProcessId = (_GetCurrentProcessId)GetProcAddress(MyKernel32, strgetcurrprid);

//QueryPerformanceCounter
typedef BOOL(WINAPI* _QueryPerformanceCounter)(
	_Out_ LARGE_INTEGER* lpPerformanceCount
);
CHAR strqeryprfcount[] = { 'Q' ,'u' ,'e' ,'r' ,'y' ,'P' ,'e' ,'r' ,'f' ,'o' ,'r' ,'m' ,'a' ,'n' ,'c' ,'e' ,'C' ,'o' ,'u' ,'n' ,'t' ,'e' ,'r', '\00' };
_QueryPerformanceCounter MyQueryPerformanceCounter = (_QueryPerformanceCounter)GetProcAddress(MyKernel32, strqeryprfcount);

//IsProcessorFeaturePresent
typedef BOOL(WINAPI* _IsProcessorFeaturePresent)(
	_In_ DWORD ProcessorFeature
);
CHAR strisprfeaturpres[] = { 'I' ,'s' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'o' ,'r' ,'F' ,'e' ,'a' ,'t' ,'u' ,'r' ,'e' ,'P' ,'r' ,'e' ,'s' ,'e' ,'n' ,'t', '\00' };
_IsProcessorFeaturePresent MyIsProcessorFeaturePresent = (_IsProcessorFeaturePresent)GetProcAddress(MyKernel32, strisprfeaturpres);

//TerminateProcess
typedef BOOL(WINAPI* _TerminateProcess)(
	_In_ HANDLE hProcess,
	_In_ UINT   uExitCode
);
CHAR strterminateproc[] = { 'T' ,'e' ,'r' ,'m' ,'i' ,'n' ,'a' ,'t' ,'e' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s', '\00' };
_TerminateProcess MyTerminateProcess = (_TerminateProcess)GetProcAddress(MyKernel32, strterminateproc);

//GetCurrentProcess
typedef HANDLE(WINAPI* _GetCurrentProcess)();
CHAR strgetcurrentproc[] = { 'G' ,'e' ,'t' ,'C' ,'u' ,'r' ,'r' ,'e' ,'n' ,'t' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s', '\00' };
_GetCurrentProcess MyGetCurrentProcess = (_GetCurrentProcess)GetProcAddress(MyKernel32, strgetcurrentproc);

//SetUnhandledExceptionFilter
typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI* _SetUnhandledExceptionFilter)(
	_In_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
);
CHAR strlptoplvlfl[] = { 'S' ,'e' ,'t' ,'U' ,'n' ,'h' ,'a' ,'n' ,'d' ,'l' ,'e' ,'d' ,'E' ,'x' ,'c' ,'e' ,'p' ,'t' ,'i' ,'o' ,'n' ,'F' ,'i' ,'l' ,'t' ,'e' ,'r', '\00' };
_SetUnhandledExceptionFilter MySetUnhandledExceptionFilter = (_SetUnhandledExceptionFilter)GetProcAddress(MyKernel32, strlptoplvlfl);

//UnhandledExceptionFilter
typedef LONG(WINAPI* _UnhandledExceptionFilter)(
	_In_ _EXCEPTION_POINTERS* ExceptionInfo
);
CHAR strunhandleexfl[] = { 'U' ,'n' ,'h' ,'a' ,'n' ,'d' ,'l' ,'e' ,'d' ,'E' ,'x' ,'c' ,'e' ,'p' ,'t' ,'i' ,'o' ,'n' ,'F' ,'i' ,'l' ,'t' ,'e' ,'r', '\00' };
_UnhandledExceptionFilter MyUnhandledExceptionFilter = (_UnhandledExceptionFilter)GetProcAddress(MyKernel32, strunhandleexfl);

//CreateProcessWithTokenW
typedef BOOL(WINAPI* _CreateProcessWithTokenW)(
	_In_                HANDLE                hToken,
	_In_                DWORD                 dwLogonFlags,
	_In_opt_			LPCWSTR               lpApplicationName,
	_In_opt_			LPWSTR                lpCommandLine,
	_In_			    DWORD                 dwCreationFlags,
	_In_opt_			LPVOID                lpEnvironment,
	_In_opt_			LPCWSTR               lpCurrentDirectory,
	_In_                LPSTARTUPINFOW        lpStartupInfo,
	_Out_               LPPROCESS_INFORMATION lpProcessInformation
);
CHAR strcreateprocwithtok[] = { 'C' ,'r' ,'e' ,'a' ,'t' ,'e' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'W' ,'i' ,'t' ,'h' ,'T' ,'o' ,'k' ,'e' ,'n' ,'W', '\00' };
_CreateProcessWithTokenW MyCreateProcessWithTokenW = (_CreateProcessWithTokenW)GetProcAddress(MyAdvapi32, strcreateprocwithtok);

//ImpersonateLoggedOnUser
typedef BOOL(WINAPI* _ImpersonateLoggedOnUser)(
	_In_ HANDLE hToken
);
CHAR strimploggerusr[] = { 'I' ,'m' ,'p' ,'e' ,'r' ,'s' ,'o' ,'n' ,'a' ,'t' ,'e' ,'L' ,'o' ,'g' ,'g' ,'e' ,'d' ,'O' ,'n' ,'U' ,'s' ,'e' ,'r', '\00' };
_ImpersonateLoggedOnUser MyImpersonateLoggedOnUser = (_ImpersonateLoggedOnUser)GetProcAddress(MyAdvapi32, strimploggerusr);

//OpenProcessToken
typedef BOOL(WINAPI* _OpenProcessToken)(
	_In_  HANDLE  ProcessHandle,
	_In_  DWORD   DesiredAccess,
	_Out_ PHANDLE TokenHandle
);
CHAR stropenproctok[] = { 'O' ,'p' ,'e' ,'n' ,'P' ,'r' ,'o' ,'c' ,'e' ,'s' ,'s' ,'T' ,'o' ,'k' ,'e' ,'n', '\00' };
_OpenProcessToken MyOpenProcessToken = (_OpenProcessToken)GetProcAddress(MyAdvapi32, stropenproctok);

//ConvertStringSidToSidA
typedef BOOL(WINAPI* _ConvertStringSidToSidA)(
	_In_  LPCSTR StringSid,
	_Out_ PSID* Sid
);
CHAR strconvsttr2sid[] = { 'C' ,'o' ,'n' ,'v' ,'e' ,'r' ,'t' ,'S' ,'t' ,'r' ,'i' ,'n' ,'g' ,'S' ,'i' ,'d' ,'T' ,'o' ,'S' ,'i' ,'d' ,'A', '\00' };
_ConvertStringSidToSidA  MyConvertStringSidToSidA = (_ConvertStringSidToSidA)GetProcAddress(MyAdvapi32, strconvsttr2sid);

//GetTokenInformation
typedef BOOL(WINAPI* _GetTokenInformation)(
	_In_            HANDLE                  TokenHandle,
	_In_            TOKEN_INFORMATION_CLASS TokenInformationClass,
	_Out_opt_ LPVOID                  TokenInformation,
	_In_            DWORD                   TokenInformationLength,
	_Out_           PDWORD                  ReturnLength
);
CHAR strgettokinfo[] = { 'G' ,'e' ,'t' ,'T' ,'o' ,'k' ,'e' ,'n' ,'I' ,'n' ,'f' ,'o' ,'r' ,'m' ,'a' ,'t' ,'i' ,'o' ,'n', '\00' };
_GetTokenInformation MyGetTokenInformation = (_GetTokenInformation)GetProcAddress(MyAdvapi32, strgettokinfo);

//RevertToSelf
typedef BOOL(WINAPI* _RevertToSelf)();
CHAR strrevert2self[] = { 'R' ,'e' ,'v' ,'e' ,'r' ,'t' ,'T' ,'o' ,'S' ,'e' ,'l' ,'f', '\00' };
_RevertToSelf MyRevertToSelf = (_RevertToSelf)GetProcAddress(MyAdvapi32, strrevert2self);

