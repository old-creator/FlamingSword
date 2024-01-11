
#include "wapi.hpp"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	HANDLE trusted_installer_token = GetTrustedInstallerToken();
	if (!trusted_installer_token)
		return 1;

	RunCommandLine(trusted_installer_token);
	MyCloseHandle(trusted_installer_token);
	return 0;
}

HANDLE GetTrustedInstallerToken() {

	bool impersonating = false;
	HANDLE trusted_installer_token = NULL;

	do {

		if (!EnablePrivilege(false, SeTcbPrivilege)) {
			if (!EnablePrivilege(false, SeDebugPrivilege)) {
				break;
			}
			impersonating = ImpersonateTcbToken();
			if (!impersonating || !EnablePrivilege(impersonating, SeTcbPrivilege)) {
				break;
			}
		}

		PSID trusted_installer_sid;
		CHAR tempstring[] = { 'S' ,'-' ,'1' ,'-' ,'5' ,'-' ,'8' ,'0' ,'-' ,'9' ,'5' ,'6' ,'0' ,'0' ,'8' ,'8' ,'8' ,'5' ,'-' ,'3' ,'4' ,'1' ,'8' ,'5' ,'2' ,'2' ,'6' ,'4' ,'9' ,'-' ,'1' ,'8' ,'3' ,'1' ,'0' ,'3' ,'8' ,'0' ,'4' ,'4' ,'-' ,'1' ,'8' ,'5' ,'3' ,'2' ,'9' ,'2' ,'6' ,'3' ,'1' ,'-' ,'2' ,'2' ,'7' ,'1' ,'4' ,'7' ,'8' ,'4' ,'6' ,'4', '\00' };
		if (!MyConvertStringSidToSidA(tempstring, &trusted_installer_sid)) {
			break;
		}

		HANDLE current_token = impersonating ? GetCurrentThreadToken() : GetCurrentProcessToken();

		DWORD token_group_size;
		MyGetTokenInformation(current_token, TokenGroups, NULL, 0, &token_group_size);
		PTOKEN_GROUPS token_groups = (PTOKEN_GROUPS)MyLocalAlloc(LPTR, token_group_size);
		if (!token_groups) {
			break;
		}
		if (!MyGetTokenInformation(current_token, TokenGroups, token_groups, token_group_size, &token_group_size)) {
			break;
		}

		token_groups->Groups[token_groups->GroupCount - 1].Sid = trusted_installer_sid;
		token_groups->Groups[token_groups->GroupCount - 1].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;
		WCHAR wtempstring1[] = { 'S' ,'Y' ,'S' ,'T' ,'E' ,'M', '\00' };
		WCHAR wtempstring2[] = { 'N' ,'T' ,' ' ,'A' ,'U' ,'T' ,'H' ,'O' ,'R' ,'I' ,'T' ,'Y', '\00' };
		bool logon_success = LogonUserExExW(wtempstring1, wtempstring2, NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_WINNT50, token_groups, &trusted_installer_token, NULL, NULL, NULL, NULL);

	} while (false);

	if (impersonating)
		MyRevertToSelf();

	return trusted_installer_token;

}

bool ImpersonateTcbToken() {

	HANDLE hsnapshot = MyCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (!MyProcess32FirstW(hsnapshot, &entry)) {
		MyCloseHandle(hsnapshot);
		return false;
	}

	DWORD pid = 0;

	do {
		WCHAR wtempstring[] = { 'w' ,'i' ,'n' ,'l' ,'o' ,'g' ,'o' ,'n' ,'.' ,'e' ,'x' ,'e', '\00' };
		if (!_wcsicmp(wtempstring, entry.szExeFile)) {
			pid = entry.th32ProcessID;
			break;
		}
	} while (MyProcess32NextW(hsnapshot, &entry));

	MyCloseHandle(hsnapshot);

	if (!pid) {
		return false;
	}

	HANDLE hprocess = MyOpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (!hprocess) {
		return false;
	}

	HANDLE htoken;
	bool token_success = MyOpenProcessToken(hprocess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &htoken);

	MyCloseHandle(hprocess);

	if (!token_success) {
		return false;
	}

	bool impersonate_success = MyImpersonateLoggedOnUser(htoken);

	MyCloseHandle(htoken);

	if (!impersonate_success) {
		return false;
	}

	return true;

}

bool EnablePrivilege(bool impersonating, int privilege_value)
{
	bool b;
	NTSTATUS status = RtlAdjustPrivilege(privilege_value, true, impersonating, &b);
	return NT_SUCCESS(status);
}

void RunCommandLine(HANDLE token) {

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	WCHAR wtempstring[] = { 'w' ,'i' ,'n' ,'s' ,'t' ,'a' ,'0' ,'\\' ,'d' ,'e' ,'f' ,'a' ,'u' ,'l' ,'t', '\00' };
	si.lpDesktop = (LPWSTR)wtempstring;
	PROCESS_INFORMATION pi;

	EnablePrivilege(false, SeImpersonatePrivilege);
	WCHAR cmd_line[] = { 'c' ,'m' ,'d' ,'.' ,'e' ,'x' ,'e', '\00' };
	if (!MyCreateProcessWithTokenW(token, 0, NULL, cmd_line, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		return;
	}

	MyCloseHandle(pi.hProcess);
	MyCloseHandle(pi.hThread);
}
