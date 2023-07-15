#include "src/core/windows/create_process.h"

#include <WtsApi32.h>
#include <UserEnv.h>
#include <iostream>


using namespace std;

static DWORD GetActiveSessionID() {
    DWORD session_id = 0;
    PWTS_SESSION_INFO pwsi = nullptr;
    DWORD dwCounts = 0;

    if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pwsi, &dwCounts)) {
        cout << "WTSEnumerateSessions error :" << GetLastError() << endl;
        return session_id;
    }

    for (DWORD i = 0; i < dwCounts; ++i) {
        WTS_SESSION_INFO wsi = pwsi[i];
        if (WTSActive == wsi.State) {
            cout << "GetActiveSessionID success, session id:" << wsi.SessionId << ", name: " << wsi.pWinStationName << endl;
            session_id = wsi.SessionId;
            break;
        }
    }
    WTSFreeMemory(pwsi);
    return session_id;
}

static HANDLE GetActiveUserToken() {
    DWORD session_id = GetActiveSessionID();

    if (session_id == 0) {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE tmp_token = INVALID_HANDLE_VALUE;
    if (WTSQueryUserToken(session_id, &tmp_token) == 0) {
        cout << "WTSQueryUserToken error, session id: " << session_id << ", error: " << GetLastError() << endl;
    }

    if (tmp_token == INVALID_HANDLE_VALUE) {
        cout << "GetActiveUserToken error : " << GetLastError() << endl;
        return INVALID_HANDLE_VALUE;
    }

    HANDLE token = INVALID_HANDLE_VALUE;
    if (DuplicateTokenEx(tmp_token,
                         TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                         nullptr,
                         SecurityAnonymous,
                         TokenPrimary,
                         &token) == 0) {
        cout << "DuplicateTokenEx error : " << GetLastError() << endl;
        CloseHandle(tmp_token); 
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(tmp_token); 
    return token;
}

static HANDLE CreateProcessAsCurrentUser(HANDLE token, const std::wstring& cmd) {
    STARTUPINFOW start_info = {0};
    start_info.cb = sizeof(start_info);
    start_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    start_info.wShowWindow = SW_SHOW;

    PROCESS_INFORMATION pi;

    LPVOID environment = nullptr;
    if (CreateEnvironmentBlock(&environment, token, FALSE) == 0) {
        cout << "CreateEnvironmentBlock error : " << GetLastError() << endl;
        return nullptr;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    BOOL result = CreateProcessAsUserW(token,
                                       nullptr,
                                       (LPWSTR)(cmd.data()),
                                       &sa,
                                       &sa,
                                       TRUE,
                                       CREATE_UNICODE_ENVIRONMENT| NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
                                       environment,
                                       nullptr,
                                       &start_info,
                                       &pi);

    DestroyEnvironmentBlock(environment);

    if (result == 0) {
        return nullptr;
    }

    if (pi.hThread != nullptr) {
        CloseHandle(pi.hThread);
    }

    return pi.hProcess;
}

HANDLE CreateProcessAsCurrentUser(const std::wstring& cmd, bool admin_privilege) {
    HANDLE token = GetActiveUserToken();
    if (token == INVALID_HANDLE_VALUE) {
        cout << "GetCurrentUserToken error." << endl;;
        return nullptr;
    }

    HANDLE process = nullptr;
    HANDLE admin_privilege_token = nullptr;
    DWORD length = 0;
    if (admin_privilege && GetTokenInformation(token, TokenLinkedToken, (VOID*)&admin_privilege_token, sizeof(HANDLE), &length)) {
        process = CreateProcessAsCurrentUser(admin_privilege_token, cmd);
        CloseHandle(admin_privilege_token);
    } else {
        process = CreateProcessAsCurrentUser(token, cmd);
    }

    CloseHandle(token);
    return process;
}