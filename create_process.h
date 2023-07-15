#include <string>
#include <Windows.h>

/**
 * 当前登录用户的会话中创建子进程
 * 
 * @param cmd 需要执行的命令,例如 L"D:\\SendInput.exe key_event --code=VK_LWIN --flag=KEY_DOWN"
 * @param admin_privilege 是否以管理员权限启动
 */
HANDLE CreateProcessAsCurrentUser(const std::wstring& cmd, bool admin_privilege);