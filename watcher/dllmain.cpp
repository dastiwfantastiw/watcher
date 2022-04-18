#include "watcher.h"

bool 
APIENTRY
DllMain(
	HMODULE hModule,
	DWORD dwReason,
	Config* BinaryConfig)
{
    if (DLL_PROCESS_ATTACH == dwReason)
    {
        if (watcher::AttachConfig(BinaryConfig))
        {
            if (watcher::CreateLogFile())
            {
                watcher::LogCurrentProcessInfo();

                if (watcher::Configuration->m_Settings.m_IsEnableSyscalls)
                {
                    if (watcher::InitSyscalls())
                    {
                        watcher::InitSyscallsCumstomHandlers();
                        watcher::EnableSyscallHandler();
                    }
                }
            }
        }
    }
    return true;
}