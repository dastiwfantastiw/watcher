#include "database.h"
#include "adler32.h"

#include "logger.h"

sys_database::SysDataModule::SysDataModule(SyscallDllInfo& SysDllInfo)
{
	m_DllInfo = SysDllInfo;
	m_peModule = SearchModule(SysDllInfo.m_DllHash);
}

PEFormat* sys_database::SysDataModule::FindModule()
{
	if (m_DllInfo.m_DllHash)
	{
		if (m_peModule)
		{
			delete m_peModule;
		}

		return m_peModule = SearchModule(m_DllInfo.m_DllHash);
	}
	return NULL;
}

PEFormat* sys_database::SysDataModule::GetModule()
{
	return m_peModule;
}

int sys_database::SysDataModule::GetSizeUnknownCalls()
{
	return m_UnkownCalls.size();
}

int sys_database::SysDataModule::GetSizeKnownCalls()
{
	return m_KnownCalls.size();
}

bool sys_database::SysDataModule::CheckModuleForUnknownCalls()
{
	if (!m_peModule ||
		!m_peModule->m_ExportSize)
	{
		return false;
	}

	std::map<DWORD, Syscall> idSyscalls;

	if (m_DllInfo.m_IsAllSyscalls && m_peModule->LoadAllIdSyscalls(idSyscalls))
	{
		for (auto it = idSyscalls.begin(); it != idSyscalls.end(); it++)
		{
			it->second.m_Types = m_DllInfo.m_Types;
			it->second.m_Flags = m_DllInfo.m_Flags;

			if (m_UnkownCalls.size() > 0)
			{
				for (auto itb = m_UnkownCalls.begin(); itb != m_UnkownCalls.end(); )
				{
					if ((itb->m_IsByNameHash &&
						(adler32(it->second.m_Name.c_str(), it->second.m_Name.length()) == itb->u.m_NameHash)) ||
						(!itb->m_IsByNameHash && (it->second.m_Id == itb->u.m_Id)))
					{
						it->second.m_Types = itb->m_Types;
						it->second.m_Flags = itb->m_Flags;
						m_UnkownCalls.erase(itb--);
						break;
					}
					itb++;
				}
			}
			m_KnownCalls.insert(std::pair<DWORD, Syscall>(it->first, it->second));
		}
		return true;
	}
	else
	{
		std::map<DWORD, Syscall> hashSyscalls;
		if (m_peModule->LoadAllHashSyscalls(hashSyscalls))
		{
			for (auto it = m_UnkownCalls.begin(); it != m_UnkownCalls.end();)
			{
				if (it->m_IsByNameHash)
				{
					auto isExist = hashSyscalls.find(it->u.m_NameHash);
					if (isExist != hashSyscalls.end())
					{
						isExist->second.m_Types = it->m_Types;
						isExist->second.m_Flags = it->m_Flags;
						m_KnownCalls.insert(std::pair<DWORD, Syscall>(isExist->second.m_Id, isExist->second));
						m_UnkownCalls.erase(it--);
					}
				}
				else
				{
					auto isExist = idSyscalls.find(it->u.m_Id);
					if (isExist != idSyscalls.end())
					{
						isExist->second.m_Types = it->m_Types;
						isExist->second.m_Flags = it->m_Flags;
						m_KnownCalls.insert(std::pair<DWORD, Syscall>(isExist->second.m_Id, isExist->second));
						m_UnkownCalls.erase(it--);
					}
				}
				it++;
			}
			return true;
		}
	}
	return false;
}

void sys_database::SysDataModule::UploadUnknownCalls(BinSyscall* BinSyscall, int Count)
{
	for (size_t i = 0; i < Count; i++)
	{
		m_UnkownCalls.push_back(BinSyscall[i]);
	}
}

Syscall* sys_database::SysDataModule::FindKnownCallId(DWORD Id)
{
	auto isExist = m_KnownCalls.find(Id);
	if (isExist != m_KnownCalls.end())
	{
		return &isExist->second;
	}
	return NULL;
}

Syscall* sys_database::SysDataModule::FindKnownCallHash(DWORD Hash)
{
	for (auto it = m_KnownCalls.begin(); it != m_KnownCalls.end(); it++)
	{
		if (adler32(it->second.m_Name.c_str(), it->second.m_Name.length()) == Hash)
		{
			return &it->second;
		}
	}
	return NULL;
}

Syscall* sys_database::SysDataBase::FindKnownCallIdInModules(DWORD Id, PEFormat*& OutModuleInfo)
{
	for (auto it = m_SysModules.begin(); it != m_SysModules.end(); it++)
	{
		Syscall* isSysExist = it->FindKnownCallId(Id);
		if (isSysExist)
		{
			OutModuleInfo = it->GetModule();
			return isSysExist;
		}
	}
	return NULL;
}

sys_database::SysDataModule* sys_database::SysDataBase::AddModule(SyscallDllInfo& SysDllInfo)
{
	m_SysModules.push_back(SysDataModule(SysDllInfo));
	return &m_SysModules.back();
}

Syscall* sys_database::SysDataBase::FindKnownCallHashInModules(DWORD Hash, PEFormat*& OutModuleInfo)
{
	for (auto it = m_SysModules.begin(); it != m_SysModules.end(); it++)
	{
		Syscall* isSysExist = it->FindKnownCallHash(Hash);
		if (isSysExist)
		{
			OutModuleInfo = it->GetModule();
			return isSysExist;
		}
	}
	return NULL;
}

int sys_database::SysDataBase::InstallCustomHandlers(std::map<DWORD, Syscall::Event>& Events)
{
	int count = NULL;
	for (auto it = Events.begin(); it != Events.end(); it++)
	{
		PEFormat* peModule = NULL;
		Syscall* isFound = FindKnownCallHashInModules(it->first, peModule);
		if (isFound)
		{
			isFound->m_Event = it->second;
			count++;
		}
	}
	return count;
}
