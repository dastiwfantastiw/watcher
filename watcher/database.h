#pragma once
#include "config.h"
#include "pe_format.h"

#include <map>
#include <vector>

using namespace cfg;
using namespace pe_format;

namespace sys_database
{
	class SysDataModule
	{
	private:
		std::map<DWORD, Syscall> m_KnownCalls;
		std::vector<BinSyscall>  m_UnkownCalls;
		PEFormat*                m_peModule;
		SyscallDllInfo           m_DllInfo;

	public:

		SysDataModule(SyscallDllInfo& SysDllInfo);

		pe_format::PEFormat* FindModule();
		pe_format::PEFormat* GetModule();

		int GetSizeUnknownCalls();
		int GetSizeKnownCalls();

		bool CheckModuleForUnknownCalls();

		void UploadUnknownCalls(BinSyscall* BinSyscall, int Count);

		Syscall* FindKnownCallId(DWORD Id);
		Syscall* FindKnownCallHash(DWORD Hash);
	};

	class SysDataBase
	{
	private:
		std::vector<SysDataModule> m_SysModules;

	public:
		SysDataBase() {};

		Syscall* FindKnownCallIdInModules(DWORD Id, pe_format::PEFormat*& OutModuleInfo);
		Syscall* FindKnownCallHashInModules(DWORD Hash, pe_format::PEFormat*& OutModuleInfo);

		SysDataModule* AddModule(SyscallDllInfo& SysDllInfo);

		int InstallCustomHandlers(std::map<DWORD, Syscall::Event>& Event);
	};
}