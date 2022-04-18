#pragma once
#include "config.h"

#include <string>
#include <map>

using namespace cfg;

namespace pe_format
{
	class PEFormat
	{
	private:
		IMAGE_DOS_HEADER*        m_ImageDosHeader;
		IMAGE_NT_HEADERS*        m_NtHeaders;
		IMAGE_OPTIONAL_HEADER*   m_OptHeader;
		IMAGE_DATA_DIRECTORY*    m_DataDirectory;
		IMAGE_EXPORT_DIRECTORY*  m_ExportDirectory;
		IMAGE_IMPORT_DESCRIPTOR* m_ImportDescriptor;

	public:
		HMODULE m_hModule;
		DWORD   m_CheckSum;
		DWORD   m_TimeDateStamp;
		DWORD   m_peModuleNameHash;

		std::string m_peModuleName;
		std::string m_FullModulePath;

		DWORD m_ExportSize;
		DWORD m_ImportSize;

		PEFormat(HMODULE hModule);

		bool GetExportApiFunction(DWORD FuncNameHash, Apicall& ApiInfo);
		bool GetExportApiFunction(char* FuncName, Apicall& ApiInfo);
		
		bool GetImportApiFunction(DWORD DllNameHash, DWORD FuncNameHash, Apicall& ApiInfo);
		bool GetImportApiFunction(char* DllName, char* FuncName, Apicall& ApiInfo);

		bool LoadAllIdSyscalls(std::map<DWORD, Syscall>& IdSyscall);
		bool LoadAllHashSyscalls(std::map<DWORD, Syscall>& IdSyscall);
	};

	PEFormat* SearchModule(DWORD ModuleNameHash);
	PEFormat* SearchModule(char* ModuleName);
}