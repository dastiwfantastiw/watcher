#include "pe_format.h"
#include "adler32.h"
#include "tools.h"

using namespace tools;

pe_format::PEFormat::PEFormat(HMODULE hModule)
{
	m_ImageDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
	m_NtHeaders = NULL;
	m_OptHeader = NULL;
	m_DataDirectory = NULL;
	m_ExportDirectory = NULL;
	m_ImportDescriptor = NULL;

	m_hModule = hModule;
	m_CheckSum = NULL;
	m_TimeDateStamp = NULL;
	m_peModuleNameHash = NULL;

	m_peModuleName.clear();
	m_FullModulePath.clear();

	m_ExportSize = NULL;
	m_ImportSize = NULL;

	if (m_ImageDosHeader &&
		m_ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		m_NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(m_ImageDosHeader->e_lfanew + reinterpret_cast<BYTE*>(m_ImageDosHeader));
		if (m_NtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			m_OptHeader = &m_NtHeaders->OptionalHeader;
			m_DataDirectory = m_OptHeader->DataDirectory;

			m_ExportSize = m_DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			m_ImportSize = m_DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

			if (m_ExportSize)
			{
				m_ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<BYTE*>(m_ImageDosHeader) + m_DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			}

			if (m_ImportSize)
			{
				m_ImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<BYTE*>(m_ImageDosHeader) + m_DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			}
		}
	}
}

bool pe_format::PEFormat::GetExportApiFunction(DWORD FuncNameHash, Apicall& ApiInfo)
{
	if (!m_ImageDosHeader ||
		m_ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		!m_ExportSize || 
		!m_ExportDirectory ||
		!FuncNameHash)
	{
		return false;
	}

	DWORD* addressOfFunction = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfFunctions + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	WORD* addressOfNameOrdinals = reinterpret_cast<WORD*>(m_ExportDirectory->AddressOfNameOrdinals + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	DWORD* addressOfNames = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfNames + reinterpret_cast<BYTE*>(m_ImageDosHeader));

	for (DWORD i = 0; i < m_ExportDirectory->NumberOfNames; i++) 
	{
		ULONG* funcAddress = reinterpret_cast<ULONG*>(addressOfFunction[addressOfNameOrdinals[i]] + reinterpret_cast<BYTE*>(m_ImageDosHeader));

		if (reinterpret_cast<DWORD>(funcAddress) >= reinterpret_cast<DWORD>(m_ExportDirectory) &&
			reinterpret_cast<DWORD>(funcAddress) < reinterpret_cast<DWORD>(m_ExportDirectory + m_ExportSize))
		{
			continue;
		}

		char* funcName = reinterpret_cast<char*>(addressOfNames[i] + reinterpret_cast<BYTE*>(m_ImageDosHeader));
		if (funcName && adler32(std::string(funcName).c_str(), std::string(funcName).length()))
		{
			ApiInfo.m_Address = funcAddress;
			ApiInfo.m_Name = funcName;
			ApiInfo.m_Ord = i;
			ApiInfo.m_Signature = *static_cast<DWORD*>(funcAddress);
			return true;
		}
	}
	return false;
}

bool pe_format::PEFormat::GetExportApiFunction(char* FuncName, Apicall& ApiInfo)
{
	return GetExportApiFunction(adler32(std::string(FuncName).c_str(), std::string(FuncName).length()), ApiInfo);
}

bool pe_format::PEFormat::GetImportApiFunction(DWORD DllNameHash, DWORD FuncNameHash, Apicall& ApiInfo)
{
	if (!m_ImageDosHeader ||
		m_ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		!m_ImportSize ||
		!m_ImportDescriptor ||
		!DllNameHash ||
		!FuncNameHash)
	{
		return false;
	}

	IMAGE_IMPORT_DESCRIPTOR* lImportDesc = m_ImportDescriptor;

	for (DWORD i = 0; lImportDesc[i].Characteristics != 0; i++)
	{
		char* dllName = reinterpret_cast<char*>(lImportDesc[i].Name + reinterpret_cast<BYTE*>(m_ImageDosHeader));
		if (dllName)
		{
			if (!lImportDesc[i].FirstThunk || !lImportDesc[i].OriginalFirstThunk)
			{
				return false;
			}

			std::string name;

			if (ModulePathToName(dllName, name) && adler32(name.c_str(), name.length()) == DllNameHash)
			{
				IMAGE_THUNK_DATA* thunkData = reinterpret_cast<IMAGE_THUNK_DATA*>(lImportDesc[i].FirstThunk + reinterpret_cast<BYTE*>(m_ImageDosHeader));
				IMAGE_THUNK_DATA* origThunkData = reinterpret_cast<IMAGE_THUNK_DATA*>(lImportDesc[i].OriginalFirstThunk + reinterpret_cast<BYTE*>(m_ImageDosHeader));

				for (; origThunkData->u1.Function != 0; origThunkData++, thunkData++)
				{
					if (origThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						continue;
					}

					IMAGE_IMPORT_BY_NAME* importName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(origThunkData->u1.AddressOfData + reinterpret_cast<BYTE*>(m_ImageDosHeader));
					if (importName)
					{
						if (adler32(static_cast<std::string>(importName->Name).c_str(), static_cast<std::string>(importName->Name).length()) == FuncNameHash)
						{
							ApiInfo.m_Address = reinterpret_cast<void*>(thunkData->u1.Function);
							ApiInfo.m_Name = importName->Name;
							ApiInfo.m_Signature = *reinterpret_cast<DWORD*>(thunkData->u1.Function);
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

bool pe_format::PEFormat::GetImportApiFunction(char* DllName, char* FuncName, Apicall& ApiInfo)
{
	std::string name;

	if (ModulePathToName(DllName, name))
	{
		return GetImportApiFunction(
			adler32(name.c_str(), name.length()),
			adler32(static_cast<std::string>(FuncName).c_str(), static_cast<std::string>(FuncName).length()),
			ApiInfo);
	}
	return false;
}

bool pe_format::PEFormat::LoadAllIdSyscalls(std::map<DWORD, Syscall>& IdSyscall)
{
	if (!m_ImageDosHeader ||
		m_ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		!m_ExportSize ||
		!m_ExportDirectory)
	{
		return false;
	}

	DWORD* addressOfFunction = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfFunctions + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	WORD* addressOfNameOrdinals = reinterpret_cast<WORD*>(m_ExportDirectory->AddressOfNameOrdinals + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	DWORD* addressOfNames = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfNames + reinterpret_cast<BYTE*>(m_ImageDosHeader));

	for (int i = 0; i < m_ExportDirectory->NumberOfNames; i++)
	{
		ULONG* funcAddress = reinterpret_cast<ULONG*>(addressOfFunction[addressOfNameOrdinals[i]] + reinterpret_cast<BYTE*>(m_ImageDosHeader));

		if (reinterpret_cast<DWORD>(funcAddress) >= reinterpret_cast<DWORD>(m_ExportDirectory) &&
			reinterpret_cast<DWORD>(funcAddress) < reinterpret_cast<DWORD>(m_ExportDirectory + m_ExportSize))
		{
			continue;
		}

		if (reinterpret_cast<BYTE*>(funcAddress)[0] == 0xB8 &&
			reinterpret_cast<BYTE*>(funcAddress)[5] == 0xBA)
		{
			Syscall Instance;

			Instance.m_Address = funcAddress;

			Instance.m_Name = reinterpret_cast<char*>(addressOfNames[i] + reinterpret_cast<BYTE*>(m_ImageDosHeader));

			switch (reinterpret_cast<char*>(funcAddress)[12])
			{
			case '\xC3': Instance.m_Argc = 0; break;
			case '\xC2': Instance.m_Argc = (static_cast<WORD>(reinterpret_cast<char*>(funcAddress)[13])) / 4; break;
			default: Instance.m_Argc = 0xffff; break;
			}

			Instance.m_Id = *reinterpret_cast<DWORD*>(&(reinterpret_cast<byte*>(funcAddress)[1]));
			Instance.m_Signature = *reinterpret_cast<DWORD*>(funcAddress);

			IdSyscall.insert(std::pair<DWORD, Syscall>(Instance.m_Id, Instance));
		}
	}
	return true;
}

bool pe_format::PEFormat::LoadAllHashSyscalls(std::map<DWORD, Syscall>& IdSyscall)
{
	if (!m_ImageDosHeader ||
		m_ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		!m_ExportSize ||
		!m_ExportDirectory)
	{
		return false;
	}

	DWORD* addressOfFunction = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfFunctions + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	WORD* addressOfNameOrdinals = reinterpret_cast<WORD*>(m_ExportDirectory->AddressOfNameOrdinals + reinterpret_cast<BYTE*>(m_ImageDosHeader));
	DWORD* addressOfNames = reinterpret_cast<DWORD*>(m_ExportDirectory->AddressOfNames + reinterpret_cast<BYTE*>(m_ImageDosHeader));

	for (int i = 0; i < m_ExportDirectory->NumberOfNames; i++)
	{
		ULONG* funcAddress = reinterpret_cast<ULONG*>(addressOfFunction[addressOfNameOrdinals[i]] + reinterpret_cast<BYTE*>(m_ImageDosHeader));

		if (reinterpret_cast<DWORD>(funcAddress) >= reinterpret_cast<DWORD>(m_ExportDirectory) &&
			reinterpret_cast<DWORD>(funcAddress) < reinterpret_cast<DWORD>(m_ExportDirectory + m_ExportSize))
		{
			continue;
		}

		if (reinterpret_cast<BYTE*>(funcAddress)[0] == 0xB8 &&
			reinterpret_cast<BYTE*>(funcAddress)[5] == 0xBA)
		{
			Syscall Instance;

			Instance.m_Address = funcAddress;

			Instance.m_Name = reinterpret_cast<char*>(addressOfNames[i] + reinterpret_cast<BYTE*>(m_ImageDosHeader));

			switch (reinterpret_cast<char*>(funcAddress)[12])
			{
			case '\xC3': Instance.m_Argc = 0; break;
			case '\xC2': Instance.m_Argc = (static_cast<WORD>(reinterpret_cast<char*>(funcAddress)[13])) / 4; break;
			default: Instance.m_Argc = 0xffff; break;
			}

			Instance.m_Id = *reinterpret_cast<DWORD*>(&(reinterpret_cast<byte*>(funcAddress)[1]));
			Instance.m_Signature = *reinterpret_cast<DWORD*>(funcAddress);

			IdSyscall.insert(std::pair<DWORD, Syscall>(adler32(Instance.m_Name.c_str(), Instance.m_Name.length()), Instance));
		}
	}
	return true;
}

pe_format::PEFormat* pe_format::SearchModule(DWORD ModuleNameHash)
{
	if (!ModuleNameHash)
	{
		return NULL;
	}

	PEB_LDR_DATA* ldrData = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;

	PLIST_ENTRY head = ldrData->InMemoryOrderModuleList.Flink;
	PLIST_ENTRY next = head;

	do
	{
		PLDR_DATA_TABLE_ENTRY pldrEntry = CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (!pldrEntry->DllBase)
		{
			head = pldrEntry->InMemoryOrderLinks.Flink;
			continue;
		}

		std::string pathBuffer;

		if (UnicodeToAscii(pldrEntry->FullDllName.Buffer, pathBuffer))
		{
			std::string name;

			if (ModulePathToName(const_cast<char*>(pathBuffer.c_str()), name) &&
				adler32(name.c_str(), name.length()) == ModuleNameHash)
			{
				PEFormat* peModule = new PEFormat(reinterpret_cast<HMODULE>(pldrEntry->DllBase));

				if (peModule)
				{
					peModule->m_CheckSum = pldrEntry->CheckSum;
					peModule->m_FullModulePath = pathBuffer.c_str();
					peModule->m_peModuleName = name;
					peModule->m_peModuleNameHash = ModuleNameHash;
					peModule->m_TimeDateStamp = pldrEntry->TimeDateStamp;
					return peModule;
				}
			}
		}

		head = pldrEntry->InMemoryOrderLinks.Flink;
	} while (head != next);

	return NULL;
}

pe_format::PEFormat* pe_format::SearchModule(char* ModuleName)
{
	return pe_format::SearchModule(adler32(std::string(ModuleName).c_str(), std::string(ModuleName).length()));
}