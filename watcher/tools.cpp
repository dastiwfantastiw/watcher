#include "tools.h"
#include "adler32.h"
#include <algorithm>

namespace tools
{
	fNtQueryInformationFile NtQueryInformationFile = reinterpret_cast<fNtQueryInformationFile>(GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationFile"));
	f_vsnprintf __vsnprintf = reinterpret_cast<f_vsnprintf>(GetProcAddress(LoadLibraryA("ntdll"), "_vsnprintf"));
	f__snprintf __snprintf = reinterpret_cast<f__snprintf>(GetProcAddress(LoadLibraryA("ntdll"), "_snprintf"));
}


bool tools::ModulePathToName(char* SourceString, std::string& DestinationString)
{
	if (!SourceString)
	{
		return false;
	}

	DestinationString.clear();
	DestinationString = SourceString;

	size_t fileName = DestinationString.find_last_of('\\');
	if (fileName != 0xffffffff)
	{
		DestinationString = DestinationString.substr(fileName + 1);
	}

	size_t fileName2 = DestinationString.find_last_of('/');
	if (fileName2 != 0xffffffff)
	{
		DestinationString = DestinationString.substr(fileName2 + 1);
	}

	size_t extension = DestinationString.find_last_of('.');
	if (extension != 0xffffffff)
	{
		DestinationString = DestinationString.substr(NULL, extension);
	}

	std::transform(DestinationString.begin(), DestinationString.end(), DestinationString.begin(), [](unsigned char c) { return std::tolower(c); });
	return true;
}

bool tools::UnicodeToAscii(wchar_t* SourceWideString, std::string& DestinationString)
{
	int size = WideCharToMultiByte(CP_UTF8, NULL, SourceWideString, -1, NULL, NULL, NULL, NULL);
	if (size)
	{
		DestinationString.resize(size);
		WideCharToMultiByte(CP_UTF8, NULL, SourceWideString, -1, const_cast<char*>(DestinationString.c_str()), size, NULL, NULL);
		return true;
	}

	return false;
}

int tools::FormatString(char* Buffer, size_t Size, const char* FormatString, ...)
{
	va_list args;
	va_start(args, FormatString);
	int result = __vsnprintf(Buffer, Size, FormatString, args);
	va_end(args);
	return result;
}

NTSTATUS tools::QueryObject(HANDLE Object, tools::OBJECT_INFORMATION_CLASS Class, LPVOID OutputData, ULONG DataSize, ULONG* RetSize)
{
	return NtQueryObject(Object, static_cast<::OBJECT_INFORMATION_CLASS>(Class), OutputData, DataSize, RetSize);
}

NTSTATUS tools::QueryInformationProcess(HANDLE ProcessHandle, tools::PROCESSINFOCLASS Class, LPVOID OutputData, ULONG DataSize, ULONG* RetSize)
{
	return NtQueryInformationProcess(ProcessHandle, static_cast<::PROCESSINFOCLASS>(Class), OutputData, DataSize, RetSize);
}

NTSTATUS tools::QueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, LPVOID OutputData, ULONG DataSize, tools::FILE_INFORMATION_CLASS Class)
{
	return NtQueryInformationFile(FileHandle, IoStatusBlock, OutputData, DataSize, Class);
}

std::string tools::ConstMaskToString(ACCESS_MASK Mask, std::map<ACCESS_MASK, const char*>& SourceData)
{
	std::string result;

	bool flag = false;
	for (auto it = SourceData.begin(); it != SourceData.end(); it++)
	{
		if (it->first & Mask)
		{
			if (!flag)
			{
				flag = true;
				result = it->second;
			}
			else
			{
				result += " | " + static_cast<std::string>(it->second);
			}
		}
	}
	return result;
}

std::string tools::ConstToString(DWORD Const, std::map<DWORD, const char*>& SourceData)
{
	std::string result;

	auto isExist = SourceData.find(Const);
	if (isExist != SourceData.end())
	{
		result = isExist->second;
	}
	return result;
}


std::string tools::HexBuffer(void* Buffer, int Size)
{
	std::string result, hex;
	hex.resize(2);

	result.reserve(Size * hex.length());

	for (int i = 0; i < Size; i++)
	{
		FormatString(const_cast<char*>(hex.c_str()), hex.length(), "%02X", reinterpret_cast<byte*>(Buffer)[i]);
		result += hex;
	}
	return result;
}
