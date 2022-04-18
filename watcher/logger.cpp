#include "logger.h"
#include "memory.h"
#include "process.h"
#include "analyzer.h"
#include "tools.h"

using namespace memory;
using namespace process;
using namespace analyzer;
using namespace tools;

namespace logger
{
	HANDLE           hFile = INVALID_HANDLE_VALUE;
	CRITICAL_SECTION critSect;
}

int logger::LogTrace(const char* FormatString, ...)
{
	va_list args;
	va_start(args, FormatString);

	SIZE_T frmSize = __vsnprintf(NULL, NULL, FormatString, args);

	int result = NULL;

	if (frmSize)
	{
		std::string buffer;
		buffer.resize(frmSize);

		if (__vsnprintf(const_cast<char*>(buffer.c_str()), frmSize, FormatString, args))
		{
			result = LogWriteBuffer(const_cast<char*>(buffer.c_str()), buffer.length());
		}
	}

	va_end(args);
	return result;
}

int logger::LogTraceTime(SYSTEMTIME& Time, const char* FormatString, ...)
{
	const char* timeMask = "[%02d:%02d:%02d.%03d][0x%04x][0x%04x] ";

	va_list args;
	va_start(args, FormatString);

	char timeBuf[50];
	int result = NULL;

	SIZE_T timeBufSize = __snprintf(
		timeBuf,
		sizeof(timeBuf),
		timeMask,
		Time.wHour,
		Time.wMinute,
		Time.wSecond,
		Time.wMilliseconds,
		*reinterpret_cast<DWORD*>((reinterpret_cast<byte*>(__readfsdword(0X18)) + 0x20)),
		__readfsdword(0x24));

	std::string mask = timeBuf + static_cast<std::string>(FormatString);

	SIZE_T frmSize = __vsnprintf(NULL, NULL, mask.c_str(), args);

	if (frmSize)
	{
		std::string buffer;
		buffer.resize(frmSize);

		if (__vsnprintf(const_cast<char*>(buffer.c_str()), frmSize, const_cast<char*>(mask.c_str()), args))
		{
			result = LogWriteBuffer(const_cast<char*>(buffer.c_str()), buffer.length());
		}
	}

	va_end(args);
	return result;
}

int logger::LogWriteBuffer(void* Buffer, SIZE_T Size)
{
	DWORD result = NULL;

	if (TryEnterCriticalSection(&critSect))
	{
		if (Size >= 0x1000)
		{
			FlushFileBuffers(hFile);
		}
		WriteFile(hFile, Buffer, Size, &result, NULL);
		LeaveCriticalSection(&critSect);
	}

	return result;
}

int logger::LogSysBeforeExec(SYSTEMTIME& Time, Syscall* Sys, char* ArgsBuffer, PEFormat* SysModule)
{
	const char* mask = "%s <0x%x> (%s);\n";

	return LogTraceTime(
		Time,
		mask,
		Sys->m_Name.c_str(),
		Sys->m_Id,
		ArgsBuffer);
}

int logger::LogSysAfterExec(SYSTEMTIME& Time, Syscall* Sys, char* ArgsBuffer, PEFormat* SysModule, DWORD Result)
{
	const char* mask = "~%s <0x%x> (%s) => 0x%08x\n";

	return LogTraceTime(
		Time,
		mask,
		Sys->m_Name.c_str(),
		Sys->m_Id,
		ArgsBuffer,
		Result);
}

bool logger::LogAddReadPointerToBuffer(void* Value, char*& Buffer, SIZE_T& Size)
{
	const char* mask = "%s0x%08x -> ";

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddUnknownValueToBuffer(DWORD Value, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x%c ";

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddArrayCharValueToBuffer(char* Value, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x -> \"%s\"%c ";

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Value, Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}

			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Value, Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddArrayWideCharValueToBuffer(wchar_t* Value, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x -> u\"%s\"%c ";

	std::string buffer;

	if (!UnicodeToAscii(Value, buffer))
	{
		return false;
	}

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, buffer.c_str(), Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, buffer.c_str(), Delim))
		{
			return true;
		}
	}

	return false;
}

bool logger::LogAddAnsiStringValueToBuffer(ANSI_STRING* Value, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x -> as\"%s\"%c ";

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Value->Buffer, Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Value->Buffer, Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddUnicodeStringValueToBuffer(UNICODE_STRING* Value, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x -> us\"%s\"%c ";

	std::string buffer;

	if (!UnicodeToAscii(Value->Buffer, buffer))
	{
		return false;
	}

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, buffer.c_str(), Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, buffer.c_str(), Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddHandleValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x {%s: \"%s\"}%c ";

	if (Info.m_StrName.empty() || Info.m_StrType.empty())
	{
		return false;
	}

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Info.m_StrType.c_str(), Info.m_StrName.c_str(), Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Info.m_StrType.c_str(), Info.m_StrName.c_str(), Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddHandleProcessValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x {%s: 0x%x:\"%s\"}%c ";

	if (Info.m_StrType.empty())
	{
		return false;
	}

	Process process(Value);
	process.ReadProcessImagePath();

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Info.m_StrType.c_str(), process.GetProcessId(), process.GetProcessImagePath(), Delim);

	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}

			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Info.m_StrType.c_str(), process.GetProcessId(), process.GetProcessImagePath(), Delim))
		{
			return true;
		}
	}
	
	return false;
}

bool logger::LogAddHandleThreadValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x {%s: 0x%04x}%c ";

	DWORD tid = GetThreadId(Value);

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Info.m_StrType.c_str(), tid, Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Info.m_StrType.c_str(), tid, Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddHandleFileValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim)
{
	const char* mask = "%s0x%08x {%s: \"%s\"}%c ";

	tools::FILE_NAME_INFORMATION fileNameInfo;
	IO_STATUS_BLOCK stBlock;

	if (NT_SUCCESS(QueryInformationFile(Value, &stBlock, &fileNameInfo, sizeof(fileNameInfo), tools::FileNameInformation)))
	{
		std::string fileName;
		fileName.resize(fileNameInfo.FileNameLength);

		if (UnicodeToAscii(fileNameInfo.FileName, fileName))
		{
			SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Info.m_StrType.c_str(), fileName.c_str(), Delim);
			if (size)
			{
				if (size >= Size)
				{
					Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
					if (!Buffer)
					{
						return false;
					}
					Size = size + 1;
				}

				if (FormatString(Buffer, Size, mask, Buffer, Value, Info.m_StrType.c_str(), fileName.c_str(), Delim))
				{
					return true;
				}
			}
		}
	}

	SIZE_T size = FormatString(NULL, NULL, mask, Buffer, Value, Info.m_StrType.c_str(), Info.m_StrName.c_str(), Delim);
	if (size)
	{
		if (size >= Size)
		{
			Buffer = static_cast<char*>(ReAlloc(Buffer, size + 1));
			if (!Buffer)
			{
				return false;
			}
			Size = size + 1;
		}

		if (FormatString(Buffer, Size, mask, Buffer, Value, Info.m_StrType.c_str(), Info.m_StrName.c_str(), Delim))
		{
			return true;
		}
	}
	return false;
}

bool logger::LogAddAnalyzeValueToBuffer(void* Value, Type Types, char*& Buffer, SIZE_T& Size, char Delim, BYTE MaxPointer)
{
	bool result = false;
	SIZE_T availableSize = 0;

	if (IsBadReadPointer(Value, availableSize))
	{
		if (static_cast<WORD>(Types) & static_cast<WORD>(Type::HANDLE))
		{
			OBJECT_HANDLE_INFORMATION objectInfo;
			if (IsValueHandle(static_cast<HANDLE>(Value), objectInfo))
			{
				switch (static_cast<WORD>(Types) & static_cast<WORD>(objectInfo.m_Types))
				{
				case static_cast<WORD>(Type::PROCESS):
				{
					if (!LogAddHandleProcessValueToBuffer(static_cast<HANDLE>(Value), objectInfo, Buffer, Size, Delim))
					{
						return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
					}
					return true;
				}

				case static_cast<WORD>(Type::THREAD):
				{
					if (!LogAddHandleThreadValueToBuffer(static_cast<HANDLE>(Value), objectInfo, Buffer, Size, Delim))
					{
						return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
					}
					return true;
				}

				case static_cast<DWORD>(Type::SECTION):
				case static_cast<DWORD>(Type::FILE):
				case static_cast<WORD>(Type::MUTANT):
				case static_cast<WORD>(Type::REGKEY):
				{
					if (!LogAddHandleValueToBuffer(static_cast<HANDLE>(Value), objectInfo, Buffer, Size, Delim))
					{
						return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
					}
					return true;
				}
				}
			}
		}
		return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
	}

	if (static_cast<WORD>(Types) & static_cast<WORD>(Type::CHAR))
	{
		SIZE_T length = 0;
		if (IsValueArrayChar(reinterpret_cast<char*>(Value), availableSize, length))
		{
			if (!LogAddArrayCharValueToBuffer(reinterpret_cast<char*>(Value), Buffer, Size, Delim))
			{
				return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
			}
			return true;
		}
	}

	if (static_cast<WORD>(Types) & static_cast<WORD>(Type::WIDECHAR))
	{
		SIZE_T length = 0;
		if (IsValueArrayWideChar(reinterpret_cast<wchar_t*>(Value), availableSize, length))
		{
			if (!LogAddArrayWideCharValueToBuffer(reinterpret_cast<wchar_t*>(Value), Buffer, Size, Delim))
			{
				return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
			}
			return true;
		}
	}

	if (static_cast<WORD>(Types) & static_cast<WORD>(Type::ANSI_STRING))
	{
		if (IsValueAnsiString(reinterpret_cast<ANSI_STRING*>(Value), availableSize))
		{
			if (!LogAddAnsiStringValueToBuffer(reinterpret_cast<ANSI_STRING*>(Value), Buffer, Size, Delim))
			{
				return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
			}
			return true;
		}
	}

	if (static_cast<WORD>(Types) & static_cast<WORD>(Type::UNICODE_STRING))
	{
		if (IsValueUnicodeString(reinterpret_cast<UNICODE_STRING*>(Value), availableSize))
		{
			if (!LogAddUnicodeStringValueToBuffer(reinterpret_cast<UNICODE_STRING*>(Value), Buffer, Size, Delim))
			{
				return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
			}
			return true;
		}
	}

	if (MaxPointer && (availableSize >= 4) && LogAddReadPointerToBuffer(Value, Buffer, Size))
	{
		return LogAddAnalyzeValueToBuffer(*static_cast<void**>(Value), Types, Buffer, Size, Delim, --MaxPointer);
	}
	return LogAddUnknownValueToBuffer(reinterpret_cast<DWORD>(Value), Buffer, Size, Delim);
}

char* logger::LogAddAnalyzeArgsToBuffer(DWORD* Args, WORD Argc, Type Types)
{
	SIZE_T size = 1;
	char* buffer = static_cast<char*>(Alloc(size));
	if (!buffer)
	{
		return NULL;
	}

	for (SIZE_T i = 0; i < Argc; i++)
	{
		if (!LogAddAnalyzeValueToBuffer(
			reinterpret_cast<void*>(Args[i]),
			i > Argc / 2 ? static_cast<Type>(static_cast<WORD>(Types) & (~static_cast<WORD>(Type::HANDLE))) : Types,
			buffer, size,
			i == Argc - 1 ? 0 : ',',
			MaxPtr))
		{
			Free(buffer);
			return NULL;
		}
	}
	return buffer;
}