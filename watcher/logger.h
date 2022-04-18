#pragma once
#include "config.h"
#include "analyzer.h"
#include "pe_format.h"

using namespace cfg;
using namespace analyzer;
using namespace pe_format;

namespace logger
{
	extern HANDLE           hFile;
	extern CRITICAL_SECTION critSect;

	int LogTrace(const char* FormatString, ...);
	int LogTraceTime(SYSTEMTIME& Time, const char* FormatString, ...);
	int LogWriteBuffer(void* Buffer, SIZE_T Size);

	int LogSysBeforeExec(SYSTEMTIME& Time, Syscall* Sys, char* ArgsBuffer, PEFormat* SysModule);
	int LogSysAfterExec(SYSTEMTIME& Time, Syscall* Sys, char* ArgsBuffer, PEFormat* SysModule, DWORD Result);

	bool LogAddReadPointerToBuffer(void* Value, char*& Buffer, SIZE_T& Size);
	bool LogAddUnknownValueToBuffer(DWORD Value, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddArrayCharValueToBuffer(char* Value, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddArrayWideCharValueToBuffer(wchar_t* Value, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddAnsiStringValueToBuffer(ANSI_STRING* Value, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddUnicodeStringValueToBuffer(UNICODE_STRING* Value, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddHandleValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddHandleProcessValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddHandleThreadValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim);
	bool LogAddHandleFileValueToBuffer(HANDLE Value, OBJECT_HANDLE_INFORMATION& Info, char*& Buffer, SIZE_T& Size, char Delim);

	bool LogAddAnalyzeValueToBuffer(void* Value, Type Types, char*& Buffer, SIZE_T& Size, char Delim, BYTE MaxPointer);
	char* LogAddAnalyzeArgsToBuffer(DWORD* Args, WORD Argc, Type Types);
}