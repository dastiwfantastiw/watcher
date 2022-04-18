#include "migrate.h"
#include "analyzer.h"

#include <vector>

bool migrate::Migrate(DWORD ProcessId, DWORD ThreadId, HANDLE Mapping, Config* BinaryConfig, MigrateResult& Result)
{
	HANDLE ProcessHandle = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, false, ProcessId);
	if (ProcessHandle == INVALID_HANDLE_VALUE ||
		!ProcessHandle)
	{
		Result.m_Message = "OpenProcess failed";
		Result.m_LastError = GetLastError();
		return false;
	}

	USHORT ProcessMachine = 0;
	USHORT NativeMachine = 0;

	if (IsWow64Process2(
		ProcessHandle, &ProcessMachine, &NativeMachine) &&
		IMAGE_FILE_MACHINE_UNKNOWN == ProcessMachine)
	{
		Result.m_Message = "The process is 64-bit application";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	HANDLE dupMapping = INVALID_HANDLE_VALUE;

	if (!DuplicateHandle(
		GetCurrentProcess(), Mapping, ProcessHandle, &dupMapping, NULL, false, DUPLICATE_SAME_ACCESS))
	{
		Result.m_Message = "DuplicateHandle failed";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	std::vector<byte> dupConfig;
	dupConfig.resize(BinaryConfig->m_Header.m_BinarySize);

	memcpy_s(dupConfig.data(), BinaryConfig->m_Header.m_BinarySize, BinaryConfig, BinaryConfig->m_Header.m_BinarySize);

	reinterpret_cast<Config*>(dupConfig.data())->m_Header.m_MappingHandle = dupMapping;
	reinterpret_cast<Config*>(dupConfig.data())->m_Header.m_MappingSize = BinaryConfig->m_Header.m_MappingSize;

	IMAGE_DOS_HEADER* dllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(MapViewOfFile(Mapping, FILE_MAP_READ, NULL, NULL, BinaryConfig->m_Header.m_MappingSize));
	if (!dllDosHeader)
	{
		Result.m_Message = "MapViewOfFile failed";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	if (dllDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		Result.m_Message = "Invalid IMAGE_DOS_SIGNATURE";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	IMAGE_NT_HEADERS* dllNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dllDosHeader->e_lfanew + reinterpret_cast<BYTE*>(dllDosHeader));
	if (dllNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		Result.m_Message = "Invalid IMAGE_NT_SIGNATURE";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	IMAGE_SECTION_HEADER* dllSecHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(dllNtHeader + 1);

	LPVOID lpImage = VirtualAllocEx(
		ProcessHandle, NULL, dllNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpImage)
	{
		Result.m_Message = "VirtualAllocEx failed";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	if (!WriteProcessMemory(
		ProcessHandle, lpImage, dllDosHeader, dllNtHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		Result.m_Message = "WriteProcessMemory failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	for (size_t i = 0; i < dllNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (!WriteProcessMemory(
			ProcessHandle,
			reinterpret_cast<LPVOID>(reinterpret_cast<BYTE*>(lpImage) + dllSecHeader[i].VirtualAddress),
			reinterpret_cast<LPVOID>(reinterpret_cast<BYTE*>(dllDosHeader) + dllSecHeader[i].PointerToRawData),
			dllSecHeader[i].SizeOfRawData,
			NULL))
		{
			Result.m_Message = "WriteProcessMemory failed";
			Result.m_LastError = GetLastError();
			VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
			CloseHandle(ProcessHandle);
			return false;
		}
	}

	LPVOID lpBinary = VirtualAllocEx(
		ProcessHandle, NULL, BinaryConfig->m_Header.m_BinarySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpBinary)
	{
		Result.m_Message = "VirtualAllocEx failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	if (!WriteProcessMemory(
		ProcessHandle, lpBinary, dupConfig.data(), BinaryConfig->m_Header.m_BinarySize, NULL))
	{
		Result.m_Message = "WriteProcessMemory failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	LPVOID lpManualData = VirtualAllocEx(
		ProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpManualData)
	{
		Result.m_Message = "VirtualAllocEx failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	LoaderData data = { 0 };

	data.fLoadLibraryA = LoadLibraryA;
	data.fGetProcAddress = GetProcAddress;

	data.imageBase = lpImage;
	data.imageNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(lpImage) + dllDosHeader->e_lfanew);
	data.imageBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(lpImage) + dllNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	data.imageImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<BYTE*>(lpImage) + dllNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	data.config = reinterpret_cast<Config*>(lpBinary);

	if (!WriteProcessMemory(ProcessHandle, lpManualData, &data, sizeof(data), NULL))
	{
		Result.m_Message = "WriteProcessMemory failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpManualData, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	if (!WriteProcessMemory(ProcessHandle,
		reinterpret_cast<LoaderData*>(lpManualData) + 1,
		DllLoader,
		reinterpret_cast<DWORD>(DllLoaderEnd) - reinterpret_cast<DWORD>(DllLoader),
		NULL))
	{
		Result.m_Message = "WriteProcessMemory failed";
		Result.m_LastError = GetLastError();
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpManualData, NULL, MEM_RELEASE);
		CloseHandle(ProcessHandle);
		return false;
	}

	HANDLE hOpenThread = OpenThread(THREAD_SET_CONTEXT, false, ThreadId);
	if (hOpenThread == INVALID_HANDLE_VALUE || !hOpenThread)
	{
		Result.m_Message = "OpenThread failed";
		Result.m_LastError = GetLastError();
		CloseHandle(ProcessHandle);
		return false;
	}

	DWORD result = QueueUserAPC(reinterpret_cast<PAPCFUNC>(reinterpret_cast<LoaderData*>(lpManualData) + 1), hOpenThread, reinterpret_cast<ULONG_PTR>(lpManualData));

	CloseHandle(ProcessHandle);
	CloseHandle(hOpenThread);

	return true;
}