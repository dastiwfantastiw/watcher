#pragma once
#include "config.h"
#include <winternl.h>
#include <map>

using namespace cfg;

#pragma comment(lib, "ntdll.lib")

namespace memory
{
	typedef PVOID(NTAPI* fRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, ULONG Size);
	typedef BOOLEAN(NTAPI* fRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
	typedef void* (NTAPI* fRtlReAllocateHeap)(HANDLE heap, ULONG flags, PVOID ptr, SIZE_T size);
	typedef BOOLEAN(NTAPI* fRtlLockHeap)(HANDLE heap);
	typedef BOOLEAN(NTAPI* fRtlUnlockHeap)(HANDLE heap);

	extern HANDLE             hHeap;
	extern fRtlAllocateHeap   RtlAllocateHeap;
	extern fRtlFreeHeap       RtlFreeHeap;
	extern fRtlReAllocateHeap RtlReAllocateHeap;
	extern fRtlLockHeap       RtlLockHeap;
	extern fRtlUnlockHeap     RtlUnlockHeap;

	void* Alloc(size_t Size);
	void* ReAlloc(void* Mem, size_t Size);
	bool Free(void* Mem);
	bool HeapLock();
	bool HeapUnlock();
	bool IsBadReadPointer(void* Pointer, SIZE_T& AvailableSize);
	bool ReadMemory(HANDLE ProcessHandle, LPCVOID Address, LPVOID Buffer, SIZE_T Size);
	bool WriteMemory(HANDLE ProcessHandle, LPVOID Address, LPVOID Buffer, SIZE_T Size);

	extern std::map<ACCESS_MASK, const char*> AllocationMasks;
	extern std::map<ACCESS_MASK, const char*> ProtectionMasks;

	namespace events
	{
		AllowLog NtAllocateVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtWow64AllocateVirtualMemory64(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtProtectVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtWriteVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		AllowLog NtReadVirtualMemory(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
	}
}