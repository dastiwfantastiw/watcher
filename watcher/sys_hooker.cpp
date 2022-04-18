#include "sys_hooker.h"
#include "logger.h"
#include "config.h"

#define HEAVENS_GATE __readfsdword(0xc0)

#define OFFSET_SEARCH_FRAME 0x4
#define OFFSET_SC_HANDLER 0x23
#define OFFSET_JMP33 0x31

/*
pushad
push eax
push ebp
mov edx, 0x11111111
call edx
test al, al
pop eax
popad
jne _skip

push ebp
mov ebp, esp
pushad
lea edx, dword ptr [ebp - 0x20] #registers
push edx
lea edx, dword ptr [ebp + 12] #args
push edx
push eax #id
push 0x33F320F4
mov edx, 0x33333333
call edx
test al, al
popad
mov esp, ebp
pop ebp
jne _executed

_skip:
nop
nop
nop
nop
nop
nop
nop

_executed:
ret
*/

namespace sys_hooker
{
	BYTE  MaxFrame = 0x20;
	BYTE  GateBytes[7] = "\x68\xDD\xCC\xBB\xAA\xC3";
	BYTE  JumpBytes[7] = { 0 };
	BYTE  HandlerBytes[] = "\x60\x50\x55\xBA\x11\x11\x11\x11\xFF\xD2\x84\xC0\x58\x61\x75\x21\x55\x89\xE5\x60\x8D\x55\xE0\x52\x8D\x55\x0C\x52\x50\x68\xF4\x20\xF3\x33\xBA\x33\x33\x33\x33\xFF\xD2\x84\xC0\x61\x89\xEC\x5D\x75\x07\x90\x90\x90\x90\x90\x90\x90\xC3";
	BYTE* HandlerMemory = NULL;
	void* JumpMemoryPointer = NULL;
}

bool sys_hooker::IsMagicExistsInFrame(DWORD Ebp) //self defense
{
	ULONG_PTR lMax;
	ULONG_PTR lMin;
	GetCurrentThreadStackLimits(&lMin, &lMax);

	DWORD lpEbp = Ebp;
	DWORD cEbp = NULL;

	if (((lMax < lpEbp) || (lMin > lpEbp)))
	{
		return true; //sometimes a thread doesn't run on its own stack we will skip it
	}

	for (size_t i = 0; i < MaxFrame; i++)
	{
		if (((lMax > lpEbp) && (lMin < lpEbp)))
		{
			if (reinterpret_cast<DWORD*>(lpEbp)[2] == cfg::Magic)
			{
				return true;
			}

			lpEbp = *reinterpret_cast<DWORD*>(lpEbp);
		}
	}

	return false;
}

bool sys_hooker::InstallHook(void* Handler)
{
	USHORT procMachine = 0;
	USHORT nativeMachine = 0;
	MEMORY_BASIC_INFORMATION memBasicInfo = { 0 };

	if (IsWow64Process2(GetCurrentProcess(), &procMachine, &nativeMachine)
		&& procMachine != IMAGE_FILE_MACHINE_UNKNOWN)
	{
		memcpy_s(JumpBytes, sizeof(JumpBytes), reinterpret_cast<void*>(HEAVENS_GATE), sizeof(JumpBytes));
		HandlerMemory = static_cast<BYTE*>(VirtualAlloc(NULL, sizeof(HandlerBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!HandlerMemory)
		{
			return false;
		}

		memcpy_s(HandlerMemory, sizeof(HandlerBytes), HandlerBytes, sizeof(HandlerBytes));

		*(void**)(HandlerMemory + OFFSET_SEARCH_FRAME) = IsMagicExistsInFrame;
		*(void**)(HandlerMemory + OFFSET_SC_HANDLER) = Handler;
		memcpy_s(HandlerMemory + OFFSET_JMP33, sizeof(JumpBytes), &JumpBytes, sizeof(JumpBytes));

		if (!VirtualQuery(reinterpret_cast<void*>(HEAVENS_GATE), &memBasicInfo, sizeof(memBasicInfo)))
		{
			return false;
		}

		if (memBasicInfo.AllocationProtect != PAGE_EXECUTE_READWRITE)
		{
			if (!VirtualProtect(memBasicInfo.BaseAddress, memBasicInfo.RegionSize, PAGE_EXECUTE_READWRITE, &memBasicInfo.Protect))
			{
				return false;
			}

			*(void**)(GateBytes + 1) = HandlerMemory;
			JumpMemoryPointer= HandlerMemory + OFFSET_JMP33;

			memcpy_s(reinterpret_cast<void*>(HEAVENS_GATE), sizeof(GateBytes), GateBytes, sizeof(GateBytes));
			return true;
		}
	}
	return false;
}

bool sys_hooker::ExecuteSyscall(DWORD Id, WORD Argc, DWORD* Args, Registers* Regs)
{
	if (!Regs || !JumpMemoryPointer)
	{
		return false;
	}

	if (Argc)
	{
		DWORD* lArgs = Args + Argc - 1;
		for (size_t i = 0; i < Argc; i++)
		{
			DWORD val = *lArgs;
			_asm push val
			lArgs--;
		}
	}

	DWORD rArgc = Argc * 4;

	_asm
	{
		call _syscall

		_syscall:
		mov eax, Id
		mov edx, JumpMemoryPointer
		call edx;
		add esp, rArgc;
		mov edx, Regs;
		mov[edx]Regs.EAX, eax;
	}
	return true;
}