#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <chrono>
#include <thread>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_TERMINATE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define Force_attack 0x3114BA4

HANDLE hDriver;
static int client, engine, address;
DWORD baseAddr = 0;
DWORD pid;

typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Response;
	ULONG Size;

} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;
typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Value;
	ULONG Size;

} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;
typedef struct _KERNEL_TERMINATE_REQUEST
{
	ULONG ProcessId;
} KERNEL_TERMINATE_REQUEST, *PKERNEL_TERMINATE_REQUEST;

template <typename type>type ReadVirtualMemory(ULONG ProcessId, ULONG ReadAddress, SIZE_T Size)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return (type)false;

	DWORD Return, Bytes;
	KERNEL_READ_REQUEST ReadRequest;

	ReadRequest.ProcessId = ProcessId;
	ReadRequest.Address = ReadAddress;
	ReadRequest.Size = Size;

	if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))
		return (type)ReadRequest.Response;
	else
		return (type)false;
}
bool WriteVirtualMemory(ULONG ProcessId, ULONG WriteAddress, ULONG WriteValue, SIZE_T WriteSize)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;
	DWORD Bytes;

	KERNEL_WRITE_REQUEST  WriteRequest;
	WriteRequest.ProcessId = ProcessId;
	WriteRequest.Address = WriteAddress;
	WriteRequest.Value = WriteValue;
	WriteRequest.Size = WriteSize;

	if (DeviceIoControl(hDriver, IO_WRITE_REQUEST, &WriteRequest, sizeof(WriteRequest),0, 0, &Bytes, NULL))
		return true;
	else
		return false;
}

uint32_t find(const wchar_t* proc)
{
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	auto pe = PROCESSENTRY32W{ sizeof(PROCESSENTRY32W) };

	if (Process32First(snapshot, &pe)) {
		do {
			if (!_wcsicmp(proc, pe.szExeFile)) {
				CloseHandle(snapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(snapshot, &pe));
	}
	CloseHandle(snapshot);
	return 0;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

static void GetProcessAddress()
{
	MODULEENTRY32 Module;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::cout << " SNAP FAILED ";
	}
	Module.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapshot, &Module)) {

		std::cout << "FIRST MODULE NOT FOUND!" << std::endl;
		CloseHandle(snapshot);
	}
	while (baseAddr == 0)
	{
		do
		{
			std::cout << "Module Name: ";
			std::cout << Module.szModule << std::endl;

			if (!_tcscmp(Module.szModule, L"panorama_client.dll") == 0)
			{
				baseAddr = (DWORD)Module.modBaseAddr;
				break;
			}
		} while (Module32Next(snapshot, &Module));

		if (baseAddr == 0)
		{
			system("CLS");
			std::cout << "Failed to find module" << std::endl;
		}
		
	}
	std::cout << "Base Address Is: " << std::hex << baseAddr << std::endl;
	CloseHandle(snapshot);
}
static void GetAddresses()
{
	pid = find(L"csgo.exe");
	GetProcessAddress();
}

static DWORD read(ULONG processId, ULONG ReadAddress, SIZE_T size) 
{
	hDriver = CreateFileA("\\\\.\\dr1v3r", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	DWORD value = ReadVirtualMemory<DWORD>(processId, ReadAddress, size);
	CloseHandle(hDriver);
	return value;
}
static void write(ULONG processId, ULONG writeAddress, INT value, SIZE_T size)
{
	hDriver = CreateFileA("\\\\.\\dr1v3r", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	WriteVirtualMemory(processId, writeAddress, value, size);
	CloseHandle(hDriver);
}
static bool TerminateProcess(ULONG processId)
{
	hDriver = CreateFileA("\\\\.\\dr1v3r", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hDriver == INVALID_HANDLE_VALUE)
		return false;
	DWORD Bytes;

	KERNEL_TERMINATE_REQUEST TermRequest;
	TermRequest.ProcessId = processId;
	
	if (DeviceIoControl(hDriver, IO_TERMINATE_REQUEST, &TermRequest, sizeof(TermRequest), 0, 0, &Bytes, NULL))
		return true;
	else
		return false;
	CloseHandle(hDriver);
}
static void attack()
{
	address = baseAddr + Force_attack;
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	write(pid, address, 0x5, 8);
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	write(pid, address, 0x4, 8);
}

int main()
{
	std::cout << "Usermode Started.\n";

	GetAddresses();

	std::cout << "Process Id: ";
	std::cout << pid << std::endl;
	//std::cout << "Process Base: ";
	//std::cout << baseAddr << std::endl;
	TerminateProcess(pid);
	system("pause");
}

