#include "ntos.h"
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_TERMINATE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1003, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

UNICODE_STRING DriverName, SymbolName;

PDEVICE_OBJECT pDeviceObj;
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

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

NTSTATUS KeRead(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}
NTSTATUS KeWrite(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}
NTSTATUS TerminateProcess(ULONG targetPid)
{
	NTSTATUS NtRet = STATUS_SUCCESS;
	PEPROCESS PeProc = { 0 };
	NtRet = PsLookupProcessByProcessId(targetPid, &PeProc);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	HANDLE ProcessHandle;
	NtRet = ObOpenObjectByPointer(PeProc, NULL, NULL, 25, *PsProcessType, KernelMode, &ProcessHandle);
	if (NtRet != STATUS_SUCCESS)
	{
		return NtRet;
	}
	ZwTerminateProcess(ProcessHandle, 0);
	ZwClose(ProcessHandle);
	return NtRet;
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG CodeReq = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (CodeReq == IO_READ_REQUEST)
	{
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PKERNEL_READ_REQUEST ReadOutput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadInput->ProcessId, &Process)))
			KeRead(Process, ReadInput->Address, &ReadInput->Response, ReadInput->Size);

		DbgPrintEx(0, 0, "Read Params:  %lu, %#010x \n", ReadInput->ProcessId, ReadInput->Address);
		DbgPrintEx(0, 0, "Value: %lu \n", ReadOutput->Response);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else if (CodeReq == IO_WRITE_REQUEST)
	{
		PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process)))
			KeWrite(Process, &WriteInput->Value,WriteInput->Address, WriteInput->Size);

		DbgPrintEx(0, 0, "Write Params:  %lu, %#010x \n", WriteInput->Value, WriteInput->Address);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else if (CodeReq == IO_TERMINATE_REQUEST) 
	{
		PKERNEL_TERMINATE_REQUEST TermIn = (PKERNEL_TERMINATE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(0, 0, "xX Terminating %lu Xx \n", TermIn->ProcessId);
		TerminateProcess(TermIn->ProcessId);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else
	{
		// if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS myEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver Loaded");
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING deviceName, symbolName;
	PDEVICE_OBJECT pDeviceObj;

	RtlInitUnicodeString(&deviceName, L"\\Device\\dr1v3r");
	RtlInitUnicodeString(&symbolName, L"\\DosDevices\\dr1v3r");

	NTSTATUS ntStatus = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateDevice failed %lx\n", ntStatus);
		return ntStatus;
	}

	ntStatus = IoCreateSymbolicLink(&symbolName, &deviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink failed %lx\n", ntStatus);
		return ntStatus;
	}

	pDeviceObj->Flags |= DO_DIRECT_IO;
	pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

	return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT *DriverObject, _In_  PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING drv_name;
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&drv_name, L"\\Driver\\dr1v3r");
	return IoCreateDriver(&drv_name, &myEntry);
}
