#pragma once
#ifndef _MAIN_H
#define _MAIN_H

#include <windows.h>
#include <winbase.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <psapi.h>
#include <ctype.h>
#include <Uxtheme.h>
#include <stddef.h>
#include <string.h>

#include "share.h"
#include "PartialDump.h"
#include "RegionDump.h"

#define MAINWND_MIN_WIDTH   600
#define MAINWND_MIN_HEIGHT  400

#define ID_POPUP_P_DUMPFULL 9001
#define ID_POPUP_P_DUMPPART 9002
#define ID_POPUP_P_DUMPREG  9003
#define ID_POPUP_P_REFRESH  9004

#define ID_POPUP_M_DUMPFULL 9005
#define ID_POPUP_M_DUMPPART 9006
#define ID_POPUP_M_REFRESH  9007

#define GET_API(DllHandle, ProcName) ((ProcName) = (pfn##ProcName)GetProcAddress(DllHandle, #ProcName))

#define PVOID_HEX_SIZE (sizeof(PVOID) * 2 + 1)

#ifdef _WIN64
#undef _WIN32
#endif



TCHAR gszWndMainClass[] = "FRT_DUMPER";
TCHAR gszWndProcClass[] = "FRT_PROCESS";
TCHAR gszWndModulesClass[] = "FRT_MODULES";

LPVOID origWndProcProcess = NULL, origWndProcModules = NULL;

HINSTANCE ghInst;
//HWND ghWndProcList, ghWndModuleList;

ULONG uSelectedPid = 0;
CHAR szSelectedModule[MAX_PATH] = {0};

HIMAGELIST himl;

ULONG ColorGrid;


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef LONG KPRIORITY;
typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;
typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;
typedef struct _VM_COUNTERS {
	ULONG uPeakVirtualSize;
	ULONG uVirtualSize;
	ULONG uPageFaultCount;
	ULONG uPeakWorkingSetSize;
	ULONG uWorkingSetSize;
	ULONG uQuotaPeakPagedPoolUsage;
	ULONG uQuotaPagedPoolUsage;
	ULONG uQuotaPeakNonPagedPoolUsage;
	ULONG uQuotaNonPagedPoolUsage;
	ULONG uPagefileUsage;
	ULONG uPeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _IOCOUNTERS {
	ULONG uReadOperationCount;
	ULONG uWriteOperationCount;
	ULONG uOtherOperationCount;
	LARGE_INTEGER liReadTransferCount;
	LARGE_INTEGER liWriteTransferCount;
	LARGE_INTEGER liOtherTransferCount;
} IOCOUNTERS, *PIOCOUNTERS;
typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

/*
typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;
*/
typedef struct _SYSTEM_PROCESSES {	// Information Class 5
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	LARGE_INTEGER Reserved1[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	SIZE_T ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;	// Windows 2000 only
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _DEBUG_BUFFER {
	HANDLE SectionHandle;
	PVOID SectionBase;
	PVOID RemoteSectionBase;
	ULONG SectionBaseDelta;
	HANDLE EventPairHandle;
	PVOID Unknown[2];
	HANDLE RemoteThreadHandle;
	SIZE_T InfoClassMask;
	SIZE_T SizeOfInfo;
	SIZE_T AllocatedSize;
	SIZE_T SectionSize;
	PVOID ModuleInformation;
	PVOID BackTraceInformation;
	PVOID HeapInformation;
	PVOID LockInformation;
	PVOID Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

typedef struct _DEBUG_MODULE_INFORMATION { // c.f. SYSTEM_MODULE_INFORMATION
	SIZE_T Reserved[2];
	ULONG_PTR Base;
	ULONG Size;
	ULONG Flags;
	unsigned short Index;
	unsigned short Unknown;
	unsigned short LoadCount;
	unsigned short ModuleNameOffset;
	CHAR ImageName[256];
} DEBUG_MODULE_INFORMATION, *PDEBUG_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define SystemProcessesAndThreadsInformation 5

#define PDI_MODULES 0x01

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation, // 0 Y N
	ProcessQuotaLimits, // 1 Y Y
	ProcessIoCounters, // 2 Y N
	ProcessVmCounters, // 3 Y N
	ProcessTimes, // 4 Y N
	ProcessBasePriority, // 5 N Y
	ProcessRaisePriority, // 6 N Y
	ProcessDebugPort, // 7 Y Y
	ProcessExceptionPort, // 8 N Y
	ProcessAccessToken, // 9 N Y
	ProcessLdtInformation, // 10 Y Y
	ProcessLdtSize, // 11 N Y
	ProcessDefaultHardErrorMode, // 12 Y Y
	ProcessIoPortHandlers, // 13 N Y
	ProcessPooledUsageAndLimits, // 14 Y N
	ProcessWorkingSetWatch, // 15 Y Y
	ProcessUserModeIOPL, // 16 N Y
	ProcessEnableAlignmentFaultFixup, // 17 N Y
	ProcessPriorityClass, // 18 N Y
	ProcessWx86Information, // 19 Y N
	ProcessHandleCount, // 20 Y N
	ProcessAffinityMask, // 21 N Y
	ProcessPriorityBoost, // 22 Y Y
	ProcessDeviceMap, // 23 Y Y
	ProcessSessionInformation, // 24 Y Y
	ProcessForegroundInformation, // 25 N Y
	ProcessWow64Information // 26 Y N
} PROCESSINFOCLASS;

struct _UNICODE_STRING
{
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned short * Buffer;
};

typedef struct _PEB_LDR_DATA
{
    unsigned long Length;
    unsigned char Initialized;
    void * SsHandle;
    struct _LIST_ENTRY InLoadOrderModuleList;
    struct _LIST_ENTRY InMemoryOrderModuleList;
    struct _LIST_ENTRY InInitializationOrderModuleList;
    void * EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE {

  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
  PVOID                   BaseAddress;
  PVOID                   EntryPoint;
  ULONG                   SizeOfImage;
  UNICODE_STRING          FullDllName;
  UNICODE_STRING          BaseDllName;
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;


} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB
{
    unsigned char InheritedAddressSpace;
    unsigned char ReadImageFileExecOptions;
    unsigned char BeingDebugged;
    unsigned char SpareBool;
    void * Mutant;
    void * ImageBaseAddress;
    struct _PEB_LDR_DATA * Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS * ProcessParameters;
    void * SubSystemData;
    void * ProcessHeap;
    struct _RTL_CRITICAL_SECTION * FastPebLock;
    void * FastPebLockRoutine;
    void * FastPebUnlockRoutine;
    unsigned long EnvironmentUpdateCount;
    void * KernelCallbackTable;
    unsigned long SystemReserved[1];
    struct
    {
        unsigned long ExecuteOptions: 2;
        unsigned long SpareBits: 30;
    };
    struct _PEB_FREE_BLOCK * FreeList;
    unsigned long TlsExpansionCounter;
    void * TlsBitmap;
    unsigned long TlsBitmapBits[2];
    void * ReadOnlySharedMemoryBase;
    void * ReadOnlySharedMemoryHeap;
    void * * ReadOnlyStaticServerData;
    void * AnsiCodePageData;
    void * OemCodePageData;
    void * UnicodeCaseTableData;
    unsigned long NumberOfProcessors;
    unsigned long NtGlobalFlag;
    union _LARGE_INTEGER CriticalSectionTimeout;
    unsigned long HeapSegmentReserve;
    unsigned long HeapSegmentCommit;
    unsigned long HeapDeCommitTotalFreeThreshold;
    unsigned long HeapDeCommitFreeBlockThreshold;
    unsigned long NumberOfHeaps;
    unsigned long MaximumNumberOfHeaps;
    void * * ProcessHeaps;
    void * GdiSharedHandleTable;
    void * ProcessStarterHelper;
    unsigned long GdiDCAttributeList;
    void * LoaderLock;
    unsigned long OSMajorVersion;
    unsigned long OSMinorVersion;
    unsigned short OSBuildNumber;
    unsigned short OSCSDVersion;
    unsigned long OSPlatformId;
    unsigned long ImageSubsystem;
    unsigned long ImageSubsystemMajorVersion;
    unsigned long ImageSubsystemMinorVersion;
    unsigned long ImageProcessAffinityMask;
    unsigned long GdiHandleBuffer[34];
    void ( * PostProcessInitRoutine)();
    void * TlsExpansionBitmap;
    unsigned long TlsExpansionBitmapBits[32];
    unsigned long SessionId;
    union _ULARGE_INTEGER AppCompatFlags;
    union _ULARGE_INTEGER AppCompatFlagsUser;
    void * pShimData;
    void * AppCompatInfo;
    struct _UNICODE_STRING CSDVersion;
    void * ActivationContextData;
    void * ProcessAssemblyStorageMap;
    void * SystemDefaultActivationContextData;
    void * SystemAssemblyStorageMap;
    unsigned long MinimumStackCommit;
} PEB, *PPEB;

#ifdef _WIN64
typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS    ExitStatus;
    ULONG       Reserved0;
    PPEB        PebBaseAddress;
    ULONG64     AffinityMask;
    LONG        BasePriority;
    ULONG       Reserved1;
    ULONG64     uUniqueProcessId;
    ULONG64     uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
#endif

#ifdef _WIN32
typedef struct _PROCESS_BASIC_INFORMATION { // Information Class 0
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	KAFFINITY AffinityMask;
	KPRIORITY BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
#endif

typedef ULONG(WINAPI *pfnZwQuerySystemInformation) (ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef ULONG(WINAPI *pfnZwQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef DWORD(WINAPI *pfnGetModuleFileNameEx)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

typedef PDEBUG_BUFFER (WINAPI *pfnRtlCreateQueryDebugBuffer) (ULONG Size, BOOLEAN EventPair);
typedef DWORD (WINAPI *pfnRtlQueryProcessDebugInformation) (SIZE_T ProcessId, ULONG DebugInfoClassMask, PDEBUG_BUFFER DebugBuffer);
typedef DWORD (WINAPI *pfnRtlDestroyQueryDebugBuffer) (PDEBUG_BUFFER DebugBuffer);
typedef DWORD (WINAPI *pfnRtlpQueryRemoteProcessModules)	(HANDLE ProcessHandle, PRTL_PROCESS_MODULES Modules, ULONG Size, PULONG ReturnedSize);

static pfnZwQuerySystemInformation ZwQuerySystemInformation = NULL;
static pfnZwQueryInformationProcess ZwQueryInformationProcess = NULL;
//static pfnGetModuleFileNameEx GetModuleFileNameEx = NULL;

pfnRtlCreateQueryDebugBuffer RtlCreateQueryDebugBuffer = NULL;
pfnRtlQueryProcessDebugInformation RtlQueryProcessDebugInformation = NULL;
pfnRtlDestroyQueryDebugBuffer RtlDestroyQueryDebugBuffer = NULL;

#endif
