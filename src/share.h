#ifndef _SHARE_H
#define _SHARE_H

#include <stdio.h>
#include <stdlib.h>

static const TCHAR gszTitle[] = "FRT Dumper v0.8";

enum {PROCESS_TYPE, MODULE_TYPE, PARTIAL_TYPE, REGION_TYPE};

HWND ghWndMain;

extern ULONG uSelectedPid;
extern CHAR szSelectedModule[MAX_PATH];

typedef struct DUMPPART_INIT{
	ULONG Type;
	ULONG dwProcId;
	ULONG_PTR Address;
	ULONG_PTR Size;
} DUMPPART_INIT, *PDUMPPART_INIT;

// Эта структура заполняется перед вызовом окон дампа, правится если надо, и передается в DumpMemory
struct DUMPPART_INIT dmpData;

extern BOOL DumpMemory(PDUMPPART_INIT lpDmpData, HWND hWndParent);

#endif
