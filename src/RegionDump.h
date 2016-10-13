#ifndef _REGIONDUMP_H
#define _REGIONDUMP_H

#include <windows.h>
#include <commctrl.h>

#include "share.h"

#define DLG_REGION_ID  "#1002"

#define ID_REGION_LIST          4001
#define ID_REGION_EDIT_ADDRESS  4006
#define ID_REGION_EDIT_SIZE     4007
#define ID_REGION_BTN_REFRESH   4002

BOOL CALLBACK DumpRegionDialogProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

#endif
