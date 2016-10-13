#ifndef _PARTIALDUMP_H
#define _PARTIALDUMP_H

#include <windows.h>
#include <stdio.h>

#include "share.h"

#define DLG_PARTIAL_ID  "#1001"

#define ID_PART_EDIT_ADDRESS  4002
#define ID_PART_EDIT_SIZE     4003

#define ID_PART_LABEL_ADDRESS 4006
#define ID_PART_LABEL_SIZE    4007

BOOL CALLBACK DumpPartDialogProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

#endif
