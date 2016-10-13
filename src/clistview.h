#ifndef __CLISTVIEW_H
#define __CLISTVIEW_H

#include <windows.h>
#include <commctrl.h>

typedef struct {
	HWND hWnd;
	HIMAGELIST hImageList;
	SIZE_T nElemsCount;
	SIZE_T nColumnCount;
} CListView;

CListView* CListView_Create(HINSTANCE hInstance, LPTSTR lpClassName, HWND hWndParent);
void CListView_Clear(CListView* lv);
void CListView_InsertColumns(CListView* lv, LVCOLUMN *lpColumn, size_t nCount);
void CListView_AppendLine(CListView* lv, LVITEM *li);
void CListView_ApplyImageList(CListView* lv);
void CListView_AddToImageList(CListView* lv, HICON hIcon);

#endif // __CLISTVIEW_H
