
// my_router.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cmy_routerApp:
// �йش����ʵ�֣������ my_router.cpp
//

class Cmy_routerApp : public CWinApp
{
public:
	Cmy_routerApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Cmy_routerApp theApp;