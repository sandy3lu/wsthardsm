/*!
 *  Copyright (C), 2001-2011, CETC30 SCW.
 *  \file       sm_inn_type_lnx.h
 *  \author     WorkGroup
 *  \version    V5.2.1105.0514
 *  \date       2011-05-05
 *  \note       define some macro, data type by api5.2.
 *
 *	History:        
 *
 *  [OS macro]
 *  WIN32       windows 32
 *  WIN64       windows 64, only vc2005
 *  __linux__   linux
 *
 *  #if _MSC_VER < 1300
 *  #error Compiler version not supported by Windows 64
 *  #endif
 *
 *  [linux macro]
 *  __KERNEL__  driver define
 *  MODULE      driver define
 *  __SMP__     multi-core
 *  -fPIC       directs the compiler to generate position independent code
 *              64bits system need, in CFLAGS
 */

#ifndef _SM_INN_TYPE_H_
#define _SM_INN_TYPE_H_

#include "sm_api_type.h"
	
//    typedef void*                   SM_HMODULE;

    #define WINAPI                  
    #define _MAX_PATH               260
#endif
