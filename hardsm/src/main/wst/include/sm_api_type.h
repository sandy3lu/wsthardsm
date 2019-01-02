/*!
 *  Copyright (C), 2001-2011, CETC30 SCW.
 *  \file       sm_api_type.h
 *  \author     WorkGroup
 *  \version    V5.2.1108.2415
 *  \date       2011-08-24
 *  \warning    define some macro, data type by api5.2.
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

#ifndef _SM_API_TYPE_H_
#define _SM_API_TYPE_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#ifdef  WIN32
    #include <windows.h>

#elif   WIN64
    #include <windows.h>

#elif   __linux__
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/ipc.h>
    #include <sys/sem.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>

    #include <sys/ipc.h>
    #include <sys/sem.h>
    #include <sys/ioctl.h>

    #define CTL_CODE(DeviceType, Function, Method, Access) \
                ( ((DeviceType) << 16) | ((Access) << 14)  \
                | ((Function) << 2) | (Method) )
#endif

#ifndef FALSE
#define FALSE                   0
#endif

#ifndef TRUE
#define TRUE                    (!FALSE)
#endif

/* ///////////////////////////////////////////////////////////////////////// */
/*
 * <Windows>
 *  CreateFile return fails
 *
 * <Linux>
 *  open, create, semget, read, write return fails
 */
/* ///////////////////////////////////////////////////////////////////////// */
#ifdef  WIN32
    #ifndef SM_INVALID_HANDLE_VALUE
        #define SM_INVALID_HANDLE_VALUE     (~0UL)
    #endif

#elif   WIN64
    #ifndef SM_INVALID_HANDLE_VALUE
        #define SM_INVALID_HANDLE_VALUE     (~0UL)
    #endif

#elif  __linux__
    #ifndef SM_INVALID_HANDLE_VALUE
        #define SM_INVALID_HANDLE_VALUE     -1
    #endif

    #define __cdecl
    #define __stdcall

#endif


/* ///////////////////////////////////////////////////////////////////////// */
/*
 * <Windows>
 *  1. CreateEvent, CreateMutex return fails
 *  2. new class return fails
 *  3. DeviceIoControl(BOOL) return fails
 *
 * <Linux>
 *  1. DeviceIoControl(BOOL) return fails
 */
/* ///////////////////////////////////////////////////////////////////////// */
#ifndef SM_NULL_HANDLE_VALUE
#define SM_NULL_HANDLE_VALUE        0
#endif

#ifndef SM_NULL
#define SM_NULL                     0
#endif

#ifndef SM_CRITICAL_SECTION
#define SM_CRITICAL_SECTION         unsigned int
#endif

#ifndef SM_WPARAM
#define SM_WPARAM                   unsigned int
#endif

#ifndef SM_LPARAM
#define SM_LPARAM                   unsigned int
#endif


/* ///////////////////////////////////////////////////////////////////////// */
/* data type define */
/* ///////////////////////////////////////////////////////////////////////// */
typedef char                    SM_CHAR;
typedef unsigned char           SM_BYTE;
typedef unsigned char           SM_UCHAR;
typedef unsigned short          SM_USHORT;
typedef unsigned short          SM_WORD;
typedef int                     SM_INT;
typedef unsigned int            SM_UINT;
typedef unsigned int            SM_BOOL;
typedef unsigned int            SM_RV;

typedef long                    SM_LONG;
typedef	unsigned long           SM_ULONG;

#ifdef WIN32
  typedef unsigned __int64      SM_UINT64;
  typedef __int64               SM_INT64;
#elif  WIN64
  typedef unsigned __int64      SM_UINT64;
  typedef __int64               SM_INT64;
#elif   __linux__
  typedef unsigned long long    SM_UINT64;
  typedef long long             SM_INT64;
#endif

typedef SM_CHAR     *           PSM_CHAR;
typedef SM_BYTE     *           PSM_BYTE;
typedef SM_UCHAR    *           PSM_UCHAR;
typedef SM_USHORT   *           PSM_USHORT;
typedef SM_WORD     *           PSM_WORD;
typedef SM_INT      *           PSM_INT;
typedef SM_UINT     *           PSM_UINT;
typedef SM_BOOL     *           PSM_BOOL;
typedef SM_LONG     *           PSM_LONG;
typedef SM_ULONG    *           PSM_ULONG;

typedef void                    SM_VOID;
typedef SM_VOID     *           PSM_VOID;
typedef PSM_VOID    *           PPSM_VOID;

typedef void        *           SM_HANDLE;
typedef SM_HANDLE   *           PSM_HANDLE;

typedef SM_UINT64   *           PSM_UINT64;

/* ///////////////////////////////////////////////////////////////////////// */
/* api5.0, api5.2 */
/* ///////////////////////////////////////////////////////////////////////// */
typedef SM_UINT                 SM_ALGORITHM_TYPE;
typedef SM_UINT                 SM_KEY_TYPE;
typedef SM_UINT                 SM_MEM_TYPE;
typedef SM_UINT                 SM_CERTIFICATE_TYPE;
typedef SM_UINT                 SM_CERT_FIELD_TYPE;
typedef SM_UINT                 SM_EVENT_TYPE;

typedef SM_HANDLE               SM_DEVICE_HANDLE;
typedef SM_HANDLE               SM_PIPE_HANDLE;
typedef SM_HANDLE               SM_KEY_HANDLE;
typedef SM_HANDLE               SM_ECC_PARA_HANDLE;

typedef SM_HANDLE   *           PSM_DEVICE_HANDLE;
typedef SM_HANDLE   *           PSM_PIPE_HANDLE;
typedef SM_HANDLE   *           PSM_KEY_HANDLE;
typedef SM_HANDLE   *           PSM_ECC_PARA_HANDLE;

#endif
