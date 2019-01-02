/////////////////////////////////////////////////////////////////////////////
/*
    File:           PlateformDefine.h
    Description:    Normal functions without regard to OS	
    Creator:        Huo&Zeng, 2007-11-28
    Version:        V1.0.712.1816

    History:
    1. 2007-12-10, Huo, add define USBKEY_ONEDEV_SHARE, USBKEY_ONEDEV_EXCLUSIVE
    2. 2007-12-18, Huo, Zeng, add define Plat_SetPrintLock, Plat_FreePrintLock
*/
/////////////////////////////////////////////////////////////////////////////
#ifndef PLATFORM_INDEPENDENT_HEADER_FILE_BY_HBABY
#define PLATFORM_INDEPENDENT_HEADER_FILE_BY_HBABY

#include "sm_api_type.h"

#ifdef  WIN32
    #include <process.h>

    typedef HINSTANCE               SM_HMODULE;
    typedef __int64                 SM_LONGLONG;
    typedef SM_HANDLE               SM_THREADHANDLE;
    typedef unsigned                SM_THREADFUNRET;
    typedef unsigned (__stdcall *SM_PTHREADFUN)( PSM_VOID );

#elif  __linux__
    #include "sm_inn_type_lnx.h"
    #include <dlfcn.h>
    #include <stdarg.h>
    #include <pthread.h>
    #include <sys/time.h>

    typedef long long               SM_LONGLONG;
    typedef void*                   SM_HMODULE;
    typedef pthread_t               SM_THREADHANDLE;
    typedef PSM_VOID                SM_THREADFUNRET;
    typedef PSM_VOID (*SM_PTHREADFUN)( PSM_VOID );

    #define _MAX_PATH               260 

#endif

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


/////////////////////////////////////////////////////////////////////////////
//define the error code
#define SWTEST_ERR_FREE             0x0000  //ok
#define SWTEST_ERR_INVALID_HANDLE   0x1001  
#define SWTEST_ERR_INVALID_PARAM    0x1002  
#define SWTEST_ERR_INVALID_DEVNUM   0x1003  
#define SWTEST_ERR_INVALID_DEVINDEX 0x1004  
#define SWTEST_ERR_INVALID_DEVSTATE 0x1005
#define SWTEST_ERR_DLL_LOADED       0x1006  
#define SWTEST_ERR_DLL_NOTLOAD      0x1007  
#define SWTEST_ERR_DLL_LOADFAIL     0x1008  
#define SWTEST_ERR_HUID_SAME        0x1009  
#define SWTEST_ERR_HUID_DIFFERENT   0x100A  
#define SWTEST_ERR_LEN              0X100B

SM_THREADHANDLE Plat_CreateThread(SM_PTHREADFUN pThreadFun, void* lpParameter);
void Plat_ReleaseThread(SM_THREADHANDLE phThread, unsigned long* pulRetCode);

//load api dll
SM_HMODULE Plat_LoadAPIDll(SM_CHAR* pAPIFileName);
SM_VOID Plat_UnLoadAPIDll(SM_HMODULE hAPIDll);
//Plat_GetFunction see macro GETDLLFUNADDRESS
#ifdef	WIN32
    #define API_LOADDLL(hDLLLib, pAPIFileName) do{\
        hDLLLib = LoadLibrary(pAPIFileName); }while(0)

    #define API_GETFUNADDRESS_DF(pMang, FunName) do{\
        pMang->m_pfn_##FunName = (##FunName)GetProcAddress(pMang->m_hDLLLib, #FunName); \
        if(pMang->m_pfn_##FunName == 0) return SWTEST_ERR_DLL_LOADFAIL; } while(0)

    #define API_UNLOADDLL(hDLLLib) do{\
        FreeLibrary(hDLLLib); }while(0)

#elif __linux__
    #define API_LOADDLL(hDLLLib, pAPIFileName) do{\
        SM_VOID*    pHandle = 0;\
        SM_CHAR* pszErr;\
        pHandle = dlopen(pAPIFileName, RTLD_LAZY|RTLD_GLOBAL);\
        if( pHandle == NULL ) {\
            hDLLLib = 0;\
            pszErr  = dlerror();\
            printf("[Error] dlopen: %s\n", pszErr);\
        }\
        else {\
            hDLLLib = pHandle; \
        } }while(0)

    #define API_GETFUNADDRESS_DF(pMang, FunName) do{\
        SM_CHAR *pszErr;\
        pMang->m_pfn_##FunName = (FunName)dlsym(pMang->m_hDLLLib, #FunName);\
        pszErr = dlerror();\
        if ( pszErr != NULL ) return SWTEST_ERR_DLL_LOADFAIL;}while(0)

    #define API_UNLOADDLL(hDLLLib) do{\
        dlclose(hDLLLib); }while(0)
#endif
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
//Get time
SM_LONGLONG Plat_GetCPUFrequency();
SM_LONGLONG Plat_GetNowTick();
struct tm* Plat_GetNowTime();
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
//Get working directory
SM_BOOL  Plat_GetCWD(SM_CHAR* pFileName, SM_BOOL bIsFullPath);
SM_UINT  Inn_GetFileSize(SM_CHAR *pFileName);
SM_UINT  Inn_ReadFileData(SM_CHAR *pFileName, SM_BYTE *pbyData);
SM_VOID     Inn_WriteFileData(SM_CHAR *pFileName, SM_BYTE *pbyData, SM_UINT uiLen);
/////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//	get ini info function
#define UTIL_ERR_FREE            0
#define UTIL_ERR_FILE            1
#define UTIL_ERR_NOSECTION       2
#define UTIL_ERR_NOFIELD         3
#define UTIL_ERR_BUFTOOSMALL     4
#define UTIL_ERR_PARAMS          5

SM_INT Plat_GetProfileString(const SM_CHAR *pConfigFilename, 
                          const SM_CHAR *pSection, const SM_CHAR *pFieldName,
                          SM_CHAR *pValue, SM_INT MaxValueLen);
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
//  printf with color control
#ifdef  WIN32
    #define CON_COLOR_BLACK     0x00
    #define CON_COLOR_WHITE     0x07
    #define CON_COLOR_BLUE      0x09
    #define CON_COLOR_DBLUE     0x01
    #define CON_COLOR_GREEN     0x0A
    #define CON_COLOR_DGREEN    0x03
    #define CON_COLOR_RED       0x0C
    #define CON_COLOR_DRED      0x04
    #define CON_COLOR_YELLOW    0x0E
#elif   __linux__
    #define CON_COLOR_BLACK     0x00
    #define CON_COLOR_WHITE     0x07

    #define CON_COLOR_RED       0x01
    #define CON_COLOR_GREEN     0x02
    #define CON_COLOR_BLUE      0x06
    #define CON_COLOR_YELLOW    0x03

    #define CON_COLOR_DRED      0x05
    #define CON_COLOR_DGREEN    0x08
    #define CON_COLOR_DBLUE     0x04
#endif
//Plat_Printf use
#define CON_COLOR_NORMAL        0x01    //White+Black
#define CON_COLOR_FLAG          0x02    //Yellow+Blue
#define CON_COLOR_WARNING       0x03    //White+Red
//
typedef struct _MSGINFO{
    SM_BOOL bIsDefault;
    SM_BOOL bIsBold;
    SM_CHAR byForegroundColor; 
    SM_CHAR byBackgroundColor; 
}MSGINFO, *PMSGINFO;
SM_VOID Plat_Inn_Printf(MSGINFO *pMsgInfo, SM_CHAR *pOutString);
SM_VOID Plat_Printf(SM_INT iFormatFlag, SM_CHAR *pOutString);
static int write_hex(char* strFileName, unsigned char *buff, int length);

/////////////////////////////////////////////////////////////////////////////

#endif//PLATFORM_INDEPENDENT_HEADER_FILE_BY_HBABY
