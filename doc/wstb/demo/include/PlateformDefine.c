/////////////////////////////////////////////////////////////////////////////
/*  Copyright (C), 2001-2007, SiChuan Westone Co., Ltd.
    File name:   PlateformDefine.c
    Author:      Huo, Zeng
    Version:     V1.0.712.1816
    Date:        2007-12-07
    Description: The implement of Normal functions

    Function List:
    1. SWTest_GetIniConfig(), use to get ini configuration
    2. SWTest_Execute(int iTestItem), use to execute the test item
          iTestItem: 1-test function parameters
                     2-test function module
                     3-auto run

    History:
    1. 2007-12-07, Huo, Zeng, change to c
    2. 2007-12-18, Huo, Zeng, add Plat_SetPrintLock, Plat_FreePrintLock
*/
/////////////////////////////////////////////////////////////////////////////
#include "PlateformDefine.h"

#ifdef WIN32
    #include <process.h>
#elif __linux__
    #include <ctype.h>
    #include <pthread.h>
    #include <sys/time.h>
#endif
/////////////////////////////////////////////////////////////////////////////
#define MAX_CHAR_PERLINE     2049


/////////////////////////////////////////////////////////////////////////////
//	Inner functions using by Plat_GetProfileString
/////////////////////////////////////////////////////////////////////////////
SM_VOID GetFileLine(FILE* pFile, SM_CHAR* pData, SM_UINT uiSize);
SM_BOOL IsEmptyString(const SM_CHAR* pString);
SM_CHAR* findFirstCharacter(const SM_CHAR* pString);
SM_CHAR* isSection(SM_CHAR* pString, const SM_CHAR* pSection);
SM_CHAR* FindValue(SM_CHAR* pString, const SM_CHAR* pFieldName);

SM_THREADHANDLE Plat_CreateThread(SM_PTHREADFUN pThreadFun, SM_VOID* lpParameter)
{
#ifdef  WIN32
    UINT dwThreadID;
    return((SM_VOID*) _beginthreadex(NULL, 0, pThreadFun, lpParameter, 0, &dwThreadID));
	
#elif   __linux__
    pthread_t TempThread;
    pthread_create(&TempThread, NULL, pThreadFun, lpParameter);
    return TempThread;
#endif
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_VOID Plat_ReleaseThread(SM_THREADHANDLE phThread, unsigned long* pulRetCode)
{
#ifdef  WIN32
    WaitForSingleObject(phThread, INFINITE);
    GetExitCodeThread(phThread, pulRetCode);
    _endthread();
#elif   __linux__
    unsigned long   ulTemp = 0;
    pthread_join(phThread, (SM_VOID**)&ulTemp);
    *pulRetCode = ulTemp;
#endif
}

/////////////////////////////////////////////////////////////////////////////
//  time function
/////////////////////////////////////////////////////////////////////////////
SM_LONGLONG Plat_GetCPUFrequency(SM_VOID)
{
#ifdef  WIN32
    LARGE_INTEGER   i64CPUFrequency;

    i64CPUFrequency.QuadPart = 0;
    QueryPerformanceFrequency(&i64CPUFrequency);
    return (i64CPUFrequency.QuadPart);

#elif   __linux__
    return 1000000;
#endif
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_LONGLONG Plat_GetNowTick(SM_VOID)
{
#ifdef  WIN32
    LARGE_INTEGER   i64NowCount;

    i64NowCount.QuadPart = 0;
    QueryPerformanceCounter(&i64NowCount);
    return (i64NowCount.QuadPart);

#elif   __linux__
    struct timeval  NowTime;
    SM_LONGLONG     iTime;

    gettimeofday(&NowTime, NULL);
    iTime = 1000000 * NowTime.tv_sec + NowTime.tv_usec;
    return iTime;
#endif
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
struct tm* Plat_GetNowTime(SM_VOID)
{
    time_t      NowTime;
    struct tm*  pTime;

    time(&NowTime);
    pTime = gmtime(&NowTime);
    pTime->tm_year += 1900;
    pTime->tm_mon  += 1;
    pTime->tm_hour += 8;
    return pTime;
}


/////////////////////////////////////////////////////////////////////////////
//Get current working directory
/////////////////////////////////////////////////////////////////////////////
SM_BOOL  Plat_GetCWD(SM_CHAR* pFileName, SM_BOOL bIsFullPath)
{
#ifdef  WIN32
    PCHAR pStrPtr = NULL;
    DWORD dwRet   = GetModuleFileName(NULL, pFileName, _MAX_PATH);
    if(dwRet == 0)
        return FALSE;

    pStrPtr = strrchr(pFileName, '\\');
    if(bIsFullPath)
        pStrPtr++;
    *pStrPtr = '\0';

#elif   __linux__
    SM_CHAR*	pRet = 0;

    pRet = getcwd(pFileName, _MAX_PATH);
    if(pRet == NULL)
        return FALSE;
    if(bIsFullPath)
        strcat(pFileName, "/");
#endif

    return TRUE;
}
//get file size
SM_UINT Inn_GetFileSize(SM_CHAR *pFileName)
{
    FILE* pFile = 0;
    SM_LONG  lStart = 0, lStop = 0, lLength = 0;
    
    if( (pFileName == NULL) || (strlen(pFileName) < 1) )
        goto LB_END;
    
    pFile = fopen(pFileName, "rb");
    if( pFile == NULL )
        goto LB_END;
    
    //seek to begin of the file
    if( fseek(pFile, 0, SEEK_SET) != 0 )
        goto LB_END;
    lStart = ftell(pFile);
    if( lStart == -1 )
        goto LB_END;
    
    //seek to the end of the file
    if( fseek(pFile, 0, SEEK_END) != 0 )
        goto LB_END;
    lStop = ftell(pFile);
    if( lStop == -1 )
        goto LB_END;
    
    //get file length
    lLength = lStop - lStart;
    
LB_END:
    if(pFile != NULL)
    {
        fseek(pFile, 0, SEEK_SET);
        fclose(pFile);
    }
    
    return (SM_UINT)lLength;
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//read file data
SM_UINT Inn_ReadFileData(SM_CHAR *pFileName, SM_BYTE *pbyData)
{
    FILE*    pFilePtr  = 0;
    SM_UINT  uiFileLen = Inn_GetFileSize(pFileName);
    
    if( pbyData == NULL )
        return 0;
    if( uiFileLen == 0 )
        return 0;
    
    pFilePtr = fopen(pFileName, "rb");
    if( pFilePtr == NULL )
        return 0;
    
    fread(pbyData, 1, uiFileLen, pFilePtr);
    fclose(pFilePtr);
    return uiFileLen;
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//wirte file data
SM_VOID  Inn_WriteFileData(SM_CHAR *pFileName, SM_BYTE *pbyData, SM_UINT uiLen)
{
    FILE*   pFilePtr = 0;
    
    if( pbyData == NULL )
        return;
    if( uiLen == 0 )
        return;
    
    pFilePtr = fopen(pFileName, "wb+");
    if( pFilePtr == NULL )
        return;
    
    fwrite(pbyData, 1, uiLen, pFilePtr);
    fclose(pFilePtr);
}

//////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//	get ini info function
/////////////////////////////////////////////////////////////////////////////
SM_INT Plat_GetProfileString(const SM_CHAR *pConfigFilename, 
                          const SM_CHAR *pSection, const SM_CHAR *pFieldName,
                          SM_CHAR *pValue, SM_INT MaxValueLen)
{
    SM_BOOL    bSectionFound = FALSE;
    SM_CHAR     str[MAX_CHAR_PERLINE]={0};
    SM_CHAR    *pValidString = NULL, *pResult = NULL;
    FILE*   pFile = NULL;

    if( (pConfigFilename == NULL) || (pSection == NULL) || 
                    (pFieldName == NULL) || (pValue == NULL) )
        return UTIL_ERR_PARAMS;
    if(MaxValueLen < 1)
        return UTIL_ERR_PARAMS;
    if( (strlen(pConfigFilename) < 1) || (strlen(pSection)< 1) || 
                    (strlen(pFieldName) < 1))
        return UTIL_ERR_PARAMS;

    pFile = fopen(pConfigFilename, "rb");
    if( pFile == NULL )
        return UTIL_ERR_FILE;

    while( !feof(pFile) )
    {
        GetFileLine(pFile, str, MAX_CHAR_PERLINE);
//        inifile.getline(str, MAX_CHAR_PERLINE);
        if( !IsEmptyString(str) )
        {
            //get rid of the space and tab fore
            pValidString = findFirstCharacter(str);
            if(pValidString == NULL)
                continue;

            if(!bSectionFound)
            {
                //find section:
                pResult = NULL;
                pResult = isSection(pValidString, pSection);
                if(pResult == NULL)
                    continue;

                bSectionFound = TRUE;
            }
            else
            {
                //find value string in section
                if(pValidString[0] == '[') //should be next section
                {
                    return UTIL_ERR_NOFIELD;
                }
                pResult = NULL;
                pResult = FindValue(pValidString, pFieldName);
                if(pResult == NULL)
                    continue;
                if(MaxValueLen < (int)(strlen(pResult) + 1))
                    return UTIL_ERR_BUFTOOSMALL;
                strcpy(pValue, pResult);
                break;
            }
        }
    }//while
    fclose(pFile);

    if(!bSectionFound)
        return UTIL_ERR_NOSECTION;

    return UTIL_ERR_FREE; 
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//	Inner functions
//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_VOID GetFileLine(FILE* pFile, SM_CHAR* pData, SM_UINT uiSize)
{
    SM_CHAR    byTemp = 0, *pPtr = pData;
    SM_INT     iTemp  = 0;

    memset(pData, 0, uiSize);
    while( (byTemp != '\n') )
    {
        iTemp = fread( &byTemp, 1, 1, pFile);
        if(iTemp == 0)
            break;

        *pPtr = byTemp;
        pPtr++;

        if ( (SM_ULONG)(pPtr - pData) > uiSize )
            break;
    }//while
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_BOOL IsEmptyString(const SM_CHAR* pString)
{
    if(pString == NULL)
        return TRUE;
    if((pString[0] == '#') || (pString[0] == ';'))
        return TRUE;

    while(*pString != '\0')
    {
        if(isprint(*pString) && (*pString != ' ') && (*pString != '\t')
                     && (*pString != '\r') && (*pString != '\n'))
            return FALSE;
        pString++;
    }
    return TRUE;
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_CHAR* findFirstCharacter(const SM_CHAR* pString)
{
    while(*pString != '\0')
    {
        if((*pString != ' ') && (*pString != '\t')
                     && (*pString != '\r') && (*pString != '\n'))
            return (SM_CHAR*)pString;

        pString++;
    }
    return NULL;
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_CHAR* isSection(SM_CHAR* pString, const SM_CHAR* pSection)
{
    SM_CHAR* pLeftpos = NULL;

    if(pString[0] != '[') //not a valid section
        return NULL;

    pString++;
    pString = findFirstCharacter(pString);
    pLeftpos = strchr(pString, ']');
    *pLeftpos = '\0';
    pLeftpos++;
    if(pLeftpos == NULL)
        return NULL;
    if(IsEmptyString(pLeftpos))
    {
        SM_CHAR* pTemp = (SM_CHAR*)pSection;
#ifdef  WIN32
        if(strnicmp(pString, pTemp, strlen(pTemp)) != 0)
            return NULL;
#elif   __linux__
        if(strncasecmp(pString, pTemp, strlen(pTemp)) != 0)
            return NULL;
#endif
        return pString;
    }
    return NULL;
}

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
SM_CHAR* FindValue(SM_CHAR* pString, const SM_CHAR* pFieldName)
{
    SM_CHAR strField[_MAX_PATH] = {0}, strTemp[_MAX_PATH] = {0};
    SM_CHAR* pTemp = NULL;

    strcpy(strField, pFieldName);
    strcpy(strTemp,  pString);
#ifdef  WIN32
    strlwr(strTemp);
    strlwr(strField);
#elif   __linux__
    SM_UINT i;
    for(i=0; i<strlen(strTemp); ++i)
        strTemp[i] = tolower(strTemp[i]);
    for(i=0; i<strlen(strField); ++i)
        strField[i] = tolower(strField[i]);
#endif
    if(strstr(strTemp, strField) == strTemp)
    {
        pString += strlen(strField);
        pString = findFirstCharacter(pString);
        if(*pString == '=')
        {
            pString++;
            pString = findFirstCharacter(pString);
            pTemp = pString + strlen(pString);
            pTemp--;
            while((*pTemp == ' ') || (*pTemp == '\t')
                     || (*pTemp == '\r') || (*pTemp == '\n'))
            {
                pTemp--;
                if(pTemp <= pString)
                    break;
            }
            pTemp++;
            *pTemp = '\0';
            return pString;
        }
    }
    return NULL;
}


/////////////////////////////////////////////////////////////////////////////
//	printf with color control
//  note:   the end of format string do not need "\n"!
/////////////////////////////////////////////////////////////////////////////
SM_VOID Plat_Inn_Printf(MSGINFO *pMsgInfo, SM_CHAR *pOutString)
{
/*
#ifdef  WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    unsigned short wFore = 0, wBack = 0;
    SWH_PLATFORM   *strPlat;
    SM_CRITICAL* Critical = NULL;
    
    strPlat = SWH_CreatePlatformInterface();
    Critical = strPlat->CreateCriticalSecInterface();

    if(pMsgInfo->bIsDefault)
    {
        goto LB_DISPLAY;
    }
    else
    {
        if( pMsgInfo->byForegroundColor > 0x0F )
        {   //error, use default value
            goto LB_DISPLAY;
        }
        if( pMsgInfo->byBackgroundColor > 0x0F )
        {   //error, use default value
            goto LB_DISPLAY;
        }
        wFore = pMsgInfo->byForegroundColor;
        wBack = pMsgInfo->byBackgroundColor;
        wBack = (unsigned short)((wBack << 4) | wFore);
        SetConsoleTextAttribute(hConsole, wBack); 
    }

LB_DISPLAY:
    printf("%s\n", pOutString);
    SetConsoleTextAttribute(hConsole, CON_COLOR_WHITE); 
    if( (pMsgInfo->byForegroundColor== CON_COLOR_WHITE) && 
                    (pMsgInfo->byBackgroundColor == CON_COLOR_RED) )
        printf("\n");

#elif   _LINUX
    if(g_hPrintEvent != NULL)
    {
        g_hPrintEvent->TestCriticalLock(g_hPrintEvent);
    }

    if(pMsgInfo->bIsDefault)
    {   //default-F:white, B:black
        printf("%s\n", pOutString);
    }
    else
    {   //custom color
        if( pMsgInfo->byForegroundColor > 0x08 )   //error, use default value-white
            pMsgInfo->byForegroundColor = CON_COLOR_WHITE;

        //MYPRINTF(byTempF, byTempB, pOutString);
        if(pMsgInfo->bIsBold)
        {
            switch(pMsgInfo->byForegroundColor)
            {
            case CON_COLOR_RED:
                printf("\033[1;31m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_GREEN:
            case CON_COLOR_DGREEN:
                printf("\033[1;32m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_BLUE:
                printf("\033[1;34m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_YELLOW:
                if(pMsgInfo->byBackgroundColor == CON_COLOR_BLUE)
                    printf("\033[1;33;44m%s\033[0m \n", pOutString);
                else
                    printf("\033[1;33m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_DRED:
                printf("\033[1;35m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_DBLUE:
                printf("\033[1;36m%s\033[0m \n", pOutString);
                break;
            default:
                if(pMsgInfo->byBackgroundColor == CON_COLOR_RED)
                    printf("\033[1;37;41m%s\033[0m \n", pOutString);
                else
                    printf("%s\n", pOutString);
            }//switch
        }
        else
        {
            switch(pMsgInfo->byForegroundColor)
            {
            case CON_COLOR_RED: 
                printf("\033[31m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_GREEN:
            case CON_COLOR_DGREEN:
                printf("\033[32m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_BLUE:
                printf("\033[34m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_YELLOW:
                if(pMsgInfo->byBackgroundColor == CON_COLOR_BLUE)
                    printf("\033[33;44m%s\033[0m \n", pOutString);
                else
                    printf("\033[33m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_DRED:
                printf("\033[35m%s\033[0m \n", pOutString);
                break;
            case CON_COLOR_DBLUE:
                printf("\033[36m%s\033[0m \n", pOutString);
                break;
            default:
                if(pMsgInfo->byBackgroundColor == CON_COLOR_RED)
                    printf("\033[37;41m%s\033[0m \n\n", pOutString);
                else
                    printf("%s\n", pOutString);
            }
        }//if_bold
    }
#endif
    
    strPlat->ReleaseCriticalSecInterface(Critical);
*/
}

/////////////////////////////////////////////////////////////////////////////
SM_VOID Plat_Printf(SM_INT iFormatFlag, SM_CHAR *pOutString)
{
    MSGINFO MsgInfo;
    
    switch(iFormatFlag)
    {
    case CON_COLOR_FLAG:    //Yellow+Blue
        MsgInfo.bIsDefault = FALSE;
        MsgInfo.bIsBold           = TRUE;
        MsgInfo.byForegroundColor = CON_COLOR_YELLOW;
        MsgInfo.byBackgroundColor = CON_COLOR_BLUE;
        break;
    case CON_COLOR_WARNING: //White+Red
        MsgInfo.bIsDefault = FALSE;
        MsgInfo.bIsBold           = TRUE;
        MsgInfo.byForegroundColor = CON_COLOR_YELLOW;//CON_COLOR_WHITE;
        MsgInfo.byBackgroundColor = CON_COLOR_RED;
        break;
    default:
        MsgInfo.bIsDefault = TRUE;
    }
    Plat_Inn_Printf(&MsgInfo, pOutString);
}

/////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
int write_hex(char* strFileName, unsigned char *buff, int length)
{
    unsigned char *string_tmp = buff;
    SM_CHAR strData[50000] = {0};
    SM_CHAR* strTmp = strData;
    int i = 0, filelen = 0;
    int count = 0;
    FILE*   pFile = 0;
   
    sprintf(strTmp, "\n");
    strTmp++;
    
    for(i = 0; i< length; i++, count++)
    {
        if(count < 16)
        {
            sprintf(strTmp, "%02x ", string_tmp[i]);
            strTmp += 3;
            filelen += 3;
        }
        else
        {
            count = 0;
            sprintf(strTmp, "\n%02x ", string_tmp[i]);
            strTmp += 4;
            filelen += 4;
            continue;
        }
    }
	/*
    sprintf(strTmp, "\ndata length: %d\n", length);
    filelen += 20;
	*/
    sprintf(strTmp, "\n\n");
    filelen += 3;
    pFile = fopen(strFileName, "a+");
    fwrite(strData, 1, filelen, pFile);
    fclose(pFile);
    return 0;
}