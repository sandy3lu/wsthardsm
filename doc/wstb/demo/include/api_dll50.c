/* /////////////////////////////////////////////////////////////////////////// */
/*  Copyright (C), 2001-2007, SiChuan Westone Co., Ltd.
    File name:   api_dll.c
    Author:      Huo
    Version:     V1.0.803.2511
    Date:        2008-3-11
    Description: Implement the class for managing basic test

    History:

*/
/* /////////////////////////////////////////////////////////////////////////// */
#include "api_dll50.h"
#include "PlateformDefine.h"
/* /////////////////////////////////////////////////////////////////////////// */
/* 1. load dll dynamic */
unsigned short Dll_Load(SWDLLMANGHANDLE	pDllMang, char* pAPIPath)
{
    SWAPI50DllMang* pDeviceMang = (SWAPI50DllMang*)pDllMang;

    if ( pDeviceMang->m_hDLLLib != NULL )
        return SWTEST_ERR_DLL_LOADED;

    if ( pDllMang == NULL )
        return SWTEST_ERR_INVALID_HANDLE;
    if ( pAPIPath == NULL )
        return SWTEST_ERR_INVALID_PARAM;

    API_LOADDLL(pDeviceMang->m_hDLLLib, pAPIPath);
    if ( pDeviceMang->m_hDLLLib == NULL )
        return SWTEST_ERR_DLL_LOADFAIL;

    /* load default functions */
    API_GETFUNADDRESS_DF(pDeviceMang, SM_GetDeviceNum);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_GetErrorString);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_OpenDevice);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_CloseDevice);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_OpenSecPipe);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_CloseSecPipe);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_Login);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_Logout);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_Encrypt);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_Decrypt);

    API_GETFUNADDRESS_DF(pDeviceMang, SM_ECCEncrypt);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ECCDecrypt);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ECCSignature);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ECCVerify);

    API_GETFUNADDRESS_DF(pDeviceMang, SM_GetCfgKeyHandle);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_GenerateKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ImportKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ExportKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_DestroyKey);

    API_GETFUNADDRESS_DF(pDeviceMang, SM_GenerateKeyPair);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ImportPublicKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ImportPrivateKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ExportPublicKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ExportPrivateKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_DestroyPublicKey);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_DestroyPrivateKey);

    API_GETFUNADDRESS_DF(pDeviceMang, SM_BuildAuthDev);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_BackupAuthDev);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_ChangeUserPin);
    API_GETFUNADDRESS_DF(pDeviceMang, SM_UpdateKeyPair);

    return SWTEST_ERR_FREE;
}

/* ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, */
/* 2. unload dll dynamic */
unsigned short Dll_Unload(SWDLLMANGHANDLE hDllMang)
{
    SWAPI50DllMang* pDeviceMang = (SWAPI50DllMang*)hDllMang;

    if (hDllMang == NULL)
        return SWTEST_ERR_INVALID_HANDLE;

    if (pDeviceMang->m_hDLLLib == NULL)
        return SWTEST_ERR_FREE;

    API_UNLOADDLL(pDeviceMang->m_hDLLLib);
    return SWTEST_ERR_FREE;
}

/* ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, */
/* 3. check load status */
SM_BOOL Dll_IsLoad(SWDLLMANGHANDLE	hDllMang)
{
    SWAPI50DllMang* pDeviceMang = (SWAPI50DllMang*)hDllMang;

    if ( hDllMang == NULL )
        return FALSE;

    return pDeviceMang->m_bLoadDLL;
}

/* /////////////////////////////////////////////////////////////////////////// */
/* /////////////////////////////////////////////////////////////////////////// */
SWAPI50DllMang* GetDllMangInterface()
{
    SWAPI50DllMang* pSWDllMang = (SWAPI50DllMang*)malloc(sizeof(SWAPI50DllMang));
    memset(pSWDllMang, 0, sizeof(SWAPI50DllMang));

    pSWDllMang->Dll_Load    = Dll_Load;
    pSWDllMang->Dll_Unload  = Dll_Unload;
    pSWDllMang->Dll_IsLoad  = Dll_IsLoad;
    return pSWDllMang;
}

/* ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, */
void DelDllMangInterface(SWAPI50DllMang* pDllMang)
{
    if ( pDllMang == NULL )
        return;

    free(pDllMang);
    pDllMang = NULL;
}

/* /////////////////////////////////////////////////////////////////////////// */
