/* ///////////////////////////////////////////////////////////////////////// */
/* header files */
#include "PlateformDefine.h"
#include "api_dll50.h"
#define MAX_PATH               260
/* ///////////////////////////////////////////////////////////////////////// */
typedef struct _SW_TEST_HANDLE
{
    SM_DEVICE_HANDLE    hDevice;
    SM_PIPE_HANDLE      hPipe;
}SW_TEST_HANDLE, *PSW_TEST_HANDLE;

/* global variable */
SWAPI50DllMang *g_pDllMang = SM_NULL;
SW_TEST_HANDLE	g_stHandle;
/* ///////////////////////////////////////////////////////////////////////// */
#ifdef __linux__
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifdef _WINDOWS_
#define API_DLL_NAME "sw11513061_a2000_v52.dll"
#else
#define API_DLL_NAME "libsw11513061_a2000_v52.so"
#endif
#define CON_LEN_FILEPATH 256

SM_BOOL Inn_LoadAPI();
SM_VOID  Inn_UnLoadAPI();

SM_BOOL Inn_OpenDevice();
SM_BOOL Inn_CloseDevice();
SM_BOOL Inn_Login();
SM_BOOL Inn_Logout();
SM_VOID Inn_UpdateDate(SM_BYTE* pbyData);
SM_BOOL Inn_gen_sym_key(PSM_KEY_HANDLE phKey);
SM_BOOL Inn_destroy_sym_key(PSM_KEY_HANDLE phKey);
SM_BOOL Inn_gen_ecc_key(PSM_KEY_HANDLE phPubKey, PSM_KEY_HANDLE phPriKey);
SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPubKey, SM_KEY_HANDLE hPriKey);
SM_BOOL Inn_export_sym_key(SM_KEY_HANDLE hKey);
SM_BOOL Inn_export_asym_key(SM_KEY_HANDLE hPubKey, SM_KEY_HANDLE hPriKey);

/* ///////////////////////////////////////////////////////////////////////// */
/* main function                                                             */
/* ///////////////////////////////////////////////////////////////////////// */
SM_INT main()
{
    SM_RV                   ret = SM_ERR_FREE;
	SM_KEY_HANDLE			hKey, hPubKey, hPriKey;
		
	/* load API */
	if ( !Inn_LoadAPI() ) 
        return 0;
	
	/* Open Device */
    if ( !Inn_OpenDevice() )
		return 0;

	/* Login*/
    if ( !Inn_Login() )
		goto LB_END;
	
	/* Generate symm_key*/
	if (!Inn_gen_sym_key(&hKey))
		goto LB_END;
	
	if (!Inn_export_sym_key(hKey))
		goto LB_END;
	
	/* Generate Asymm_key*/
	if (!Inn_gen_ecc_key(&hPubKey, &hPriKey))
		goto LB_END;
	
	if (!Inn_export_asym_key(hPubKey, hPriKey))
		goto LB_END;
	
	/* Destroy symm_key */
	Inn_destroy_sym_key(&hKey);
	
	/* Destroy Asymm_key */
	Inn_destroy_asym_key(hPubKey, hPriKey);
	
LB_END:
	/* Logout */
    Inn_Logout();
	/* Close Device */
    Inn_CloseDevice();
	/* unload API */
    Inn_UnLoadAPI();
    printf("\n");

#ifdef WIN32
    system("pause");
#endif
    return 0;
}

SM_BOOL Inn_LoadAPI()
{
    SM_CHAR    pDllPath[CON_LEN_FILEPATH] = {0};
    SM_UINT      ret = 0;
    
    if ( g_pDllMang == SM_NULL )
        g_pDllMang = GetDllMangInterface();
    
    if ( g_pDllMang->Dll_IsLoad(g_pDllMang) )
        return TRUE;
    
    Plat_GetCWD(pDllPath, TRUE);
    strcat(pDllPath, API_DLL_NAME);
    printf("Path = %s\n",pDllPath);
    ret = g_pDllMang->Dll_Load(g_pDllMang, pDllPath);
    if ( ret != SM_ERR_FREE )
    {   
        printf("[Error] Load API5.2 dll error!\n\n");
        return FALSE;
    }
    
    return TRUE;
}

SM_VOID Inn_UnLoadAPI()
{
    if ( g_pDllMang != SM_NULL )
    {
        g_pDllMang->Dll_Unload(g_pDllMang);
        DelDllMangInterface(g_pDllMang);
    }
    
    g_pDllMang = SM_NULL;
}

SM_BOOL Inn_OpenDevice()
{
	SM_RV	  ret = 0;
    SM_UINT   uiDevNum = 0, uiResult = 0;

	printf("Get Device Number......\n");
    ret = g_pDllMang->m_pfn_SM_GetDeviceNum(&uiDevNum);
    if ( ret != SM_ERR_FREE )
    {
        printf("Failed(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
        return FALSE;
    }
	else
        printf("Success, Device Num = %d\n", uiDevNum);

	if (uiDevNum == 0)
	{
		printf("NO device!\n\n");
        return FALSE;
	}
    /* 1. OpenDevice    */
	printf("Opendevice......");
    ret = g_pDllMang->m_pfn_SM_OpenDevice(uiDevNum-1, 
                    0, &g_stHandle.hDevice);
    if ( ret != SM_ERR_FREE )
    {
        printf("Failed(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
        return FALSE;
    }
    else
        printf("Success\n");

    /* 2. OpenSecPipe   */
	printf("Openpipe......");
    ret = g_pDllMang->m_pfn_SM_OpenSecPipe(g_stHandle.hDevice, &g_stHandle.hPipe);
    if ( ret != SM_ERR_FREE )
    {
        printf("Failed(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
        return FALSE;
    }
    else
        printf("Success\n");        

    return TRUE;
}

SM_BOOL Inn_CloseDevice()
{  
    SM_RV	ret = 0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
		printf("ClosePipe......");
        ret = g_pDllMang->m_pfn_SM_CloseSecPipe(g_stHandle.hPipe);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("Success\n");        

    }
    if ( g_stHandle.hDevice != SM_NULL )
    {
		printf("Close Device......");
        ret = g_pDllMang->m_pfn_SM_CloseDevice(g_stHandle.hDevice);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("Success\n");        

        g_stHandle.hDevice = SM_NULL;
    }

    return TRUE;
}

SM_BOOL Inn_Login()
{
	SM_RV	ret = 0;
	SM_WORD wTryNum =0;
	SM_BYTE byPassword[] = "00000000";

	printf("Login key(%s)......", "00000000");
    ret = g_pDllMang->m_pfn_SM_Login(g_stHandle.hPipe, 
        byPassword, 8, &wTryNum);
	if (ret != SM_ERR_FREE)
    {
        printf("Failed\n");
        return FALSE;
    }
    printf("Success\n");    

    return TRUE;
}

SM_BOOL Inn_Logout()
{
    SM_RV ret =0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
		printf("Logout......");
        ret = g_pDllMang->m_pfn_SM_Logout(g_stHandle.hPipe);
		if (ret != SM_ERR_FREE)
		{
			printf("Failed\n");
			return FALSE;
		}
		else
		{
			printf("Success\n");    
		}
    }
    return TRUE;
}
SM_VOID Inn_UpdateDate(SM_BYTE* pbyData)
{
    SM_BYTE    byTimeString[16] = {0};
    SM_BYTE    byTime[8] = {0};
    SM_UINT    i = 0, iNo = 0;
    struct tm   when;
    time_t      now;
    
    time( &now );
    when = *localtime( &now );
    sprintf((SM_CHAR*)byTimeString, "%04d%02d%02d%\n", 
        when.tm_year+1900, when.tm_mon+1, when.tm_mday);
    
    for ( iNo=0; iNo<8; iNo+=2 )
    {
        byTime[i] = ( ((byTimeString[iNo] - 0x30) << 4) | (byTimeString[iNo+1] - 0x30) );
        i++;
    }//for
    memcpy(pbyData, byTime, 4);
}
SM_BOOL Inn_gen_sym_key(PSM_KEY_HANDLE phKey)
{
    SM_RV               rv = SM_ERR_FREE;
    SM_KEY_ATTRIBUTE    stKeyAttr;
	
    SM_BYTE byDate[8] = {0x20, 0x10, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00};
    
    Inn_UpdateDate(byDate);
	
    memset(&stKeyAttr,  0, sizeof(SM_KEY_ATTRIBUTE));
    memcpy(&stKeyAttr.byStartDate, byDate, sizeof(SM_BYTE)*4);
    memcpy(&stKeyAttr.byEndDate,   byDate, sizeof(SM_BYTE)*4);
    stKeyAttr.uiObjectClass  = SMO_SECRET_KEY;
    stKeyAttr.KeyType        = SM_KEY_ALG34_L;
    stKeyAttr.pParameter     = SM_NULL;
    stKeyAttr.uiParameterLen = 0;
    stKeyAttr.uiKeyLabel     = 1;
    stKeyAttr.uiFlags        = SMKA_EXTRACTABLE |SMKA_ENCRYPT | SMKA_DECRYPT;	
	printf("Generate Symmkey......");
    rv = g_pDllMang->m_pfn_SM_GenerateKey(g_stHandle.hPipe, &stKeyAttr, phKey);
    if (rv != SM_ERR_FREE)
    {
        printf("Failed\n", SM_KEY_ALG34_L);
        return FALSE;
    }
	else
		printf("Success\n");
    return TRUE;
}

SM_BOOL Inn_destroy_sym_key(PSM_KEY_HANDLE phKey)
{
    SM_RV               rv = SM_ERR_FREE;
	
    if (*phKey)
    {
		printf("Destroy Symmkey......");
        rv = g_pDllMang->m_pfn_SM_DestroyKey(g_stHandle.hPipe, *phKey);
        *phKey = NULL;
        if (rv)
        {
            printf("Failed\n");
            return FALSE;
        }
		else
			printf("Sucess\n");
		
    }
	
    return TRUE;
}
SM_BOOL Inn_gen_ecc_key(PSM_KEY_HANDLE phPubKey, PSM_KEY_HANDLE phPriKey)
{
    SM_RV               rv = SM_ERR_FREE;
    SM_KEY_ATTRIBUTE    stPubKeyAttr, stPriKeyAttr;
    SM_ECC_PARAMETER    stEccPara;
    	
    SM_BYTE byDate[8] = {0x20, 0x10, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00};
    
    Inn_UpdateDate(byDate);
    memset(&stPubKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(&stPriKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(&stEccPara,    0, sizeof(SM_ECC_PARAMETER));
    stPubKeyAttr.uiObjectClass  = SMO_PUBLIC_KEY;
    stPubKeyAttr.KeyType        = SM_KEY_ECC_PUBLIC;
    stPubKeyAttr.uiKeyLabel     = 1;
    memcpy(stPubKeyAttr.byStartDate, byDate, sizeof(SM_BYTE) * 4);
    memcpy(stPubKeyAttr.byEndDate,   byDate, sizeof(SM_BYTE) * 4);
    stPriKeyAttr.uiObjectClass  = SMO_PRIVATE_KEY;
    stPriKeyAttr.KeyType        = SM_KEY_ECC_PRIVATE;
    stPriKeyAttr.uiKeyLabel     = 1;
    memcpy(stPriKeyAttr.byStartDate, byDate, sizeof(SM_BYTE) * 4);
    memcpy(stPriKeyAttr.byEndDate,   byDate, sizeof(SM_BYTE) * 4);
    
        stPubKeyAttr.pParameter     = &stEccPara;
        stPubKeyAttr.uiParameterLen = sizeof(SM_ECC_PARAMETER);
        stPriKeyAttr.pParameter     = &stEccPara;
        stPriKeyAttr.uiParameterLen = sizeof(SM_ECC_PARAMETER);
        stEccPara.uiModulusBits     = SMMA_ECC_FP_256_MODULUS_BITS;
        stPubKeyAttr.uiFlags = SMKA_ENCRYPT | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;
        stPriKeyAttr.uiFlags = SMKA_DECRYPT | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;
	/* 产生ECC密钥对 */
	printf("Generate ECC key pair......");
    rv = g_pDllMang->m_pfn_SM_GenerateKeyPair(g_stHandle.hPipe, &stPubKeyAttr, phPubKey, &stPriKeyAttr, phPriKey);
    if (rv)
    {
        printf("Failed\n");
        return FALSE;
    }
	else
		printf("Success\n");
    
    return TRUE;
}

SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPubKey, SM_KEY_HANDLE hPriKey)
{
    SM_RV               rv = SM_ERR_FREE;
    

    if (hPubKey)
    {
		/* 销毁公钥 */
		printf("Destroy Pubkey......");
        rv = g_pDllMang->m_pfn_SM_DestroyPublicKey(g_stHandle.hPipe, hPubKey);
        hPubKey = NULL;
        if (rv)
        {
            printf("Failed\n");
            return FALSE;
        }
		else
			printf("Success\n");
    }
    if (hPriKey)
    {
		/* 销毁私钥 */
		printf("Destroy privatekey......");
        rv = g_pDllMang->m_pfn_SM_DestroyPrivateKey(g_stHandle.hPipe, hPriKey);
        hPriKey = NULL;
        if (rv)
        {
            printf("Failed\n");
            return FALSE;
        }
		else
			printf("Success\n");
    }
	
    return TRUE;
}
SM_BOOL Inn_export_sym_key(SM_KEY_HANDLE hKey)
{
	SM_KEY_HANDLE hBasicKey = SM_NULL;
	SM_RV         rv = SM_ERR_FREE;
	SM_BLOB_KEY   stblKey;
	SM_ALGORITHM stKEKAlgo;
	SM_BYTE		byKey[SMMA_ALG34_KEY_L_LEN] = {0};
	SM_CHAR		byKeyFileName[MAX_PATH] = {0};
	SM_WORD		wKeyLen = 0;
	SM_UINT     uiCfgKeyLen = SMCK_SYMM;
	
	memset(&stKEKAlgo, 0, sizeof(SM_ALGORITHM));
	memset(&stblKey, 0, sizeof(SM_BLOB_KEY));

	/* 使用主密钥作为保护密钥，导出对称密钥 */
	stblKey.pbyData = (SM_BYTE*)&uiCfgKeyLen;
	stblKey.uiDataLen = sizeof(SM_UINT);

	if (SM_ERR_FREE != g_pDllMang->m_pfn_SM_GetCfgKeyHandle(g_stHandle.hPipe, &stblKey, &hBasicKey))
	{
		printf("Get Key Handle Failed\n");
		return FALSE;
	}
	/* 保护算法为ALG34_ECB */
	stKEKAlgo.AlgoType = SMM_ALG34_ECB;
	stKEKAlgo.pParameter = SM_NULL;
	stKEKAlgo.uiParameterLen = 0;
	
    /* 导出对称密钥 */
	rv = g_pDllMang->m_pfn_SM_ExportKey(g_stHandle.hPipe, hKey, hBasicKey, &stKEKAlgo, byKey, &wKeyLen);
    if (rv != SM_ERR_FREE)
    {
        printf("export SymmKey Failed\n");
        return FALSE;
    }
	printf("Input the name of exported symm_key(absolutly path):");
	scanf("%s", byKeyFileName);
	//printf("\n");
	
	Inn_WriteFileData(byKeyFileName, byKey, wKeyLen);
	printf("Export symm_Key Success,save in%s\n", byKeyFileName);
    return TRUE;
}
SM_BOOL Inn_export_asym_key(SM_KEY_HANDLE hPubKey, SM_KEY_HANDLE hPriKey)
{
	SM_KEY_HANDLE hBasicKey = SM_NULL;
	SM_UINT rv = SM_ERR_FREE;
	SM_BOOL bRet = FALSE;
    SM_ALGORITHM stKEKAlgo;
	SM_BYTE					byPubKey[SMMA_ECC_FP_256_PUBLIC_KEY_LEN] = {0}, byPriKey[SMMA_ECC_FP_256_PRIVATE_KEY_LEN] = {0};
	SM_CHAR					byPubKeyFileName[MAX_PATH] = {0}, byPriKeyFileName[MAX_PATH] = {0};
	SM_WORD					wPubKeyLen = 0, wPriKeyLen = 0;
	SM_UINT     uiCfgKeyLen = SMCK_SYMM;
	SM_BLOB_KEY   stblKey;

	memset(&stKEKAlgo, 0, sizeof(SM_ALGORITHM));
	memset(&stblKey, 0, sizeof(SM_BLOB_KEY));
	
	/* 使用主密钥作为保护密钥，导出对称密钥 */
	stblKey.pbyData = (SM_BYTE*)&uiCfgKeyLen;
	stblKey.uiDataLen = sizeof(SM_UINT);

	if (SM_ERR_FREE != g_pDllMang->m_pfn_SM_GetCfgKeyHandle(g_stHandle.hPipe, &stblKey, &hBasicKey))
	{
		printf("Get Key Handle Failed\n");
		return FALSE;
	}

	/* 保护算法为ALG34_ECB */
	stKEKAlgo.AlgoType = SMM_ALG34_ECB;
	stKEKAlgo.pParameter = SM_NULL;
	stKEKAlgo.uiParameterLen = 0;
	
    /* 导出公钥 */
	rv = g_pDllMang->m_pfn_SM_ExportPublicKey(g_stHandle.hPipe, hPubKey, byPubKey, &wPubKeyLen);
    if (rv != SM_ERR_FREE)
    {
        printf("export public key failed\n");
		return FALSE;
    }
    /*　导出私钥　*/
	rv = g_pDllMang->m_pfn_SM_ExportPrivateKey(g_stHandle.hPipe, hPriKey, hBasicKey, &stKEKAlgo, byPriKey, &wPriKeyLen);
    if (rv != SM_ERR_FREE)
    {
        printf("export private key failed\n");
		return FALSE;
    }
	printf("Input the name of exported public key(absolutly path)");
	scanf("%s", byPubKeyFileName);
	
	Inn_WriteFileData(byPubKeyFileName, byPubKey, wPubKeyLen);
	printf("Export public Key Success,save in%s\n", byPubKeyFileName);
	
	printf("Input the name of exported private key(absolutly path)");
	scanf("%s", byPriKeyFileName);
	Inn_WriteFileData(byPriKeyFileName, byPriKey, wPriKeyLen);
	printf("Export private Key Success,save in%s\n", byPriKeyFileName);
    
    return TRUE;
}
