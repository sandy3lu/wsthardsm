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
SM_BOOL Inn_import_key(PSM_KEY_HANDLE phPriKey);
SM_BOOL Inn_ecc_encdec(SM_KEY_HANDLE hPriKey);
SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPriKey);

/* ///////////////////////////////////////////////////////////////////////// */
/* main function                                                             */
/* ///////////////////////////////////////////////////////////////////////// */
SM_INT main()
{
    SM_RV                   ret = SM_ERR_FREE;
	SM_KEY_HANDLE			hPriKey;
		
	/* load API*/
	if ( !Inn_LoadAPI() ) 
        return 0;
	
	/*Open Device */
    if ( !Inn_OpenDevice() )
		return 0;

	/* Login*/
    if ( !Inn_Login() )
		goto LB_END;
	
	/*Import Asymm_key*/
	if (!Inn_import_key(&hPriKey))
		goto LB_END;
	
	/* enc_dec */
	Inn_ecc_encdec(hPriKey);
	/* Destroy Asymm_key */
	Inn_destroy_asym_key(hPriKey);
	
LB_END:
	/* Logout*/
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

	printf("Get Device Number.....");
    ret = g_pDllMang->m_pfn_SM_GetDeviceNum(&uiDevNum);
    if ( ret != SM_ERR_FREE )
    {
        printf("Failed(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
        return FALSE;
    }
	else
        printf("Success, Device Num =%d\n", uiDevNum);

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
	printf("Openpipe.....");
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
		printf("ClosePipe.....");
        ret = g_pDllMang->m_pfn_SM_CloseSecPipe(g_stHandle.hPipe);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("Success\n");        

    }
    if ( g_stHandle.hDevice != SM_NULL )
    {
		printf("Close Device.......");
        ret = g_pDllMang->m_pfn_SM_CloseDevice(g_stHandle.hDevice);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
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
		printf("Logout.....");
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

SM_BOOL Inn_import_key(PSM_KEY_HANDLE phPriKey)
{
	SM_UINT rv = SM_ERR_FREE;
	SM_BOOL bRet = FALSE;
    SM_ALGORITHM stKEKAlgo;
	SM_BYTE					byPriKey[SMMA_ECC_FP_256_PRIVATE_KEY_LEN] = {0};
	SM_CHAR					byPriKeyFileName[MAX_PATH] = {0};
	SM_WORD					wPriKeyLen = 0;
	SM_KEY_HANDLE hBasicKey = SM_NULL;
    SM_KEY_ATTRIBUTE    stPriKeyAttr;
    SM_ECC_PARAMETER    stEccPara;
	SM_UINT     uiCfgKeyLen = SMCK_SYMM;
	SM_BLOB_KEY   stblKey;

       	SM_BYTE byDate[8] = {0x20, 0x10, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00};

	memset(&stEccPara, 0, sizeof(SM_ECC_PARAMETER));
	memset(&stPriKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
	memset(&stKEKAlgo, 0, sizeof(SM_ALGORITHM));
	memset(&stblKey, 0, sizeof(SM_BLOB_KEY));

	/* 使用主密钥作为保护密钥，导出对称密钥 */
	stblKey.pbyData = (SM_BYTE*)&uiCfgKeyLen;
	stblKey.uiDataLen = sizeof(SM_UINT);
	if (SM_ERR_FREE != g_pDllMang->m_pfn_SM_GetCfgKeyHandle(g_stHandle.hPipe, &stblKey, &hBasicKey))
	{
		printf("Get KeyHandle Failed\n");
		return FALSE;
	}
		
	/* 读私密钥文件 */
	printf("import the name of private key(absolute path):");
	scanf("%s", byPriKeyFileName);
	//printf("\n");
	
	wPriKeyLen = Inn_GetFileSize(byPriKeyFileName);
	if ( wPriKeyLen == 0 )
	{
		printf("invalid file\n");
		return FALSE;
	}	
	/* 读文件 */
	wPriKeyLen = Inn_ReadFileData(byPriKeyFileName, byPriKey);

		
	/* 设置ECC密钥属性，以ECC256为例 */
    Inn_UpdateDate(byDate);
    memset(&stPriKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(&stEccPara,    0, sizeof(SM_ECC_PARAMETER));
    stPriKeyAttr.uiObjectClass  = SMO_PRIVATE_KEY;
    stPriKeyAttr.KeyType        = SM_KEY_ECC_PRIVATE;
    stPriKeyAttr.uiKeyLabel     = 1;
    memcpy(stPriKeyAttr.byStartDate, byDate, sizeof(SM_BYTE) * 4);
    memcpy(stPriKeyAttr.byEndDate,   byDate, sizeof(SM_BYTE) * 4);
    
	stPriKeyAttr.pParameter     = &stEccPara;
	stPriKeyAttr.uiParameterLen = sizeof(SM_ECC_PARAMETER);
	stEccPara.uiModulusBits     = SMMA_ECC_FP_256_MODULUS_BITS;
	stPriKeyAttr.uiFlags = SMKA_DECRYPT | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;

	/* 保护算法为ALG34_ECB */
	stKEKAlgo.AlgoType = SMM_ALG34_ECB;
	stKEKAlgo.pParameter = SM_NULL;
	stKEKAlgo.uiParameterLen = 0;
	
	/* 导入私钥 */    
	printf("export private key");
    rv = g_pDllMang->m_pfn_SM_ImportPrivateKey(g_stHandle.hPipe, byPriKey, wPriKeyLen, hBasicKey, &stKEKAlgo, &stPriKeyAttr, phPriKey);
	if (rv != SM_ERR_FREE)
    {
        printf("Failed\n");
		return FALSE;
    }
	else
		printf("success\n");
	
    return TRUE;
}

SM_BOOL Inn_ecc_encdec(SM_KEY_HANDLE hPriKey)
{
    SM_BOOL bRet = FALSE;

    SM_RV               rv = SM_ERR_FREE;
    SM_UINT             uiPlainDataLen = 0, uiCipherLen = 0, uiUsrChoose = 0;
    PSM_BYTE            pbyPlain = NULL, pbyCipher = NULL;
   	SM_CHAR				byPlainFileName[MAX_PATH] = {0}, byCipherFileName[MAX_PATH] = {0};
    SM_BLOB_KEY			stBlKey;        
	SM_ALGORITHM        stAlgo;
	SM_BLOB_ECCCIPHER	stECCCipher;

	/* 提示用户输入密文文件名*/
	printf("input Cipher FileName(absolute path):");
	scanf("%s", byCipherFileName);
	//printf("\n");

	/* 提示用户输入明文文件名*/
	printf("input Plain FileName(absolute path):");
	scanf("%s", byPlainFileName);
	//printf("\n");

	/* 读文件长度 */
	uiCipherLen = Inn_GetFileSize(byCipherFileName);
	/* 根据文件长度分配内存空间 */
	pbyCipher = (SM_BYTE*)malloc(uiCipherLen*sizeof(SM_BYTE));
	if ( pbyCipher == SM_NULL )
	{
		printf("invalid file\n");
		return FALSE;
	}
	/* 读文件 */
	uiCipherLen = Inn_ReadFileData(byCipherFileName, pbyCipher);
	stECCCipher.pbyData = (SM_BYTE*)malloc(uiCipherLen);
	memcpy(stECCCipher.pbyData, pbyCipher, uiCipherLen);

	stECCCipher.uiCheckDataLen = SMMA_SCH_256_LEN;
	stECCCipher.uiSessionKeyLen = SMMA_ECC_FP_256_PUBLIC_KEY_LEN;
	stECCCipher.uiCipherDataLen = uiCipherLen-SMMA_SCH_256_LEN-SMMA_ECC_FP_256_PUBLIC_KEY_LEN;

	/* 设置解密算法 */
	memset(&stAlgo, 0, sizeof(SM_ALGORITHM));
	stAlgo.AlgoType = SMM_ECC_FP_DEC;
	stAlgo.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

	/* 解密文件 */
	memset(&stBlKey, 0, sizeof(SM_BLOB_KEY));
	stBlKey.pbyData = (SM_BYTE*)&hPriKey;
	stBlKey.uiDataLen = sizeof(SM_KEY_HANDLE);
	rv = g_pDllMang->m_pfn_SM_ECCDecrypt(g_stHandle.hPipe, &stBlKey, &stAlgo, &stECCCipher, SM_NULL, &uiPlainDataLen);
	if (rv)
	{
		printf("Dec Failed\n");
		goto LB_END;
	}
	pbyPlain = (PSM_BYTE)malloc(uiPlainDataLen * sizeof(SM_BYTE));
	memset(pbyPlain, 0x00, uiPlainDataLen);
	
	printf("Dec File ......");
	rv = g_pDllMang->m_pfn_SM_ECCDecrypt(g_stHandle.hPipe, &stBlKey, &stAlgo, &stECCCipher, pbyPlain, &uiPlainDataLen);
	if (rv)
	{
		printf("Failed\n");
		goto LB_END;
	}
	else
		printf("Success\n");
	Inn_WriteFileData(byPlainFileName, pbyPlain, uiPlainDataLen);
	printf("Dec file sucess, Plain file save in %s\n", byPlainFileName);
		bRet = TRUE;

LB_END:
    free(pbyPlain);
    free(pbyCipher);
    return bRet;
}
SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPriKey)
{
    SM_RV               rv = SM_ERR_FREE;
    
    if (hPriKey)
    {
		/* 销毁私钥 */
		printf("Destroy key......");
        rv = g_pDllMang->m_pfn_SM_DestroyPrivateKey(g_stHandle.hPipe, hPriKey);
        hPriKey = NULL;
        if (rv)
        {
            printf("Failed\n");
            return FALSE;
        }
		else
			printf("success\n");
    }
	
    return TRUE;
}
