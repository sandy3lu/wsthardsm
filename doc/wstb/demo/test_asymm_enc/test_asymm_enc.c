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
SM_BOOL Inn_import_key(PSM_KEY_HANDLE phPubKey);
SM_BOOL Inn_ecc_encdec(SM_KEY_HANDLE hPubKey);
SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPubKey);

/* ///////////////////////////////////////////////////////////////////////// */
/* main function                                                             */
/* ///////////////////////////////////////////////////////////////////////// */
SM_INT main()
{
    SM_RV                   ret = SM_ERR_FREE;
	SM_KEY_HANDLE			hPubKey;
		
	/* Load API */
	if ( !Inn_LoadAPI() ) 
        return 0;
	
	/* Open device */
    if ( !Inn_OpenDevice() )
		return 0;

	/* login  */
    if ( !Inn_Login() )
		goto LB_END;
	
	/* Import Asymm_key*/
	if (!Inn_import_key(&hPubKey))
		goto LB_END;
	
	/*  enc_dec*/
	Inn_ecc_encdec(hPubKey);
	/* Destroy Asymm_key */
	Inn_destroy_asym_key(hPubKey);
	
LB_END:
	/* Logout*/
    Inn_Logout();
	/*Close Device */
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
	printf("Opendevice.....");
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
	printf("Openpipe.......");
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
			printf("Failed\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("Success\n");        

    }
    if ( g_stHandle.hDevice != SM_NULL )
    {
		printf("Close Device.....");
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

SM_BOOL Inn_import_key(PSM_KEY_HANDLE phPubKey)
{
	SM_UINT rv = SM_ERR_FREE;
	SM_BOOL bRet = FALSE;
	SM_BYTE					byPubKey[SMMA_ECC_FP_256_PUBLIC_KEY_LEN] = {0};
	SM_CHAR					byPubKeyFileName[MAX_PATH] = {0};
	SM_WORD					wPubKeyLen = 0;
    SM_KEY_ATTRIBUTE    stPubKeyAttr;
    SM_ECC_PARAMETER    stEccPara;
	SM_BLOB_KEY   stblKey;
    SM_BYTE byDate[8] = {0x20, 0x10, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00};

	memset(&stEccPara, 0, sizeof(SM_KEY_ATTRIBUTE));
	memset(&stPubKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
	memset(&stblKey, 0, sizeof(SM_BLOB_KEY));

	/* 读公密钥文件 */
	printf("import the name of public key(absolutely path):");
	scanf("%s", byPubKeyFileName);
	//printf("\n");
	
	wPubKeyLen = Inn_GetFileSize(byPubKeyFileName);
	if ( wPubKeyLen == 0 )
	{
		printf("Failed\n");
		return FALSE;
	}	
	/* 读文件 */
	wPubKeyLen = Inn_ReadFileData(byPubKeyFileName, byPubKey);
		
	/* 设置ECC密钥属性，以ECC256为例 */
    Inn_UpdateDate(byDate);
    memset(&stPubKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(&stEccPara,    0, sizeof(SM_ECC_PARAMETER));
    stPubKeyAttr.uiObjectClass  = SMO_PUBLIC_KEY;
    stPubKeyAttr.KeyType        = SM_KEY_ECC_PUBLIC;
    stPubKeyAttr.uiKeyLabel     = 1;
    memcpy(stPubKeyAttr.byStartDate, byDate, sizeof(SM_BYTE) * 4);
    memcpy(stPubKeyAttr.byEndDate,   byDate, sizeof(SM_BYTE) * 4);
    
	stPubKeyAttr.pParameter     = &stEccPara;
	stPubKeyAttr.uiParameterLen = sizeof(SM_ECC_PARAMETER);
	stEccPara.uiModulusBits     = SMMA_ECC_FP_256_MODULUS_BITS;
	stPubKeyAttr.uiFlags = SMKA_ENCRYPT | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;
	
	/* 导入公钥 */    
	printf("import public key");
    rv = g_pDllMang->m_pfn_SM_ImportPublicKey(g_stHandle.hPipe, byPubKey, wPubKeyLen, &stPubKeyAttr, phPubKey);
    if (rv != SM_ERR_FREE)
    {
        printf("Failed\n");
		return FALSE;
    }
	else
		printf(" success\n");
	return TRUE;
}
SM_BOOL Inn_ecc_encdec(SM_KEY_HANDLE hPubKey)
{
    SM_BOOL bRet = FALSE;

    SM_RV               rv = SM_ERR_FREE;
    SM_UINT             uiPlainDataLen = 0, uiCipherLen = 0, uiUsrChoose = 0;
    PSM_BYTE            pbyPlain = NULL, pbyCipher = NULL;
   	SM_CHAR				byPlainFileName[MAX_PATH] = {0}, byCipherFileName[MAX_PATH] = {0};
    SM_BLOB_KEY			stBlKey;        
	SM_BLOB_ECCCIPHER	stEccCipher;
	SM_ALGORITHM        stAlgo;

	/* 提示用户输入待加密的文件名*/
	printf("the name of clear text(absolute path):");
	scanf("%s", byPlainFileName);
	//printf("\n");
	
	/* 提示用户输密文保存路径*/
	printf("the name of cipher text(absolute path):");
	scanf("%s", byCipherFileName);
	//printf("\n");

	/* 读文件长度 */
	uiPlainDataLen = Inn_GetFileSize(byPlainFileName);
	if ( uiPlainDataLen == 0 )
	{
		printf("invalid file\n");
		return FALSE;
	}
	/* 根据文件长度分配内存空间 */
	pbyPlain = (SM_BYTE*)malloc(uiPlainDataLen*sizeof(SM_BYTE));
	if ( pbyPlain == SM_NULL )
	{
		printf("out of memory\n");
		return FALSE;
	}
	/* 读文件 */
	uiPlainDataLen = Inn_ReadFileData(byPlainFileName, pbyPlain);
	if (uiPlainDataLen> SMMA_ECC_FP_256_ENC_MAX_LEN)
	{
		printf("invalid length of clear text(%d~%d)\n", SMMA_ECC_FP_256_ENC_MIN_LEN, SMMA_ECC_FP_256_ENC_MAX_LEN);
		goto LB_END;
	}

	/* 设置加密算法 */
	memset(&stAlgo, 0, sizeof(SM_ALGORITHM));
	stAlgo.AlgoType = SMM_ECC_FP_ENC;
	stAlgo.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

	/* 加密文件 */
	memset(&stBlKey, 0, sizeof(SM_BLOB_KEY));
	memset(&stEccCipher, 0, sizeof(SM_BLOB_ECCCIPHER));
	stBlKey.pbyData = (SM_BYTE*)&hPubKey;
	stBlKey.uiDataLen = sizeof(SM_KEY_HANDLE);
	rv = g_pDllMang->m_pfn_SM_ECCEncrypt(g_stHandle.hPipe, &stBlKey, &stAlgo, pbyPlain, uiPlainDataLen, &stEccCipher);
	if (rv)
	{
		printf("Enc Failed\n");
		goto LB_END;
	}
	uiCipherLen = stEccCipher.uiCheckDataLen+stEccCipher.uiCipherDataLen+stEccCipher.uiSessionKeyLen;
	stEccCipher.pbyData = (PSM_BYTE)malloc(uiCipherLen*sizeof(SM_BYTE));
	memset(stEccCipher.pbyData, 0x00, uiCipherLen);
	
	printf("Enc File......");
	rv = g_pDllMang->m_pfn_SM_ECCEncrypt(g_stHandle.hPipe, &stBlKey, &stAlgo, pbyPlain, uiPlainDataLen, &stEccCipher);
	if (rv)
	{
		printf("Failed\n");
		goto LB_END;
	}
	else
		printf("Success\n");
	Inn_WriteFileData(byCipherFileName, stEccCipher.pbyData, uiCipherLen);
	printf("Enc Success,Cipher file save in %s\n", byCipherFileName);
	bRet = TRUE;

LB_END:
    free(pbyPlain);
    free(pbyCipher);
    return bRet;
}
SM_BOOL Inn_destroy_asym_key(SM_KEY_HANDLE hPubKey)
{
    SM_RV               rv = SM_ERR_FREE;
    
	
    if (hPubKey)
    {
		/* 销毁公钥 */
		printf("destroy key......");
        rv = g_pDllMang->m_pfn_SM_DestroyPublicKey(g_stHandle.hPipe, hPubKey);
        hPubKey = NULL;
        if (rv)
        {
            printf("failed\n");
            return FALSE;
        }
		else
			printf("success\n");
    }
    return TRUE;
}
