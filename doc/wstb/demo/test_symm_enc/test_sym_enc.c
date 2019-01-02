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
SM_BOOL Inn_import_key(PSM_KEY_HANDLE phKey);
SM_BOOL Inn_destroy_sym_key(PSM_KEY_HANDLE phKey);
SM_BOOL Inn_sym_algo(SM_KEY_HANDLE hKey);

/* ///////////////////////////////////////////////////////////////////////// */
/* main function                                                             */
/* ///////////////////////////////////////////////////////////////////////// */
SM_INT main()
{
    SM_RV                   ret = SM_ERR_FREE;
	SM_KEY_HANDLE			hKey;

	/* 加载API */
	if ( !Inn_LoadAPI() ) 
        return 0;

	/* 打开设备 */
    if ( !Inn_OpenDevice() )
		return 0;

	/* 登陆 */
    if ( !Inn_Login() )
		goto LB_END;
	
	/* 导入对称密钥　*/
	if (!Inn_import_key(&hKey))
		goto LB_END;
	
	/* 加解密运算 */
	Inn_sym_algo(hKey);
	
	/* 销毁对称密钥 */
	Inn_destroy_sym_key(&hKey);
	
LB_END:
	/* 登出 */
    Inn_Logout();
	/* 关闭设备 */
    Inn_CloseDevice();
	/* 卸载API */
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

	printf("Get Device Number......");
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
        printf("success\n");

    /* 2. OpenSecPipe   */
	printf("Openpipe......");
    ret = g_pDllMang->m_pfn_SM_OpenSecPipe(g_stHandle.hDevice, &g_stHandle.hPipe);
    if ( ret != SM_ERR_FREE )
    {
        printf("Failed(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
        return FALSE;
    }
    else
        printf("success\n");        

    return TRUE;
}

SM_BOOL Inn_CloseDevice()
{  
    SM_RV	ret = 0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
		printf("ClosePipe....");
        ret = g_pDllMang->m_pfn_SM_CloseSecPipe(g_stHandle.hPipe);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("success\n");        

    }
    if ( g_stHandle.hDevice != SM_NULL )
    {
		printf("Close Device.......");
        ret = g_pDllMang->m_pfn_SM_CloseDevice(g_stHandle.hDevice);
        if ( ret != SM_ERR_FREE )
        {
			printf("Failed!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, TRUE));
			return FALSE;
        }
		else
			printf("success\n");        

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
        printf("failed\n");
        return FALSE;
    }
    printf("success\n");    

    return TRUE;
}

SM_BOOL Inn_Logout()
{
    SM_RV ret =0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
		printf("logout......");
        ret = g_pDllMang->m_pfn_SM_Logout(g_stHandle.hPipe);
		if (ret != SM_ERR_FREE)
		{
			printf("failed\n");
			return FALSE;
		}
		else
		{
			printf("success\n");    
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
SM_BOOL Inn_import_key(PSM_KEY_HANDLE phKey)
{
	SM_UINT rv = SM_ERR_FREE;
	SM_BOOL bRet = FALSE;
	SM_BLOB_KEY   stblKey;
    SM_ALGORITHM stKEKAlgo;
	SM_KEY_ATTRIBUTE stKeyAttr;
	SM_WORD		wKeyLen = 0;
	SM_UINT     uiCfgKeyLen = SMCK_SYMM;
	SM_BYTE	byKey[1024] = {0};
	SM_CHAR byKeyFileName[MAX_PATH] = {0};
	SM_KEY_HANDLE hBasicKey = SM_NULL;
    SM_BYTE byDate[8] = {0x20, 0x10, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00};

	memset(&stKEKAlgo, 0, sizeof(SM_ALGORITHM));
	memset(&stblKey, 0, sizeof(SM_BLOB_KEY));
	
	stblKey.pbyData = (SM_BYTE*)&uiCfgKeyLen;
	stblKey.uiDataLen = sizeof(SM_UINT);
	
	/* 使用主密钥作为保护密钥，导出对称密钥 */
	if (SM_ERR_FREE != g_pDllMang->m_pfn_SM_GetCfgKeyHandle(g_stHandle.hPipe, &stblKey, &hBasicKey))
	{
		printf("Get Key Handle Failed\n");
		return FALSE;
	}
	/* 读对称密钥文件，以ALG34为例 */
	printf("import the name of symm key(absolutely path):");
	scanf("%s", byKeyFileName);
	//printf("\n");
	
	wKeyLen = Inn_GetFileSize(byKeyFileName);
	if ( wKeyLen == 0 )
	{
		printf("invalid file\n");
		return FALSE;
	}	
	/* 读文件 */
	wKeyLen = Inn_ReadFileData(byKeyFileName, byKey);
	
	memset(&stKEKAlgo, 0, sizeof(SM_ALGORITHM));
	memset(&stKeyAttr, 0, sizeof(SM_KEY_ATTRIBUTE));
	
	/* 保护算法为ALG34_ECB */
	stKEKAlgo.AlgoType = SMM_ALG34_ECB;
	stKEKAlgo.pParameter = SM_NULL;
	stKEKAlgo.uiParameterLen = 0;

	/* 设置导入的对称密钥的属性，以ALG34为例 */
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
	
	/* 获取导入密钥的长度 */ 
	printf("import symmetry key......");
    rv = g_pDllMang->m_pfn_SM_ImportKey(g_stHandle.hPipe, byKey, wKeyLen, hBasicKey, &stKEKAlgo, &stKeyAttr, phKey);
    if (rv != SM_ERR_FREE)
    {
        printf("Failed\n");
		return FALSE;
    }
	else
		printf("success\n");
    
    return TRUE;
}
SM_BOOL Inn_sym_algo(SM_KEY_HANDLE hKey)
{
    SM_BOOL				bRet = FALSE;
    SM_RV               rv = SM_ERR_FREE;
    SM_UINT             uiUsrChoose = 0;
	SM_BLOB_KEY			stBlKey;
    SM_ALGORITHM        stAlgo;
    SM_UINT             uiPlainDataLen = 0, uiCipherDataLen = 0;
    PSM_BYTE            pbyPlain = NULL, pbyCipher = NULL;
    SM_BYTE				byIVFileName[MAX_PATH] = {0}, byIV[SMMA_ALG34_IV_LEN] = {0};
	SM_CHAR				byPlainFileName[MAX_PATH] = {0}, byCipherFileName[MAX_PATH] = {0};

	 /* 提示用户输入IV文件名*/
	printf("the name of IV File (absolute path):");
	scanf("%s", byIVFileName);
//	printf("\n");
	if(SMMA_ALG34_IV_LEN != Inn_ReadFileData((SM_CHAR *)byIVFileName, byIV) )
	{
		printf("Failed\n");
		return FALSE;
	}
	/* 设置算法属性, 以SM_ALG34_CBC为例*/
    memset(&stAlgo, 0, sizeof(SM_ALGORITHM));
    stAlgo.AlgoType = SMM_ALG34_CBC;
	stAlgo.pParameter = byIV;
	stAlgo.uiParameterLen = SMMA_ALG34_IV_LEN;

	/* 提示用户输入待加密的文件名*/
	printf("input the name of clear text(absolute path):");
	scanf("%s", byPlainFileName);
	//printf("\n");

	/* 提示用户输密文保存路径*/
	printf("the name of Cipher File(absolute path):");
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
	memset(pbyPlain, 0x00, uiPlainDataLen);
	/* 读文件 */
	uiPlainDataLen = Inn_ReadFileData(byPlainFileName, pbyPlain);
	pbyCipher = (SM_BYTE*)malloc(uiPlainDataLen+16);
	if ( pbyCipher == SM_NULL )
	{
		printf("out of memory\n");
		return FALSE;
	}
	memset(pbyCipher, 0x00, uiPlainDataLen+16);
	
	/* 加密，以填充为例 */
	
	{
		memset(&stBlKey, 0, sizeof(SM_BLOB_KEY));
		stBlKey.pbyData = (SM_BYTE*)&hKey;
		stBlKey.uiDataLen = sizeof(SM_KEY_HANDLE);

		printf("Enc......");
		rv = g_pDllMang->m_pfn_SM_Encrypt(g_stHandle.hPipe, &stBlKey, &stAlgo, TRUE, pbyPlain, uiPlainDataLen, pbyCipher, &uiCipherDataLen);
		if (rv != SM_ERR_FREE)
		{
			printf("Failed\n");
			goto LB_FREE_RESOURCE;
		}
		else
			printf("Success\n");
	}
	Inn_WriteFileData(byCipherFileName, pbyCipher, uiCipherDataLen);
	printf("Enc Success,Cipher File save in %s\n", byCipherFileName);
	bRet = TRUE;
                
LB_FREE_RESOURCE:
	free(pbyPlain);
	free(pbyCipher);
    return bRet;
}
SM_BOOL Inn_destroy_sym_key(PSM_KEY_HANDLE phKey)
{
    SM_RV               rv = SM_ERR_FREE;
	
    if (*phKey)
    {
		printf("destroy key......");
        rv = g_pDllMang->m_pfn_SM_DestroyKey(g_stHandle.hPipe, *phKey);
        *phKey = NULL;
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
