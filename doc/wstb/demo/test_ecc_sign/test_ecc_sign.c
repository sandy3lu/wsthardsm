/* ///////////////////////////////////////////////////////////////////////// */
/* header files */
#include "PlateformDefine.h"
#include "api_dll50.h"

/* ///////////////////////////////////////////////////////////////////////// */
typedef struct _SW_TEST_HANDLE
{
    SM_DEVICE_HANDLE    hDevice;
    SM_PIPE_HANDLE      hPipe;
}SW_TEST_HANDLE, *PSW_TEST_HANDLE;

/* global variable */
SWAPI50DllMang *g_pDllMang = SM_NULL;
SW_TEST_HANDLE  g_stHandle;
/* ///////////////////////////////////////////////////////////////////////// */
#ifdef __linux__
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifdef _WINDOWS_
#define API_DLL_NAME "sw91415012_50s_v52.dll"
#else
#define API_DLL_NAME "libsw91415012_50s_v52.so"
#endif

#define CON_LEN_FILEPATH 256



void DumpHex(const void* data, int size) {
    char ascii[17];
    int i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
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
    SM_RV     ret = 0;
    SM_UINT   uiDevNum = 0, uiResult = 0;

    printf("获取设备数目......");
    ret = g_pDllMang->m_pfn_SM_GetDeviceNum(&uiDevNum);
    if ( ret != SM_ERR_FREE )
    {
        printf("失败(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
        printf("成功，当前设备数：%d\n", uiDevNum);

    if (uiDevNum == 0)
    {
        printf("没有设备!\n\n");
        return FALSE;
    }

    /* 1. OpenDevice    */
    printf("打开设备......");
    ret = g_pDllMang->m_pfn_SM_OpenDevice(uiDevNum-1,
                    0, &g_stHandle.hDevice);
    if ( ret != SM_ERR_FREE )
    {
        printf("失败(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
        printf("成功\n");

    /* 2. OpenSecPipe   */
    printf("打开管道......");
    ret = g_pDllMang->m_pfn_SM_OpenSecPipe(g_stHandle.hDevice, &g_stHandle.hPipe);
    if ( ret != SM_ERR_FREE )
    {
        printf("失败(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
        printf("成功\n");

    return TRUE;
}

SM_BOOL Inn_CloseDevice()
{
    SM_RV   ret = 0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
        printf("关闭管道......");
        ret = g_pDllMang->m_pfn_SM_CloseSecPipe(g_stHandle.hPipe);
        if ( ret != SM_ERR_FREE )
        {
            printf("失败!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
            return FALSE;
        }
        else
            printf("成功\n");

    }
    if ( g_stHandle.hDevice != SM_NULL )
    {
        printf("关闭设备......");
        ret = g_pDllMang->m_pfn_SM_CloseDevice(g_stHandle.hDevice);
        if ( ret != SM_ERR_FREE )
        {
            printf("失败!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
            return FALSE;
        }
        else
            printf("成功\n");

        g_stHandle.hDevice = SM_NULL;
    }

    return TRUE;
}

SM_BOOL Inn_Login()
{
    SM_RV   ret = 0;
    SM_WORD wTryNum =0;
    SM_BYTE byPassword[] = "00000000";

    printf("登陆(口令%s)......", "00000000");
    ret = g_pDllMang->m_pfn_SM_Login(g_stHandle.hPipe,
        byPassword, 8, &wTryNum);
    if (ret != SM_ERR_FREE)
    {
        printf("失败\n");
        return FALSE;
    }
    printf("成功\n");

    return TRUE;
}

SM_BOOL Inn_Logout()
{
    SM_RV ret =0;

    if ( g_stHandle.hPipe != SM_NULL )
    {
        printf("登出......");
        ret = g_pDllMang->m_pfn_SM_Logout(g_stHandle.hPipe);
        if (ret != SM_ERR_FREE)
        {
            printf("失败\n");
            return FALSE;
        }
        else
        {
            printf("成功\n");
        }
    }
    return TRUE;
}

SM_VOID Inn_EccSign()
{
    SM_BLOB_KEY blob_key;
    SM_UINT     key_type = SMCK_ECC_SIGN_PRIVATE;
    SM_KEY_HANDLE key_handle = SM_NULL;


    memset(&blob_key, 0, sizeof(SM_BLOB_KEY));
    blob_key.pbyData = (SM_BYTE*)&key_type;
    blob_key.uiDataLen = sizeof(SM_UINT);

    SM_RV ret = 0;

    printf("获取配用签名私钥......");
    ret = g_pDllMang->m_pfn_SM_GetCfgKeyHandle(g_stHandle.hPipe, &blob_key, &key_handle);
    if (ret != SM_ERR_FREE)
    {
        printf("失败(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
    {
        printf("成功\n");
    }

    SM_BYTE data[] = "123456789abcdefg123456789abcdefg";
    SM_UCHAR sign_buf[4096] = {0};
    SM_UINT sign_len = sizeof(sign_buf);

    SM_ALGORITHM sign_algorithm;
    memset(&sign_algorithm, 0, sizeof(SM_ALGORITHM));
    sign_algorithm.AlgoType = SMM_ECC_FP_SIGN;
    sign_algorithm.pParameter = SM_NULL;
    sign_algorithm.uiParameterLen = 0;
    sign_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

    SM_BLOB_KEY private_blob;
    memset(&private_blob, 0, sizeof(SM_BLOB_KEY));

    private_blob.pbyData = (SM_BYTE*)&key_handle;
    private_blob.uiDataLen = sizeof(SM_KEY_HANDLE);

    printf("签名数据......");
    ret = g_pDllMang->m_pfn_SM_ECCSignature(g_stHandle.hPipe, &private_blob, &sign_algorithm, (PSM_BYTE)data,
                          strlen(data), (PSM_BYTE)sign_buf, (PSM_UINT)(&sign_len));
    if (ret != SM_ERR_FREE)
    {
        printf("失败(%s)!\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
    {
        printf("成功\n");
    }

    printf("data:\n");
    DumpHex(data, strlen(data));

    printf("signature:\n");
    DumpHex(sign_buf, sign_len);
}



/* ///////////////////////////////////////////////////////////////////////// */
/* main function                                                             */
/* ///////////////////////////////////////////////////////////////////////// */
SM_INT main()
{
    SM_RV                   ret = SM_ERR_FREE;
    SM_KEY_HANDLE           hKey, hPubKey, hPriKey;

    /* 加载API */
    if ( !Inn_LoadAPI() )
        return 0;

    /* 打开设备 */
    if ( !Inn_OpenDevice() )
        return 0;

    /* 登陆 */
    if ( !Inn_Login() )
        goto LB_END;

    /* 备份配用密钥 */
    Inn_EccSign();

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