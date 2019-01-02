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


int from_hex(char *buf, int *len, const char *hexdata) {

    int i;
    for (i = 0; i < strlen(hexdata); i++) {
        char c = hexdata[i];
        c = tolower(c);
        int val = c > '9'? 10 + c - 'a' : c - '0';

        if (i & 0x01) {
            *buf |= (val);
            buf++;
        } else {
            *buf = (val << 4);
        }
    }
    *len = strlen(hexdata) / 2;
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

SM_VOID Inn_EccVerify()
{

    SM_CHAR hex_data[] = "3132333435363738396162636465666731323334353637383961626364656667";
    SM_CHAR hex_signature[] = "A1F6EA980500135E6C8B7AC2B76798E040A94D16DB8CBD5A88055EFE86C44382D6BCD6BBFC06CD8407C6693E1F9719C87583D200A225DDE65A0E817CA3A85F5D";
    SM_CHAR hex_key[] = "02BEE412CA56F17808AFD054AAE0FCE24CE802ED7B0AAEEE9F6E27AD3532EF29A8A83445B2F24944939548614E11AC25FC392E06DCE4A097EF29105794FC1984";

    SM_BYTE data[1024] = {0};
    SM_BYTE signature[1024] = {0};
    SM_BYTE key[1024] = {0};
    SM_UINT data_len = 0, signature_len = 0, key_len = 0;

    from_hex(data, &data_len, hex_data);
    from_hex(signature, &signature_len, hex_signature);
    from_hex(key, &key_len, hex_key);


    SM_BLOB_KEY blob_key;
    memset(&blob_key, 0, sizeof(SM_BLOB_KEY));
    blob_key.pbyData = (PSM_BYTE)key;
    blob_key.uiDataLen = key_len;

    SM_ALGORITHM verify_algorithm;
    memset(&verify_algorithm, 0, sizeof(SM_ALGORITHM));
    verify_algorithm.AlgoType = SMM_ECC_FP_VERIFY;
    verify_algorithm.pParameter = SM_NULL;
    verify_algorithm.uiParameterLen = 0;
    verify_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

    SM_RV ret = 0;

    printf("验证数据......");
    ret = g_pDllMang->m_pfn_SM_ECCVerify(g_stHandle.hPipe, &blob_key, &verify_algorithm,
        data, data_len, signature, signature_len);
    if (ret != SM_ERR_FREE)
    {
        printf("失败(%s)!\n\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return FALSE;
    }
    else
    {
        printf("成功\n");
    }

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
    Inn_EccVerify();

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