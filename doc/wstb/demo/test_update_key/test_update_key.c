/* ///////////////////////////////////////////////////////////////////////// */
/* header files */
#include "PlateformDefine.h"
#include "api_dll50.h"
#include "base64.h"

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

SM_VOID Inn_UpdateKey()
{
    SM_CHAR public_key_base64[] = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDvns1zeAKV0zHBKbczTo0klxO4Dd+gLyifaMmQk+6JLDPXg4pEstTuPrHRMv5b4uanPi9LO7Kyp3zJxlBCJp3s8IZ74MSmwxc+GKMyGZkG9oBoX8DWHStSlEYusDjo/OA7K+UjpokFMU+jtUdDiMAim0AG9SQmExitvGud8gnLkQIDAQAB";
    SM_CHAR private_key_base64[] = "MIICXQIBAAKBgQDvns1zeAKV0zHBKbczTo0klxO4Dd+gLyifaMmQk+6JLDPXg4pEstTuPrHRMv5b4uanPi9LO7Kyp3zJxlBCJp3s8IZ74MSmwxc+GKMyGZkG9oBoX8DWHStSlEYusDjo/OA7K+UjpokFMU+jtUdDiMAim0AG9SQmExitvGud8gnLkQIDAQABAoGABxm3kNJfkTz+3nB0A0syl4D6jpuqor6C/6ZFQsl/agUrTBmTwVFjSeQFtOND8kkY+J+5Gwub0ftwkTIVMsCeMVaH3KOHhIOLZ2C8OibwnGEwK4ae5X8maghPmBazCiz3OP0sWUWDLMlmeFLXtJX8iEFmblq1FtZFojt3VIi9yHkCQQD/R/TreJ4NSfq9qFJghTSXagAccthdJ9xcK7I+cUubsq6ojRzAAV83+tPU8gh+53yk2bx5buEGrl+sJA/4DgyTAkEA8EuOKCj2pGl7wdqXmAVpNApy99inRKOaPjdvOTX3i7RHHz7sBuZB+fThoZTYNkFIpA02CE37DFprcmnUGMnBywJBAO81m0BnJxtmvkmoB4EgcRaNIouF5k7sgiXwYDb47RN5zQZuLImS/4myRXteTS21duv2iBD2IHClR0tEA566c3cCQQDRbhiNGf61FxZ8w2bCYVzqtXy0VQicAzcoqKnwo/+HrG0cZ3vRG5g/IVYRvSegSc/k43rHTCfVAW2KP4BSxm13AkAjHlw4LG2cDVH33p9Tti7tvmPffgEpTQmXweUtLEe6bzvvNauCNQwGUf/RvANqHbHMAitJvhH43CSv7vDm4W5k";

    SM_BYTE public_key[2048] = {0};
    SM_BYTE private_key[2048] = {0};

    SM_UINT private_key_len = 0, public_key_len = 0;

    public_key_len = Base64decode(public_key, public_key_base64);
    private_key_len = Base64decode(private_key, private_key_base64);

    printf("public_key_len: %d,  private_key_len: %d\n", public_key_len, private_key_len);

    SM_BLOB_KEY private_blob;
    memset(&private_blob, 0, sizeof(SM_BLOB_KEY));
    private_blob.pbyData = (PSM_BYTE)private_key;
    private_blob.uiDataLen = private_key_len;

    SM_BLOB_KEY public_blob;
    memset(&public_blob, 0, sizeof(SM_BLOB_KEY));
    public_blob.pbyData = (PSM_BYTE)public_key;
    public_blob.uiDataLen = public_key_len;

    SM_RV ret =0;

    printf("更新配用密钥......");
    ret = g_pDllMang->m_pfn_SM_UpdateKeyPair(g_stHandle.hPipe, &public_blob, &private_blob, SMKF_UPDATE_KEY_PAIR_SIGN, "00000000", 8);
    if (ret != SM_ERR_FREE){
        printf("失败(%s)!\n", g_pDllMang->m_pfn_SM_GetErrorString(ret, FALSE));
        return;
    } else {
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
    Inn_UpdateKey();

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