package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({DigestTest.class, RandomTest.class, SymTest.class, AsymTest.class})
public class SMTest {
    static int deviceCount;
    static HardSM hardSM;

    @BeforeClass
    public static void initResource() throws SMException {
        hardSM = new HardSMImpl();
        hardSM.apiInit();
        CtxInfo ctxInfo = hardSM.apiCtxInfo();
        deviceCount = ctxInfo.getDeviceCount();
        for (int i = 0; i < ctxInfo.getDeviceCount(); i++) {
            hardSM.apiLoginDevice(i, "11111111");
        }
    }

    @AfterClass
    public static void disposeResource() {
        try {
            printDeviceStatus();
            for (int i = 0; i < deviceCount; i++) {
                hardSM.apiLogoutDevice(i);
            }
            hardSM.apiFinal();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static void printDeviceStatus() throws SMException {
        for (int i = 0; i < deviceCount; i++) {
            DevStatus devStatus = hardSM.apiDeviceStatus(i);
            System.out.println("index: " + devStatus.getIndex());
            System.out.println("opened: " + devStatus.getOpened());
            System.out.println("logged_in: " + devStatus.getLoggedIn());
            System.out.println("pipes_count: " + devStatus.getPipesCount());
            System.out.println("free_pipes_count: " + devStatus.getFreePipesCount());
            System.out.println("secret_key_count: " + devStatus.getSecretKeyCount());
            System.out.println("public_key_count: " + devStatus.getPublicKeyCount());
            System.out.println("private_key_count: " + devStatus.getPrivateKeyCount());
        }
    }
}
