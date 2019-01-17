package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;
import com.yunjingit.common.Sm.DevStatus;
import com.yunjingit.common.test.TestContext;

public class SMTool {
    public static void main( String[] args ) {
        new TestContext().testAllCases();
    }

    static void test() throws SMException {
        HardSM hardSM = new HardSMImpl();
        hardSM.apiInit();
        System.out.println(hardSM.apiPrintContext(true));
        SMTool.testCtxInfo(hardSM);

        SMTool.testDevice(hardSM, 0, "11111111");
        SMTool.testDevice(hardSM, 1, "11111111");

        hardSM.apiFinal();
    }

    static void testCtxInfo(HardSM hardSM) throws SMException {
        CtxInfo ctxInfo = hardSM.apiCtxInfo();
        System.out.println("protect_key: " + ctxInfo.getProtectKey());
        System.out.println("device_count: " + ctxInfo.getDeviceCount());
        System.out.println("api_version: " + ctxInfo.getApiVersion());
    }

    static void testDevice(HardSM hardSM, int index, String pinCode) throws SMException {
        hardSM.apiLoginDevice(index, pinCode);

        SMTool.testDeviceStatus(hardSM, index);
        SMTool.testDigest(hardSM, index, 0, "abc");
        SMTool.testDigest(hardSM, index, 31, "abc");

        SMTool.testSectionDigest(hardSM, index, 0, "0123456701234567012345670123456701234567012345670123456701234567");
        SMTool.testSectionDigest(hardSM, index, 31, "0123456701234567012345670123456701234567012345670123456701234567");

        SMTool.testRandom(hardSM, index, 0, 1);
        SMTool.testRandom(hardSM, index, 0, 128);
        SMTool.testRandom(hardSM, index, 31, 1);
        SMTool.testRandom(hardSM, index, 31, 128);

        hardSM.apiLogoutDevice(index);
    }

    static void testDeviceStatus(HardSM hardSM, int index) throws SMException {
        DevStatus devStatus = hardSM.apiDeviceStatus(index);
        System.out.println("index: " + devStatus.getIndex());
        System.out.println("opened: " + devStatus.getOpened());
        System.out.println("logged_in: " + devStatus.getLoggedIn());
        System.out.println("pipes_count: " + devStatus.getPipesCount());
        System.out.println("free_pipes_count: " + devStatus.getFreePipesCount());
        System.out.println("secret_key_count: " + devStatus.getSecretKeyCount());
        System.out.println("public_key_count: " + devStatus.getPublicKeyCount());
        System.out.println("private_key_count: " + devStatus.getPrivateKeyCount());
    }

    static void testDigest(HardSM hardSM, int deviceIndex, int pipeIndex, String data) throws SMException {
        System.out.println(hardSM.apiDigest(deviceIndex, pipeIndex, data.getBytes()));
    }

    static void testSectionDigest(HardSM hardSM, int deviceIndex, int pipeIndex, String data) throws SMException {
        hardSM.apiDigestInit(deviceIndex, pipeIndex);
        hardSM.apiDigestUpdate(deviceIndex, pipeIndex, data.getBytes());
        hardSM.apiDigestUpdate(deviceIndex, pipeIndex, data.getBytes());
        System.out.println(hardSM.apiDigestFinal(deviceIndex, pipeIndex, data.getBytes()));
    }

    static void testRandom(HardSM hardSM, int deviceIndex, int pipeIndex, int length) throws SMException {
        System.out.println(hardSM.apiRandom(deviceIndex, pipeIndex, length));
    }
}
