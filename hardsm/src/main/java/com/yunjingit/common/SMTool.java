package com.yunjingit.common;

import com.yunjingit.common.Sm.CtxInfo;

public class SMTool {
    public static void main( String[] args ) throws SMException {
        HardSM hardSM = new HardSMImpl();
        hardSM.apiInit();
        System.out.println(hardSM.apiPrintContext(true));
        SMTool.testCtxInfo(hardSM);
        hardSM.apiFinal();
    }

    private static void testCtxInfo(HardSM hardSM) throws SMException {
        CtxInfo ctxInfo = hardSM.apiCtxInfo();
        System.out.println("protect_key: " + ctxInfo.getProtectKey());
        System.out.println("device_count: " + ctxInfo.getDeviceCount());
        System.out.println("api_version: " + ctxInfo.getApiVersion());
    }
}
