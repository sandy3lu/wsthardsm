package com.yunjingit.common;

public class SMTool {
    public static void main(String[] args) throws SMException {
        HardSM hardSM = new HardSMImpl();
        hardSM.apiInit();

        try {
            testSym(hardSM, 0);
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            hardSM.apiFinal();
        }
    }

    static void testSym(HardSM hardSM, int deviceIndex) throws SMException {
        String hexKey = "0123456789abcdeffedcba9876543210";
        String hexOrigin = "0123456789abcdeffedcba9876543210";
        byte[] result = hardSM.apiEncrypt(deviceIndex, 0, hexKey, null, DataTransfer.fromHex(hexOrigin));
        System.out.println(DataTransfer.toHex(result));
    }
}
