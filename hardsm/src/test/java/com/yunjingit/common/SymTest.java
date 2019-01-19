package com.yunjingit.common;

import org.junit.Test;
import org.junit.Ignore;
import static org.junit.Assert.*;

public class SymTest {
    private HardSM hardSM;
    private int deviceCount;
    private String hexOrigin = "0123456789abcdeffedcba9876543210";
    private String hexKey = "0123456789abcdeffedcba9876543210";
    private String hexResult = "681edf34d206965e86b3e94f536e4246";
    private byte[] bytesOrigin;

    public SymTest() throws SMException {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
        this.bytesOrigin = DataTransfer.fromHex(this.hexOrigin);
    }

    @Test
    public void testEncryptDecryptOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
//            byte[] result = this.hardSM.apiEncrypt(i, 0, this.hexKey, null, this.bytesOrigin);
//            assertEquals(this.hexResult, DataTransfer.toHex(result));
//            System.out.println(DataTransfer.toHex(result));
        }
    }

    @Test
    public void testGenKeyEncryptDecryptOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
//            String key = this.hardSM.apiGenerateKey(i, 0);
//            byte[] encrypted = this.hardSM.apiEncrypt(i, 0, key, null, this.bytesOrigin);
//            byte[] decrypted = this.hardSM.apiDecrypt(i, 0, key, null, encrypted);
//            System.out.println(DataTransfer.toHex(decrypted));
        }
    }
}
