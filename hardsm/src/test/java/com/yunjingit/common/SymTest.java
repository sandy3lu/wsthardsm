package com.yunjingit.common;

import org.junit.Test;
import static org.junit.Assert.*;

public class SymTest {
    private HardSM hardSM;
    private int deviceCount;
    private String hexOrigin = "0123456789abcdeffedcba9876543210";
    private String hexKey = "0123456789abcdeffedcba9876543210";
    private String hexKeyIv = "0123456789abcdeffedcba9876543210";
    private String hexResult = "681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2";
    private byte[] bytesOrigin;

    public SymTest() throws SMException {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
        this.bytesOrigin = DataTransfer.fromHex(this.hexOrigin);
    }

    @Test
    public void testEncryptOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            byte[] result = this.hardSM.apiEncrypt(i, 0, this.hexKey, null, this.bytesOrigin);
            assertEquals(this.hexResult, DataTransfer.toHex(result));
        }
    }

    @Test
    public void testDecryptOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            byte[] decrypted = this.hardSM.apiDecrypt(i, 0, this.hexKey, null, DataTransfer.fromHex(this.hexResult));
            assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
        }
    }

    @Test
    public void testGenKeyEncryptDecryptOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String key = this.hardSM.apiGenerateKey(i, 0);
            byte[] encrypted = this.hardSM.apiEncrypt(i, 0, key, null, this.bytesOrigin);
            byte[] decrypted = this.hardSM.apiDecrypt(i, 0, key, null, encrypted);
            assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
        }
    }

    @Test
    public void testAEncryptBDecryptOk() throws SMException {
        if (this.deviceCount < 2) return;
        byte[] encrypted = this.hardSM.apiEncrypt(0, 0, this.hexKey, null, this.bytesOrigin);
        byte[] decrypted = this.hardSM.apiDecrypt(1, 0, this.hexKey, null, encrypted);
        assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
    }

    @Test
    public void testBEncryptADecryptOk() throws SMException {
        if (this.deviceCount < 2) return;
        byte[] encrypted = this.hardSM.apiEncrypt(1, 0, this.hexKey, null, this.bytesOrigin);
        byte[] decrypted = this.hardSM.apiDecrypt(0, 0, this.hexKey, null, encrypted);
        assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
    }

    @Test
    public void testEncryptDifferentLenOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[1]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[7]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[17]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[1023]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[1024]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[1025]).replace("\0", "a").getBytes());
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, new String(new char[10250]).replace("\0", "a").getBytes());
        }
    }

    @Test(expected = SMException.class)
    public void testDecryptInvalidLen() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDecrypt(i, 0, this.hexKey, null, new String(new char[17]).replace("\0", "a").getBytes());
        }
    }

    @Test(expected = NullPointerException.class)
    public void testEncryptNull() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, null);
        }
    }

    @Test(expected = SMException.class)
    public void testEncryptEmpty() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiEncrypt(i, 0, this.hexKey, null, "".getBytes());
        }
    }

    @Test(expected = NullPointerException.class)
    public void testDecryptNull() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDecrypt(i, 0, this.hexKey, null, null);
        }
    }

    @Test(expected = SMException.class)
    public void testDecryptEmpty() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDecrypt(i, 0, this.hexKey, null, "".getBytes());
        }
    }

    @Test
    public void testEncryptDecryptWithIvOk() throws SMException {
        if (this.deviceCount < 2) return;

        byte[] encrypted = this.hardSM.apiEncrypt(0, 0, this.hexKey, this.hexKeyIv, this.bytesOrigin);
        assertNotEquals(this.hexResult, DataTransfer.toHex(encrypted));
        byte[] decrypted = this.hardSM.apiDecrypt(1, 0, this.hexKey, this.hexKeyIv, encrypted);
        assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
    }

//    @Test
//    public void testEncryptInitFinal() throws SMException {
//        for (int i = 0; i < this.deviceCount; i++) {
//            this.hardSM.apiEncryptInit(i, 0, this.hexKey, null);
//            byte[] encrypted = this.hardSM.apiEncryptFinal(0, 0, this.bytesOrigin);
//            System.out.println(DataTransfer.toHex(encrypted));
//            assertEquals(this.hexResult, DataTransfer.toHex(encrypted));
//        }
//    }

//    @Test
//    public void testDecryptInitFinal() throws SMException {
//        for (int i = 0; i < this.deviceCount; i++) {
//            this.hardSM.apiDecryptInit(i, 0, this.hexKey, null);
//            byte[] decrypted = this.hardSM.apiDecryptFinal(0, 0, DataTransfer.fromHex(this.hexResult));
//            assertEquals(this.hexOrigin, DataTransfer.toHex(decrypted));
//        }
//    }
}
