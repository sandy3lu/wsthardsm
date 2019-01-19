package com.yunjingit.common;

import org.junit.Test;
import static org.junit.Assert.*;
import com.yunjingit.common.Sm.KeyPair;

public class AsymTest {
    private HardSM hardSM;
    private int deviceCount;

    public AsymTest() {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
    }

    @Test
    public void testGenKeySignVerifyOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String originData = "0123456701234567012345670123456701234567012345670123456701234567";
            KeyPair keyPair = this.hardSM.apiGenerateKeyPair(i, 0);
            String signature = this.hardSM.apiSign(i, 0, keyPair.getPrivateKey(), originData);
            int result = this.hardSM.apiVerify(i, 0, keyPair.getPublicKey(), originData, signature);
            assertEquals(0, result);
        }
    }

    @Test(expected = SMException.class)
    public void testDataLenInvalid() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String originData = "012345670123456701234567012345670123456701234567012345670123456";
            KeyPair keyPair = this.hardSM.apiGenerateKeyPair(i, 0);
            String signature = this.hardSM.apiSign(i, 0, keyPair.getPrivateKey(), originData);
            int result = this.hardSM.apiVerify(i, 0, keyPair.getPublicKey(), originData, signature);
            assertEquals(0, result);
        }
    }

    @Test
    public void testGenKeySignVerifyDataBroken() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String originData = "0123456701234567012345670123456701234567012345670123456701234567";
            KeyPair keyPair = this.hardSM.apiGenerateKeyPair(i, 0);
            String signature = this.hardSM.apiSign(i, 0, keyPair.getPrivateKey(), originData);
            originData = "1123456701234567012345670123456701234567012345670123456701234567";
            int result = this.hardSM.apiVerify(i, 0, keyPair.getPublicKey(), originData, signature);
            assertNotEquals(0, result);
        }
    }

    @Test
    public void testGenKeySignVerifyPubKeyBroken() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String originData = "0123456701234567012345670123456701234567012345670123456701234567";
            KeyPair keyPair = this.hardSM.apiGenerateKeyPair(i, 0);
            String signature = this.hardSM.apiSign(i, 0, keyPair.getPrivateKey(), originData);
            String pubKey = "0123456701234567012345670123456701234567012345670123456701234567"
                + "0123456701234567012345670123456701234567012345670123456701234567";
            int result = this.hardSM.apiVerify(i, 0, pubKey, originData, signature);
            assertNotEquals(0, result);
        }
    }

    @Test
    public void testGenKeySignVerifySignatureBroken() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String originData = "0123456701234567012345670123456701234567012345670123456701234567";
            KeyPair keyPair = this.hardSM.apiGenerateKeyPair(i, 0);
            String signature = this.hardSM.apiSign(i, 0, keyPair.getPrivateKey(), originData);
            signature = "0123456701234567012345670123456701234567012345670123456701234567"
                + "0123456701234567012345670123456701234567012345670123456701234567";
            int result = this.hardSM.apiVerify(i, 0, keyPair.getPublicKey(), originData, signature);
            assertNotEquals(0, result);
        }
    }
}
