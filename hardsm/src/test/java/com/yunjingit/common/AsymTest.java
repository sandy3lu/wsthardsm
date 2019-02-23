package com.yunjingit.common;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Date;
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
            String signature = "0123456701234567012345670123456701234567012345670123456701234567"
                + "0123456701234567012345670123456701234567012345670123456701234567";
            int result = this.hardSM.apiVerify(i, 0, keyPair.getPublicKey(), originData, signature);
            assertNotEquals(0, result);
        }
    }

    @Test
    public void testASignBVerifyOk() throws SMException {
        if (this.deviceCount < 2) return;

        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);
        String signature = this.hardSM.apiSign(1, 0, keyPair.getPrivateKey(), originData);
        int result = this.hardSM.apiVerify(0, 0, keyPair.getPublicKey(), originData, signature);
        assertEquals(0, result);
    }

    @Test
    public void testBSignAVerifyOk() throws SMException {
        if (this.deviceCount < 2) return;

        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(1, 0);
        String signature = this.hardSM.apiSign(0, 0, keyPair.getPrivateKey(), originData);
        int result = this.hardSM.apiVerify(1, 0, keyPair.getPublicKey(), originData, signature);
        assertEquals(0, result);
    }

    @Test
    public void testSignAlot() throws SMException {
        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);

        int counts = 10000;
        int errors = 0;
        Date start = new Date();

        for (int i = 0; i < counts; i++) {
            try {
                this.hardSM.apiSign(0, 0, keyPair.getPrivateKey(), originData);
            } catch (SMException e) {
                errors++;
            }
        }

        Date stop = new Date();
        long timeCost = stop.getTime() - start.getTime();
        float rate = (float) counts / timeCost * 1000;

        System.out.println("Sign performance result:");
        System.out.println("counts: " + counts);
        System.out.println("errors: " + errors);
        System.out.println("time: " + timeCost);
        System.out.println("rate: " + rate);
    }

    @Test
    public void testVerifyAlot() throws SMException {
        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);
        String signature = this.hardSM.apiSign(0, 0, keyPair.getPrivateKey(), originData);

        int counts = 10000;
        int errors = 0;
        Date start = new Date();

        for (int i = 0; i < counts; i++) {
            try {
                int result = this.hardSM.apiVerify(0, 0, keyPair.getPublicKey(), originData, signature);
                if (0 != result) {
                    errors++;
                }
            } catch (SMException e) {
                errors++;
            }
        }

        Date stop = new Date();
        long timeCost = stop.getTime() - start.getTime();
        float rate = (float) counts / timeCost * 1000;

        System.out.println("Verify performance result:");
        System.out.println("counts: " + counts);
        System.out.println("errors: " + errors);
        System.out.println("time: " + timeCost);
        System.out.println("rate: " + rate);
    }
}
