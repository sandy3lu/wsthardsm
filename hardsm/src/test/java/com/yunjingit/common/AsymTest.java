package com.yunjingit.common;

import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
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

    @Ignore
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

    @Ignore
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

    @Test
    public void testSignConcurrence() throws InterruptedException, SMException {
        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);

        int counts = 10000;
        int threadCounts = 10;
        AtomicInteger errors = new AtomicInteger(0);
        ArrayList<Thread> threads = new ArrayList<>();
        final Exception[] exception = {null};
        final long[] costs = new long[threadCounts];
        List<List<String>> signatures = new ArrayList<>();
        for (int i = 0; i < threadCounts; i++) {
            signatures.add(new ArrayList<String>());
        }

        for (int i = 0; i < threadCounts; i++) {
            int thread = i;
            int pipeIndex = i % 32;
            List<String> sigs = signatures.get(i);
            Thread t = new Thread(() -> {
                Date start = new Date();

                for (int j = 0; j < counts; j++) {
                    try {
                        String signature = hardSM.apiSign(0, pipeIndex, keyPair.getPrivateKey(), originData);
                        sigs.add(signature);
                    } catch (SMException e) {
                        errors.incrementAndGet();
                        exception[0] = e;
                    }
                }

                Date stop = new Date();
                costs[thread] = stop.getTime() - start.getTime();
            });
            t.start();
            threads.add(t);
        }
        for (Thread t : threads) {
            t.join();
        }

        // verify
        int verifyErrors = 0;
        for (List<String> l : signatures) {
            for (String s : l) {
                int result = this.hardSM.apiVerify(0, 0, keyPair.getPublicKey(), originData, s);
                if (0 != result) {
                    verifyErrors++;
                }
            }
        }

        System.out.println("Sign concurrence performance result:");
        System.out.println("threads: " + threadCounts);
        System.out.println("counts per thread: " + counts);
        System.out.println("errors: " + errors.get());
        System.out.println("verify errors: " + verifyErrors);
        System.out.println("average time: " + this.average(costs));
        System.out.println("average rate: " + this.averageRate(costs, counts));
        System.out.println("top rate: " + this.averageRate(costs, counts) * threadCounts);

        if (null != exception[0]) {
            exception[0].printStackTrace();
        }
    }

    @Ignore
    @Test
    public void testVerifyConcurrence() throws InterruptedException, SMException {
        String originData = "0123456701234567012345670123456701234567012345670123456701234567";
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);
        String signature = this.hardSM.apiSign(0, 0, keyPair.getPrivateKey(), originData);

        int counts = 10000;
        int threadCounts = 10;
        AtomicInteger errors = new AtomicInteger(0);
        ArrayList<Thread> threads = new ArrayList<>();
        final Exception[] exception = {null};
        final long[] costs = new long[threadCounts];

        for (int i = 0; i < threadCounts; i++) {
            int pipeIndex = i;
            Thread t = new Thread(() -> {
                Date start = new Date();

                for (int j = 0; j < counts; j++) {
                    try {
                        int result = this.hardSM.apiVerify(0, pipeIndex, keyPair.getPublicKey(), originData, signature);
                        if (0 != result) {
                            errors.incrementAndGet();
                        }
                    } catch (SMException e) {
                        errors.incrementAndGet();
                        exception[0] = e;
                    }
                }
                Date stop = new Date();
                costs[pipeIndex] = stop.getTime() - start.getTime();
            });
            t.start();
            threads.add(t);
        }
        for (Thread t : threads) {
            t.join();
        }

        System.out.println("Verify concurrence performance result:");
        System.out.println("threads: " + threadCounts);
        System.out.println("counts per thread: " + counts);
        System.out.println("errors: " + errors.get());
        System.out.println("average time: " + this.average(costs));
        System.out.println("average rate: " + this.averageRate(costs, counts));
        System.out.println("top rate: " + this.averageRate(costs, counts) * threadCounts);

        if (null != exception[0]) {
            exception[0].printStackTrace();
        }
    }

    private float average(long[] values) {
        float total = 0.0f;
        for (long v : values) {
            total += v;
        }

        return total / values.length;
    }

    private float averageRate(long[] costs, int perCounts) {
        float totalRate = 0.0f;

        for (long v : costs) {
            totalRate += (float) perCounts / v * 1000;
        }

        return totalRate / costs.length;
    }
}
