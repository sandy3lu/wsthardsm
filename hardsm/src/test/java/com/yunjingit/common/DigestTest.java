package com.yunjingit.common;

import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

public class DigestTest {
    private HardSM hardSM;
    private int deviceCount;
    private String dataLen1 = "a";
    private String dataLen1HexDigest = "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88";
    private String dataAbc = "abc";
    private String dataAbcHexDigest = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    private String data07 = "0123456701234567012345670123456701234567012345670123456701234567";

    public DigestTest() {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
    }


    @Test
    public void testDigestOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 0, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i,
                this.hardSM.getThreads() - 1, this.dataAbc.getBytes()));
        }
    }

    @Test(expected = NullPointerException.class)
    public void testDigestNullError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigest(i, 0, null);
        }
    }

    @Test(expected = SMException.class)
    public void testDigestEmptyError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigest(i, 0, "".getBytes());
        }
    }

    @Test
    public void testDigestLen1Ok() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(this.dataLen1HexDigest, this.hardSM.apiDigest(i, 0, this.dataLen1.getBytes()));
        }
    }

    @Test
    public void testDigestVeryLongOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String str64x64 = new String(new char[64]).replace("\0", this.dataAbcHexDigest);
            this.hardSM.apiDigest(i, 0, str64x64.getBytes());
        }
    }

    @Test
    public void testDigestVeryVeryLongOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            String str64x64x1024 = new String(new char[512]).replace("\0", this.dataAbcHexDigest);
            this.hardSM.apiDigest(i, 0, str64x64x1024.getBytes());
        }
    }

    @Test
    public void testDigestInitUpdateOnceFinalOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            assertEquals("bfc9915a8586598176d98cbaf7395ac867080d4288b12db37e405c2e4f90a54c",
                this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes()));
        }
    }

    @Test
    public void testDigestInitUpdateMultiFinalOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            assertEquals("90c53c1d8e0ca427b0e372c933bfc2252a466348bb57d08a1829b33456cf7bbd",
                this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes()));
        }
    }

    @Test
    public void testDigestInitUpdateManyFinalOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            for (int j = 0; j < 10000; j++) {
                this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            }
            this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes());
        }
    }

    @Test
    public void testDigestInitUpdateFinalOverAgainOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            assertEquals("bfc9915a8586598176d98cbaf7395ac867080d4288b12db37e405c2e4f90a54c",
                this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes()));
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            assertEquals("bfc9915a8586598176d98cbaf7395ac867080d4288b12db37e405c2e4f90a54c",
                this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes()));
        }
    }

    @Test
    public void testDigestInitFinalOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigestFinal(i, 0, this.dataAbc.getBytes()));
        }
    }

    /**
     * Multi init cause crypto card in invalid state, so this case must be ignored
     * @throws SMException
     */
    @Ignore
    public void testDigestInitInitFinalError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestInit(i, 0);
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigestFinal(i, 0, this.dataAbc.getBytes()));
        }
    }

    @Test(expected = SMException.class)
    public void testDigestInitUpdateFinalUpdateFinalError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes());
            this.hardSM.apiDigestUpdate(i, 0, this.data07.getBytes());
            this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes());
        }
    }

    @Test(expected = SMException.class)
    public void testDigestInitFinalFinalError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestFinal(i, 0, this.dataAbc.getBytes());
            this.hardSM.apiDigestFinal(i, 0, this.dataAbc.getBytes());
        }
    }

    @Test(expected = SMException.class)
    public void testDigestInitUpdateInvalidLengthFinalError() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiDigestInit(i, 0);
            this.hardSM.apiDigestUpdate(i, 0, this.data07.substring(1).getBytes());
            this.hardSM.apiDigestFinal(i, 0, this.data07.getBytes());
        }
    }

    @Ignore
    @Test
    public void testDigestAlot() throws SMException {
        int counts = 10000;
        int errors = 0;
        Date start = new Date();

        for (int i = 0; i < counts; i++) {
            try {
                if (!this.dataAbcHexDigest.equals(this.hardSM.apiDigest(0, 0, this.dataAbc.getBytes()))) {
                    errors++;
                }
            } catch (SMException e) {
                errors++;
            }
        }

        Date stop = new Date();
        long timeCost = stop.getTime() - start.getTime();
        float rate = (float) counts / timeCost * 1000;

        System.out.println("Digest performance result:");
        System.out.println("counts: " + counts);
        System.out.println("errors: " + errors);
        System.out.println("time: " + timeCost);
        System.out.println("rate: " + rate);
    }

    @Test
    public void testDigestConcurrence() throws InterruptedException {
        int counts = 10000;
        int threadCounts = this.hardSM.getThreads();
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
                        if (!dataAbcHexDigest.equals(hardSM.apiDigest(0, pipeIndex, dataAbc.getBytes()))) {
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

        System.out.println("Digest concurrence performance result:");
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
