package com.yunjingit.common;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class RandomTest {
    private HardSM hardSM;
    private int deviceCount;

    public RandomTest() {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
    }

    @Test
    public void testRandomOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(13 * 2, this.hardSM.apiRandom(i, 0, 13).length());
            assertEquals(13 * 2, this.hardSM.apiRandom(i, this.hardSM.getThreads() - 1, 13).length());
        }
    }

    @Test(expected = SMException.class)
    public void testRandom0Error() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            this.hardSM.apiRandom(i, 0, 0);
        }
    }

    @Test
    public void testRandom1() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(2, this.hardSM.apiRandom(i, 0, 1).length());
        }
    }

    @Test
    public void testRandom1024() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(1024 * 2, this.hardSM.apiRandom(i, 0, 1024).length());
        }
    }

    @Test(expected = SMException.class)
    public void testRandom1025Error() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(1025 * 2, this.hardSM.apiRandom(i, 0, 1025).length());
        }
    }
}
