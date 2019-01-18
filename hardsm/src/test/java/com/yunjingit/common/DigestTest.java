package com.yunjingit.common;

import static org.junit.Assert.*;

import org.junit.Test;

public class DigestTest {
    private HardSM hardSM;
    private int deviceCount;
    private String dataLen1 = "a";
    private String dataLen1HexDigest = "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88";
    private String dataAbc = "abc";
    private String dataAbcHexDigest = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

    public DigestTest() {
        this.hardSM = SMTest.hardSM;
        this.deviceCount = SMTest.deviceCount;
    }

    @Test
    public void testDigestOk() throws SMException {
        for (int i = 0; i < this.deviceCount; i++) {
            assertEquals(this.dataLen1HexDigest, this.hardSM.apiDigest(i, 0, this.dataLen1.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 0, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, -1, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 31, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 32, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 99999, this.dataAbc.getBytes()));
        }
    }

    @Test(expected = NullPointerException.class)
    public void testDigestNull() throws SMException {
        if (this.deviceCount <= 0) return;
        this.hardSM.apiDigest(this.deviceCount - 1, 0, null);
    }

    @Test(expected = SMException.class)
    public void testDigestEmpty() throws SMException {
        if (this.deviceCount <= 0) return;
        this.hardSM.apiDigest(this.deviceCount - 1, 0, "".getBytes());
    }

    @Test
    public void testDigestVeryLong() throws SMException {
        if (this.deviceCount <= 0) return;
        String str64x64 = new String(new char[64]).replace("\0", this.dataAbcHexDigest);
        this.hardSM.apiDigest(this.deviceCount - 1, 0, str64x64.getBytes());
    }

    @Test
    public void testDigestVeryVeryLong() throws SMException {
        if (this.deviceCount <= 0) return;
        String str64x64x1024 = new String(new char[64 * 1024]).replace("\0", this.dataAbcHexDigest);
        this.hardSM.apiDigest(this.deviceCount - 1, 0, str64x64x1024.getBytes());
    }
}
