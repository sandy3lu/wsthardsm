package com.yunjingit.common;

import org.junit.Ignore;
import org.junit.Test;
import static org.junit.Assert.*;

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
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, -1, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 31, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 32, this.dataAbc.getBytes()));
            assertEquals(this.dataAbcHexDigest, this.hardSM.apiDigest(i, 99999, this.dataAbc.getBytes()));
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
            String str64x64x1024 = new String(new char[64 * 1024]).replace("\0", this.dataAbcHexDigest);
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
}
