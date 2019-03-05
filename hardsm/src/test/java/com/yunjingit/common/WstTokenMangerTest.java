package com.yunjingit.common;

import com.sun.jna.Native;
import com.yunjingit.common.crypto.WstTokenManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

public class WstTokenMangerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testLib(){

        Native.setProtected(true);
        System.out.println("Native.isProtected = " +Native.isProtected());

        WstTokenManager wstTokenManager = new WstTokenManager();
        try {
            wstTokenManager.initResource("11111111",5);
            for(int i=0;i<100;i++) {

                boolean result = wstTokenManager.test(16);
                System.out.println("------- test " + i + " ---- "+ result);
            }
        } catch (Exception e) {
            e.printStackTrace();

        }finally {
            wstTokenManager.finalize();
        }

    }

}
