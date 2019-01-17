package com.yunjingit.common.test;

import com.yunjingit.common.HardSM;
import com.yunjingit.common.HardSMImpl;
import com.yunjingit.common.Sm.CtxInfo;

public class TestContext {
    private HardSM hardSM = new HardSMImpl();

    public void testAllCases() {
        this.testGetCtxInfoBeforeInit();
        this.testInitFinalOverAgain();
        this.testInitFinalNormal();
    }

    /**
     * Test case get context info before context init, expect empty values.
     */
    private void testGetCtxInfoBeforeInit() {
        try {
            CtxInfo ctxInfo = this.hardSM.apiCtxInfo();
            assert ctxInfo.getApiVersion().equals("");
            assert ctxInfo.getDeviceCount() == 0;
            assert !ctxInfo.getProtectKey();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void testInitFinal() {
        try {
            this.hardSM.apiInit();
            this.hardSM.apiFinal();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void testInitMultiFinal() {
        try {
            this.hardSM.apiInit();
            this.hardSM.apiFinal();
            this.hardSM.apiFinal();
            this.hardSM.apiFinal();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    /**
     * Final is idempotent, so can call final any times no matter it is initialized or not.
     */
    private void testInitFinalOverAgain() {
        this.testInitFinal();
        this.testInitMultiFinal();
        this.testInitFinal();
    }

    private void testInitFinalNormal() {
        try {
            this.hardSM.apiInit();

            CtxInfo ctxInfo = this.hardSM.apiCtxInfo();
            for (int i = 0; i < ctxInfo.getDeviceCount(); i++) {
                testLoginLogoutOverAgain(i, "11111111");
            }

            this.hardSM.apiFinal();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void testLoginLogout(int deviceIndex, String pinCode) {
        try {
            this.hardSM.apiLoginDevice(deviceIndex, pinCode);
            this.hardSM.apiLogoutDevice(deviceIndex);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void testLoginMultiLogout(int deviceIndex, String pinCode) {
        try {
            this.hardSM.apiLoginDevice(deviceIndex, pinCode);
            this.hardSM.apiLogoutDevice(deviceIndex);
            this.hardSM.apiLogoutDevice(deviceIndex);
            this.hardSM.apiLogoutDevice(deviceIndex);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private void testLoginLogoutOverAgain(int deviceIndex, String pinCode) {
        this.testLoginLogout(deviceIndex, pinCode);
        this.testLoginMultiLogout(deviceIndex, pinCode);
        this.testLoginLogout(deviceIndex, pinCode);
    }
}
