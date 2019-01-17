package com.yunjingit.common;

import java.io.IOException;

public class SMTool {
    public static void main( String[] args ) throws IOException, SMException {
        HardSMImpl csmApi = new HardSMImpl();
        csmApi.api_init();
        csmApi.api_final();
    }
}
