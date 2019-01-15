package com.yunjingit.common;

import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;

public class SMTool {
    public static void main( String[] args ) throws IOException, SMException {
        CSMApiImpl csmApi = new CSMApiImpl();
        csmApi.api_init();
        csmApi.api_final();
    }
}
