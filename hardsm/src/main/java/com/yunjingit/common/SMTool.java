package com.yunjingit.common;

import com.google.protobuf.InvalidProtocolBufferException;

public class SMTool {
    public static void main( String[] args ) throws InvalidProtocolBufferException, SMException {
        CSMApiImpl csmApi = new CSMApiImpl();
        csmApi.api_init();
        csmApi.api_final();
    }
}
