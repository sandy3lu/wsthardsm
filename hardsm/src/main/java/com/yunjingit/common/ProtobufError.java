package com.yunjingit.common;

public class ProtobufError extends SMException {

    ProtobufError(Exception e) {
        super(500, "invalid protobuf exception", e);
    }
}
