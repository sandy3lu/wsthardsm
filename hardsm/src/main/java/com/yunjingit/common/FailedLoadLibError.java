package com.yunjingit.common;

public class FailedLoadLibError extends SMException {
    FailedLoadLibError(Exception e) {
        super(500, "failed load c library exception", e);
    }
}
