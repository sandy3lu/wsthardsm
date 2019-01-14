package com.yunjingit.common;

public class SMException extends Exception {
    private int code;
    private String msg;

    SMException(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public int getCode() {
        return this.code;
    }

    public String getMsg() {
        return this.msg;
    }

    @Override
    public String toString() {
        return String.format("{\"code\": \"%d\", \"msg\": \"%s\"}",
            this.code, this.msg);
    }
}
