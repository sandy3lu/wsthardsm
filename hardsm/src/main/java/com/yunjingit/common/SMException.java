package com.yunjingit.common;

import java.io.PrintWriter;
import java.io.StringWriter;

public class SMException extends Exception {
    private int code;
    private String msg;
    private Exception e;

    SMException(int code, String msg) {
        this.code = code;
        this.msg = msg;
        this.e = null;
    }

    SMException(int code, String msg, Exception e) {
        this.code = code;
        this.msg = msg;
        this.e = e;
    }

    public int getCode() {
        return this.code;
    }

    public String getMsg() {
        return this.msg;
    }

    public Exception getE() {
        return this.e;
    }

    @Override
    public String toString() {
        String details = "";

        if (null != this.e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            details = sw.toString();
        }
        return String.format("{\"code\": %d, \"msg\": \"%s\", \"details\": \"%s\"}",
            this.code, this.msg, details);
    }
}
