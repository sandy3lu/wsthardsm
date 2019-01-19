package com.yunjingit.common;

public class DataTransfer {
    private final static char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xff;
            hexChars[j * 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0f];
        }
        return new String(hexChars);
    }

    public static byte[] fromHex(String hex) throws SMException {
        if ((hex.length() & 0x01) == 0x01) {
            throw new SMException(500, hex + " not a valid hex string");
        }

        char[] chars = hex.toLowerCase().toCharArray();
        byte[] ret = new byte[chars.length / 2];

        for (int i = 0; i < chars.length; i += 2) {
            int a = Character.digit(chars[i], 0x10);
            int b = Character.digit(chars[i + 1], 0x10);
            if (a== -1 || b == -1) {
                throw new SMException(500, "non-hex digit");
            }
            ret[i/2] = (byte) ((a<<4)+b);
        }
        return ret;
    }
}
