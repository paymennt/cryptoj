/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;

/**
 * The Class Bytes.
 */
public class Bytes {
    
    /**
     * Reverse.
     *
     * @param bytes the bytes
     * @return the byte[]
     */
    public static byte[] reverse(byte[] bytes) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = bytes.length - 1; i >= 0; i--) {
            byteArrayOutputStream.write(bytes[i]);
        }
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Reverse from hex.
     *
     * @param hex the hex
     * @return the string
     */
    public static String reverseFromHex(String hex) {
        return Hex.toHexString(reverse(Hex.decodeStrict(hex)));
    }

    /**
     * Reverse to hex.
     *
     * @param bytes the bytes
     * @return the string
     */
    public static String reverseToHex(byte[] bytes) {
        return Hex.toHexString(reverse(bytes));
    }
}
