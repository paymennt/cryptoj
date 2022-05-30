/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;

/**
 * @author paymennt
 * 
 */
public class Bytes {
    
    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static byte[] reverse(byte[] bytes) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = bytes.length - 1; i >= 0; i--) {
            byteArrayOutputStream.write(bytes[i]);
        }
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * 
     *
     * @param hex 
     * @return 
     */
    public static String reverseFromHex(String hex) {
        return Hex.toHexString(reverse(Hex.decodeStrict(hex)));
    }

    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static String reverseToHex(byte[] bytes) {
        return Hex.toHexString(reverse(bytes));
    }
}
