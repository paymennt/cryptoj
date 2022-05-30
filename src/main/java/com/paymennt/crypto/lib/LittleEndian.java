/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * @author paymennt
 * 
 */
public class LittleEndian {
    
    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static BigInteger toUnsignedLittleEndian(byte[] bytes) {
        return new BigInteger(1, Bytes.reverse(bytes));
    }

    /**
     * 
     *
     * @param bigInteger 
     * @param outputLength 
     * @return 
     */
    public static byte[] fromUnsignedLittleEndian(BigInteger bigInteger, int outputLength) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(outputLength, bigInteger);
        return Bytes.reverse(bytes);
    }

    /**
     * 
     *
     * @param bigInteger 
     * @param outputLength 
     * @return 
     */
    public static String fromUnsignedLittleEndianToHex(BigInteger bigInteger, int outputLength) {
        return Hex.toHexString(fromUnsignedLittleEndian(bigInteger, outputLength));
    }
}
