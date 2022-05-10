/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * The Class LittleEndian.
 */
public class LittleEndian {
    
    /**
     * To unsigned little endian.
     *
     * @param bytes the bytes
     * @return the big integer
     */
    public static BigInteger toUnsignedLittleEndian(byte[] bytes) {
        return new BigInteger(1, Bytes.reverse(bytes));
    }

    /**
     * From unsigned little endian.
     *
     * @param bigInteger the big integer
     * @param outputLength the output length
     * @return the byte[]
     */
    public static byte[] fromUnsignedLittleEndian(BigInteger bigInteger, int outputLength) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(outputLength, bigInteger);
        return Bytes.reverse(bytes);
    }

    /**
     * From unsigned little endian to hex.
     *
     * @param bigInteger the big integer
     * @param outputLength the output length
     * @return the string
     */
    public static String fromUnsignedLittleEndianToHex(BigInteger bigInteger, int outputLength) {
        return Hex.toHexString(fromUnsignedLittleEndian(bigInteger, outputLength));
    }
}
