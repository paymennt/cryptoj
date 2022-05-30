/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto.bip32.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author paymennt
 * 
 */
public class HdUtil {

    /**
     * 
     *
     * @param i 
     * @return 
     */
    public static byte[] ser32(long i) {

        byte[] ser = new byte[4];
        ser[0] = (byte) (i >> 24);
        ser[1] = (byte) (i >> 16);
        ser[2] = (byte) (i >> 8);
        ser[3] = (byte) (i);
        return ser;
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static byte[] ser256(BigInteger p) {
        byte[] byteArray = p.toByteArray();
        byte[] ret = new byte[32];

        //0 fill value
        Arrays.fill(ret, (byte) 0);

        //copy the bigint in
        if (byteArray.length <= ret.length) {
            System.arraycopy(byteArray, 0, ret, ret.length - byteArray.length, byteArray.length);
        } else {
            System.arraycopy(byteArray, byteArray.length - ret.length, ret, 0, ret.length);
        }

        return ret;
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static byte[] ser256LE(BigInteger p) {

        byte[] byteArray = p.toByteArray();
        reverse(byteArray);

        byte[] ret = new byte[32];

        //0 fill value
        Arrays.fill(ret, (byte) 0);

        //copy the bigint in
        if (byteArray.length <= ret.length) {
            System.arraycopy(byteArray, 0, ret, ret.length - byteArray.length, byteArray.length);
        } else {
            System.arraycopy(byteArray, byteArray.length - ret.length, ret, 0, ret.length);
        }

        return ret;
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static BigInteger parse256(byte[] p) {
        return new BigInteger(1, p);
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static BigInteger parse256LE(byte[] p) {
        byte[] copy = clone(p);
        reverse(copy);

        return new BigInteger(1, copy);
    }

    /**
     * 
     *
     * @param a 
     * @param b 
     * @return 
     */
    public static byte[] append(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * 
     *
     * @param keyData 
     * @return 
     */
    public static byte[] getFingerprint(byte[] keyData) {
        byte[] point = Secp256k1.serP(Secp256k1.point(HdUtil.parse256(keyData)));
        byte[] h160 = Hash.h160(point);
        return new byte[] { h160[0], h160[1], h160[2], h160[3] };
    }

    /**
     * 
     *
     * @param i 
     * @return 
     */
    public static byte[] ser32LE(long i) {
        byte[] ser = new byte[4];
        ser[3] = (byte) (i >> 24);
        ser[2] = (byte) (i >> 16);
        ser[1] = (byte) (i >> 8);
        ser[0] = (byte) (i);
        return ser;
    }

    /**
     * 
     *
     * @param array 
     */
    public static void reverse(final byte[] array) {
        if (array == null) {
            return;
        }
        reverse(array, 0, array.length);
    }

    /**
     * 
     *
     * @param array 
     * @param startIndexInclusive 
     * @param endIndexExclusive 
     */
    public static void reverse(final byte[] array, final int startIndexInclusive, final int endIndexExclusive) {
        if (array == null) {
            return;
        }
        int i = Math.max(startIndexInclusive, 0);
        int j = Math.min(array.length, endIndexExclusive) - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }

    /**
     * 
     *
     * @param array 
     * @return 
     */
    public static byte[] clone(final byte[] array) {
        if (array == null) {
            return null;
        }
        return array.clone();
    }
}
