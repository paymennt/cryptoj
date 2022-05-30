/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto.bip32.crypto;

import com.paymennt.crypto.bip32.exception.CryptoException;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author paymennt
 * 
 */
public class Hash {

    /**
     * 
     *
     * @param input 
     * @return 
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to find SHA-256", e);
        }
    }

    /**
     * 
     *
     * @param input 
     * @return 
     */
    public static byte[] sha512(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to find SHA-512", e);
        }
    }

    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static byte[] sha256Twice(byte[] bytes) {
        return sha256Twice(bytes, 0, bytes.length);
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @param length 
     * @return 
     */
    public static byte[] sha256Twice(final byte[] bytes, final int offset, final int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, offset, length);
            digest.update(digest.digest());
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to find SHA-256", e);
        }
    }

    /**
     * 
     *
     * @param input 
     * @return 
     */
    public static byte[] h160(byte[] input) {
        byte[] sha256 = sha256(input);

        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }
}
