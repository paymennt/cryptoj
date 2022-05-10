/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

/**
 * The Class Hash256.
 */
public class Hash256 {
    
    /**
     * Hash.
     *
     * @param key the key
     * @return the byte[]
     */
    public static byte[] hash(byte[] key) {
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchElementException("Algorithm SHA-256 not found. You may need to add BouncyCastleProvider as a security provider in your project.");
        }
        return sha256.digest(sha256.digest(key));
    }

    /**
     * Hash to hex.
     *
     * @param key the key
     * @return the string
     */
    public static String hashToHex(String key) {
        return Hex.toHexString(hash(Hex.decodeStrict(key)));
    }
}