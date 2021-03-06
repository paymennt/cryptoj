/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

import java.nio.charset.StandardCharsets;

/**
 * @author paymennt
 * 
 */
public class HMacSha512 {
    
    /**
     * 
     *
     * @param key 
     * @param data 
     * @return 
     */
    public static byte[] hash(String key, byte[] data) {
        return hash(key.getBytes(StandardCharsets.UTF_8), data);
    }

    /**
     * 
     *
     * @param key 
     * @param data 
     * @return 
     */
    public static byte[] hash(byte[] key, byte[] data) {
        HMac hMac = new HMac(DigestFactory.createSHA512());
        hMac.init(new KeyParameter(key));
        byte[] result = new byte[hMac.getMacSize()];
        hMac.update(data, 0, data.length);
        hMac.doFinal(result, 0);
        return result;
    }
}
