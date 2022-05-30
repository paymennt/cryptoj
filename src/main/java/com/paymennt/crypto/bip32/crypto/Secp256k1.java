/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto.bip32.crypto;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * @author paymennt
 * 
 */
public class Secp256k1 {
    
    /**  */
    public static final X9ECParameters SECP = CustomNamedCurves.getByName("secp256k1");

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static byte[] serP(ECPoint p) {
        return p.getEncoded(true);
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static ECPoint deserP(byte[] p) {
        return SECP.getCurve().decodePoint(p);
    }

    /**
     * 
     *
     * @param p 
     * @return 
     */
    public static ECPoint point(BigInteger p) {
        return SECP.getG().multiply(p);
    }

    /**
     * 
     *
     * @return 
     */
    public static BigInteger getN() {
        return SECP.getN();
    }
}
