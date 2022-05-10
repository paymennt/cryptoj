/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.core.key;

import java.math.BigInteger;

import com.paymennt.crypto.lib.SecP256K1;

/**
 * 
 */
public class PrivateKey {

    /** secret. */
    private final BigInteger secret;

    /** public key. */
    private final PublicKey publicKey;

    /**
     * @param secret
     */
    public PrivateKey(BigInteger secret) {
        this.secret = secret;
        this.publicKey = new PublicKey(SecP256K1.G.multiply(secret).normalize());
    }

    /**
     * @return secret
     */
    public BigInteger getSecret() {
        return secret;
    }

    /**
     * @return public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

}
