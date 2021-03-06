/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.paymennt.crypto.bip32.wallet.key;

import org.bouncycastle.util.encoders.Hex;

/**
 * Defines a key with a given public key
 */
public class HdPublicKey extends HdKey {
    private byte[] publicKey;

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public String getHex() {
        return Hex.toHexString(publicKey);
    }
}
