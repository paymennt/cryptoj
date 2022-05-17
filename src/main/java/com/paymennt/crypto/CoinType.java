/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.paymennt.crypto;

import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.key.Curve;

public enum CoinType {
    BITCOIN(Curve.BITCOIN, 0, 1, false),
    SOLANA(Curve.ED25519, 501, 501, true),
    SEMUX(Curve.ED25519, 7562605, 7562605, true);

    private final Curve curve;
    private final long coinType;
    private final long testCoinType;
    private boolean alwaysHardened;

    CoinType(Curve curve, long coinType, long testCoinType, boolean alwaysHardened) {

        this.curve = curve;
        this.coinType = coinType;
        this.testCoinType = testCoinType;
        this.alwaysHardened = alwaysHardened;
    }

    /**
     * Get the curve
     *
     * @return curve
     */
    public Curve getCurve() {
        return curve;
    }

    /**
     * get the coin type
     *
     * @return coin type
     */
    public long getCoinType(Network network) {
        return network == Network.MAINNET ? coinType : testCoinType;
    }

    /**
     * get whether the addresses must always be hardened
     *
     * @return always hardened
     */
    public boolean getAlwaysHardened() {
        return alwaysHardened;
    }
}
