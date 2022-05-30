/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto;

import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.key.Curve;

/**
 * 
 */
public enum CoinType {
    
    /**  */
    BITCOIN(Curve.BITCOIN, 0, 1, false),
    
    /**  */
    SOLANA(Curve.ED25519, 501, 501, true),
    
    /**  */
    SEMUX(Curve.ED25519, 7562605, 7562605, true);

    /**  */
    private final Curve curve;
    
    /**  */
    private final long coinType;
    
    /**  */
    private final long testCoinType;
    
    /**  */
    private boolean alwaysHardened;

    /**
     * 
     *
     * @param curve 
     * @param coinType 
     * @param testCoinType 
     * @param alwaysHardened 
     */
    CoinType(Curve curve, long coinType, long testCoinType, boolean alwaysHardened) {

        this.curve = curve;
        this.coinType = coinType;
        this.testCoinType = testCoinType;
        this.alwaysHardened = alwaysHardened;
    }

    /**
     * 
     *
     * @return 
     */
    public Curve getCurve() {
        return curve;
    }

    /**
     * 
     *
     * @param network 
     * @return 
     */
    public long getCoinType(Network network) {
        return network == Network.MAINNET ? coinType : testCoinType;
    }

    /**
     * 
     *
     * @return 
     */
    public boolean getAlwaysHardened() {
        return alwaysHardened;
    }
}
