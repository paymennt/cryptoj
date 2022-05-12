/************************************************************************
 * Copyright PointCheckout, Ltd.
 */

package com.paymennt.crypto.core;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

/**
 * @author bashar
 */
public enum Coin {

    /** Bitcoin */
    BTC(0, 100_000_000L, "BTC", false),

    /** test Bitcoin */
    TBTC(1, 100_000_000L, "BTC", true),

    /** Solana. */
    // SOLANA
    SOL(501, 1_000_000_000L, "SOL", false),

    /** test Solana */
    TSOL(501, 1_000_000_000L, "SOL", true);

    /** HD wallet derivation path */
    private final int derivationPath;

    /** fraction per coin
     *  Bitcoin -> Satoshi
     *  Solana -> Lamport 
     */
    private final long fractionalUnitScale;

    /** coin code */
    private final String code;

    /** is this a test coin */
    private final boolean testCoin;

    /**
     * 
     */
    private Coin(int derivationPath, long fractionalUnitScale, String code, boolean testCoin) {
        this.derivationPath = derivationPath;
        this.fractionalUnitScale = fractionalUnitScale;
        this.code = code;
        this.testCoin = testCoin;

    }

    /**
     * @return the derivation path
     */
    public int getDerivationPath() {
        return this.derivationPath;
    }

    /**
     * @return true, if is a test coin
     */
    public boolean isTestCoin() {
        return this.testCoin;
    }

    /**
     * @return the coin code
     */
    public String getCode() {
        return this.code;
    }

    /**
     * @param derivationPath the derivation path
     * @return the coin of the derivation path
     */
    public static Coin getCoinForDerivationPathCoinType(int derivationPath) {
        for (Coin coin : Coin.values())
            if (coin.derivationPath == derivationPath)
                return coin;
        return null;
    }

    /**
     * @param value the coin amount
     * @return fractions of the given value
     */
    public BigInteger coinToFractions(BigDecimal value) {
        return value.multiply(BigDecimal.valueOf(this.fractionalUnitScale)).toBigInteger();
    }

    /**
     * @param value the fractions amount
     * @return coin amount of the given value
     */
    public BigDecimal fractionsToCoin(BigInteger value) {
        return new BigDecimal(value).divide(BigDecimal.valueOf(fractionalUnitScale), MathContext.DECIMAL32);
    }

}
