/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */

package com.paymennt.crypto.core;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

/**
 * @author bashar
 *
 */
public enum Coin {
    // BITCOIN
    BTC(0, 100_000_000L, "BTC", false, 1, 6),
    TBTC(1, 100_000_000L, "BTC", true, 1, 2),

    // SOLANA
    SOL(501, 1_000_000_000L, "SOL", false, 15, 31),
    TSOL(1, 1_000_000_000L, "SOL", true, 15, 31);

    private final int derivationPathCoinType;
    private final long fractionalUnitScale;
    private final String code;
    private final boolean testCoin;

    private final int moderateConfirmation;
    private final int highConfirmation;

    private Coin(int derivationPathCoinType, long fractionalUnitScale, String code, boolean testCoin,
            int moderateConfirmation, int highConfirmation) {
        this.derivationPathCoinType = derivationPathCoinType;
        this.fractionalUnitScale = fractionalUnitScale;
        this.code = code;
        this.testCoin = testCoin;
        this.moderateConfirmation = moderateConfirmation;
        this.highConfirmation = highConfirmation;

    }

    public int getDerivationPathCoinType() {
        return this.derivationPathCoinType;
    }

    public boolean isTestCoin() {
        return this.testCoin;
    }

    public String getCode() {
        return this.code;
    }

    public static Coin getCoinForDerivationPathCoinType(int derivationPathCoinType) {
        for (Coin coin : Coin.values())
            if (coin.derivationPathCoinType == derivationPathCoinType)
                return coin;
        return null;
    }

    public ConfirmationConfidence getConfidence(int confirmations) {
        if (confirmations >= highConfirmation)
            return ConfirmationConfidence.HIGH;
        if (confirmations >= moderateConfirmation)
            return ConfirmationConfidence.MODERATE;
        return ConfirmationConfidence.LOW;
    }

    public BigInteger coinToFractions(BigDecimal value) {
        return value.multiply(BigDecimal.valueOf(this.fractionalUnitScale)).toBigInteger();
    }

    public BigDecimal fractionsToCoin(BigInteger value) {
        return new BigDecimal(value).divide(BigDecimal.valueOf(fractionalUnitScale), MathContext.DECIMAL32);
    }

}
