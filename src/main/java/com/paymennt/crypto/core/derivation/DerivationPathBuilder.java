/************************************************************************
 * Copyright PointCheckout, Ltd.
 */

package com.paymennt.crypto.core.derivation;

import com.paymennt.crypto.core.Coin;
import com.paymennt.crypto.core.derivation.DerivationPath.Chain;
import com.paymennt.crypto.core.derivation.DerivationPath.Purpose;

/**
 * @author bashar
 */
public class DerivationPathBuilder {

    /** purpose. */
    private Purpose purpose;

    /** coin. */
    private Coin coin;

    /** account. */
    private Integer account;

    /** chain. */
    private Chain chain;

    /**
     * With purpose.
     *
     * @param purpose
     * @return derivation path builder
     */
    public DerivationPathBuilder withPurpose(Purpose purpose) {
        this.purpose = purpose;
        return this;
    }

    /**
     * @param coin 
     * @return derivation path builder
     */
    public DerivationPathBuilder withCoin(Coin coin) {
        this.coin = coin;
        return this;
    }

    /**
     * @param account
     * @return derivation path builder
     */
    public DerivationPathBuilder withAccount(int account) {
        this.account = account;
        return this;
    }

    /**
     * @param chain
     * @return derivation path builder
     */
    public DerivationPathBuilder withChain(Chain chain) {
        this.chain = chain;
        return this;
    }

    /**
     * @return derivation path
     */
    public DerivationPath build() {
        assert this.purpose != null : "purpose cannot be null";
        assert this.coin != null : "coin cannot be null";
        assert this.account != null : "account cannot be null";
        assert this.chain != null : "chain cannot be null";
        return new DerivationPath(this.purpose, this.coin, this.account, this.chain);
    }

}
