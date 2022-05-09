/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */

package com.paymennt.crypto.core.derivation;

import com.paymennt.crypto.core.Coin;
import com.paymennt.crypto.core.derivation.DerivationPath.Chain;
import com.paymennt.crypto.core.derivation.DerivationPath.Purpose;

/**
 * @author bashar
 *
 */
public class DerivationPathBuilder {
    
    private Purpose purpose;
    private Coin coin;
    private Integer account;
    private Chain chain;
    
    public DerivationPathBuilder withPurpose(Purpose purpose) {
        this.purpose = purpose;
        return this;
    }
    
    public DerivationPathBuilder withCoin(Coin coin) {
        this.coin = coin;
        return this;
    }
    
    public DerivationPathBuilder withAccount(int account) {
        this.account = account;
        return this;
    }
    
    public DerivationPathBuilder withChain(Chain chain) {
        this.chain = chain;
        return this;
    }
    
    public DerivationPath build() {
        assert this.purpose != null : "purpose cannot be null";
        assert this.coin != null : "coin cannot be null";
        assert this.account != null : "account cannot be null";
        assert this.chain != null : "chain cannot be null";
        return new DerivationPath(this.purpose, this.coin, this.account, this.chain);
    }
    
}
