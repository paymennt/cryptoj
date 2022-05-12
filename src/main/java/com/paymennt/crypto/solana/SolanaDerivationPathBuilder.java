/************************************************************************
 * Copyright PointCheckout, Ltd.
 */

package com.paymennt.crypto.solana;

import com.paymennt.crypto.core.Coin;
import com.paymennt.crypto.core.derivation.DerivationPath;
import com.paymennt.crypto.core.derivation.DerivationPath.Chain;
import com.paymennt.crypto.core.derivation.DerivationPath.Purpose;

/**
 * @author asendar
 */
public class SolanaDerivationPathBuilder {

	/** purpose. */
	private Purpose purpose = Purpose.BIP44;

	/** test. */
	private boolean test = false;

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
	public SolanaDerivationPathBuilder withPurpose(Purpose purpose) {
		this.purpose = purpose;
		return this;
	}

	/**
	 * @param account
	 * @return derivation path builder
	 */
	public SolanaDerivationPathBuilder withAccount(int account) {
		this.account = account;
		return this;
	}

	/**
	 * @param chain
	 * @return derivation path builder
	 */
	public SolanaDerivationPathBuilder withChain(Chain chain) {
		this.chain = chain;
		return this;
	}

	/**
	 * @return derivation path builder
	 */
	public SolanaDerivationPathBuilder isTest() {
		this.test = true;
		return this;
	}

	/**
	 * @return derivation path
	 */
	public DerivationPath build() {
		assert this.purpose != null : "purpose cannot be null";
		assert this.account != null : "account cannot be null";
		assert this.chain != null : "chain cannot be null";

		Coin coin = Coin.SOL;

		if (test)
			coin = Coin.TSOL;

		return new DerivationPath(this.purpose, coin, this.account, this.chain);
	}

}
