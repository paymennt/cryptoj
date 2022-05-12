/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.bitcoin;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

import com.paymennt.crypto.core.key.ExtendedPrivateKey;
import com.paymennt.crypto.core.key.ExtendedPublicKey;
import com.paymennt.crypto.core.mnemonic.MnemonicSeed;
import com.paymennt.crypto.core.mnemonic.WordList;
import com.paymennt.crypto.lib.HMacSha512;

/**
 * can be used for generating extended keys in a hierarchical deterministic
 * wallet.
 */
public class BitcoinMnemonicSeed extends MnemonicSeed {

	/**
	 * {@inheritDoc}
	 */
	public BitcoinMnemonicSeed(char[] mnemonicPhrase) {
		this(mnemonicPhrase, new char[0], WordList.ENGLISH);
	}

	/**
	 * {@inheritDoc}
	 */
	public BitcoinMnemonicSeed(char[] mnemonicPhrase, char[] passPhrase) {
		this(mnemonicPhrase, passPhrase, WordList.ENGLISH);
	}

	/**
	 * {@inheritDoc}
	 */
	public BitcoinMnemonicSeed(char[] mnemonicPhrase, char[] passPhrase, WordList wordlist) {
		super(mnemonicPhrase, passPhrase, wordlist);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedPrivateKey getMasterPrivateKey(String prefix) {

		return ExtendedPrivateKey.from(HMacSha512.hash("Bitcoin seed", toSeed()), //
				0, //
				"00000000", //
				BigInteger.ZERO, //
				prefix);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedPublicKey getMasterPublicKey(String prefix) {
		return ExtendedPublicKey.fromPrivateKey(
				//
				HMacSha512.hash("Bitcoin seed", toSeed()), //
				0, //
				"00000000", //
				BigInteger.ZERO, //
				prefix);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toSeed() {
		PKCS5S2ParametersGenerator pkcs5S2ParametersGenerator = new PKCS5S2ParametersGenerator(
				DigestFactory.createSHA512());
		pkcs5S2ParametersGenerator.init(
				//
				PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(this.mnemonicPhrase),
				PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(
						//
						ArrayUtils.addAll("mnemonic".toCharArray(), this.passPhrase)), //
				2048);
		return ((KeyParameter) pkcs5S2ParametersGenerator.generateDerivedParameters(512)).getKey();
	}

}
