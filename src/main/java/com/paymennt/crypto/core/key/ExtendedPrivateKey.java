/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.core.key;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.util.Arrays;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import com.paymennt.crypto.core.derivation.DerivationPath;
import com.paymennt.crypto.lib.Base58;
import com.paymennt.crypto.lib.HMacSha512;
import com.paymennt.crypto.lib.Hash160;
import com.paymennt.crypto.lib.SecP256K1;

/**
 */
public class ExtendedPrivateKey {

	/** key. */
	private final byte[] key;

	/** prefix. */
	private final String prefix;

	/** fingerprint. */
	private final String fingerprint;

	/** depth. */
	private final String depth;

	/** child number. */
	private final String childNumber;

	/**
	 * *****************************************************************************************************************
	 * STATIC METHODS.
	 *
	 * @param key
	 * @param depth
	 * @param fingerprint
	 * @param childNumber
	 * @param prefix
	 * @return extended private key
	 */

	public static ExtendedPrivateKey from(byte[] key, long depth, String fingerprint, BigInteger childNumber,
			String prefix) {
		int keyBytesLength = 32 - (64 - key.length);
		byte[] keyBytes = Arrays.copyOfRange(key, 0, keyBytesLength);
		byte[] chainCode = Arrays.copyOfRange(key, keyBytesLength, key.length);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		int keyLength = keyBytes.length;
		while (keyLength < 32) {
			byteArrayOutputStream.write(0);
			keyLength++;
		}
		byteArrayOutputStream.writeBytes(keyBytes);
		byteArrayOutputStream.writeBytes(chainCode);

		return new ExtendedPrivateKey(byteArrayOutputStream.toByteArray(), prefix,
				Hex.toHexString(BigIntegers.asUnsignedByteArray(1, valueOf(depth))), fingerprint,
				Hex.toHexString(BigIntegers.asUnsignedByteArray(4, childNumber)));
	}

	/*******************************************************************************************************************
	 * CONSTRUCTOR.
	 */

	/**
	 * @param key
	 * @param prefix
	 * @param depth
	 * @param fingerprint
	 * @param childNumber
	 */
	private ExtendedPrivateKey(byte[] key, String prefix, String depth, String fingerprint, String childNumber) {
		this.key = key;
		this.prefix = prefix;
		this.depth = depth;
		this.fingerprint = fingerprint;
		this.childNumber = childNumber;
	}

	/*******************************************************************************************************************
	 * PUBLIC METHODS.
	 */

	/**
	 * @return private key
	 */
	public PrivateKey toPrivateKey() {
		byte[] keyBytes = Arrays.copyOfRange(this.key, 0, 32);
		return new PrivateKey(new BigInteger(1, keyBytes));
	}

	/**
	 * @return public key
	 */
	public PublicKey toPublicKey() {
		return this.toPrivateKey().getPublicKey();
	}

	/**
	 * @param addressIndex
	 * @return private key
	 */
	public PrivateKey toAddressPrivateKey(int addressIndex) {
		ExtendedPrivateKey addressEPK = this.childKeyDerivation(new BigInteger(Integer.toString(addressIndex)), false);
		byte[] keyBytes = Arrays.copyOfRange(addressEPK.key, 0, 32);
		return new PrivateKey(new BigInteger(1, keyBytes));
	}

	/**
	 * @param addressIndex
	 * @return public key
	 */
	public PublicKey toAddressPublicKey(int addressIndex) {
		return this.toAddressPrivateKey(addressIndex).getPublicKey();
	}

	/**
	 * @param pubPrefix
	 * @return extended public key
	 */
	public ExtendedPublicKey toExtendedPublicKey(String pubPrefix) {
		return ExtendedPublicKey.fromPrivateKey(this.key,
				BigIntegers.fromUnsignedByteArray(Hex.decode(this.depth)).longValue(), this.fingerprint,
				BigIntegers.fromUnsignedByteArray(Hex.decode(this.childNumber)), pubPrefix);
	}

	/**
	 * @return the key
	 */
	public byte[] getKey() {
		return this.key;
	}

	/**
	 * @param derivationPath the derivation path
	 * @return extended private key
	 */
	public ExtendedPrivateKey getExtendedPrivateKey(DerivationPath derivationPath) {
		String strPath = derivationPath.getPath();
		String[] indexes = strPath.split("/");
		ExtendedPrivateKey extendedKey = this;
		for (int i = 0, indexesLength = indexes.length; i < indexesLength; i++) {
			String index = indexes[i];
			if ("m".equals(index))
				continue;
			boolean hardened = index.endsWith("'");
			extendedKey = extendedKey.childKeyDerivation(new BigInteger(index.replace("'", "")), hardened);
		}
		return extendedKey;
	}

	/**
	 * Serialize.
	 *
	 * @return string
	 */
	public String serialize() {
		byte[] keyBytes = Arrays.copyOfRange(key, 0, 32);
		byte[] chainCode = Arrays.copyOfRange(key, 32, key.length);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byteArrayOutputStream.writeBytes(Hex.decode(prefix));
		byteArrayOutputStream.writeBytes(Hex.decode(depth));
		byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
		byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
		byteArrayOutputStream.writeBytes(chainCode);
		byteArrayOutputStream.writeBytes(Hex.decode("00"));
		byteArrayOutputStream.writeBytes(keyBytes);
		return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
	}

	/**
	 * Unserialize.
	 *
	 * @param serialized
	 * @return extended private key
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static ExtendedPrivateKey unserialize(String serialized) throws IOException {
		byte[] bytes = Base58.decodeExtendedKey(serialized);
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		byte[] prefixBytes = byteArrayInputStream.readNBytes(4);
		byte[] depthBytes = byteArrayInputStream.readNBytes(1);
		byte[] fingerprintBytes = byteArrayInputStream.readNBytes(4);
		byte[] childNumberBytes = byteArrayInputStream.readNBytes(4);
		byte[] chainCodeBytes = byteArrayInputStream.readNBytes(32);
		byteArrayInputStream.skip(1);
		byte[] keyBytes = byteArrayInputStream.readNBytes(32);
		byte[] combinedKey = Arrays.concatenate(keyBytes, chainCodeBytes);
		return new ExtendedPrivateKey(combinedKey, Hex.toHexString(prefixBytes), Hex.toHexString(depthBytes),
				Hex.toHexString(fingerprintBytes), Hex.toHexString(childNumberBytes));
	}

	/**
	 *
	 * @param index
	 * @param isHardened
	 * @return extended private key
	 */
	public ExtendedPrivateKey childKeyDerivation(BigInteger index, boolean isHardened) {
		byte[] keyBytes = Arrays.copyOfRange(key, 0, 32);
		byte[] chainCode = Arrays.copyOfRange(key, 32, key.length);
		BigInteger actualIndex = index;
		ByteArrayOutputStream data = new ByteArrayOutputStream();
		byte[] rawKey;
		PublicKey publicKey = new PrivateKey(new BigInteger(1, keyBytes)).getPublicKey();
		if (isHardened) {
			actualIndex = actualIndex.add(new BigInteger("2147483648"));
			data.write(0);
			data.writeBytes(keyBytes);
		} else {
			data.writeBytes(publicKey.getCompressedPublicKey());
		}
		data.writeBytes(BigIntegers.asUnsignedByteArray(4, actualIndex));
		rawKey = HMacSha512.hash(chainCode, data.toByteArray());

		byte[] childRawKey = Arrays.copyOfRange(rawKey, 0, 32);
		byte[] childChainCode = Arrays.copyOfRange(rawKey, 32, rawKey.length);
		byte[] childKey = BigIntegers.asUnsignedByteArray(
				new BigInteger(1, childRawKey).add(new BigInteger(1, keyBytes)).mod(SecP256K1.order));
		String childFingerprint = Hash160.hashToHex(publicKey.getCompressedPublicKey()).substring(0, 8);
		long depth = new BigInteger(this.depth).add(ONE).longValueExact();
		return ExtendedPrivateKey.from(Arrays.concatenate(childKey, childChainCode), depth, childFingerprint,
				actualIndex, this.prefix);
	}

}
