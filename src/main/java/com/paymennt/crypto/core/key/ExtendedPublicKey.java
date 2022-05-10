/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.core.key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import com.paymennt.crypto.lib.Base58;

/**
 */
public class ExtendedPublicKey {

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

    /*******************************************************************************************************************
     * STATIC METHODS.
     */

    /**
     * @param key
     * @param depth
     * @param fingerprint
     * @param childNumber
     * @param prefix
     * @return
     */
    public static ExtendedPublicKey fromPrivateKey(
            byte[] key,
            long depth,
            String fingerprint,
            BigInteger childNumber,
            String prefix) {
        int keyBytesLength = 32 - (64 - key.length);
        byte[] keyBytes = ByteUtils.subArray(key, 0, keyBytesLength);
        byte[] chainCode = ByteUtils.subArray(key, keyBytesLength, key.length);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, keyBytes));
        byteArrayOutputStream.writeBytes(privateKey.getPublicKey().getCompressedPublicKey());
        byteArrayOutputStream.writeBytes(chainCode);

        return new ExtendedPublicKey(byteArrayOutputStream.toByteArray(), prefix,
                Hex.toHexString(BigIntegers.asUnsignedByteArray(1, BigInteger.valueOf(depth))), fingerprint,
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
    private ExtendedPublicKey(byte[] key, String prefix, String depth, String fingerprint, String childNumber) {
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
     * @return
     */
    public PublicKey toPublicKey() {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 33);
        return PublicKey.fromCompressedPublicKey(keyBytes);
    }

    /**
     * Serialize.
     *
     * @return string
     */
    public String serialize() {
        byte[] keyBytes = ByteUtils.subArray(key, 0, 33);
        byte[] chainCode = ByteUtils.subArray(key, 33, key.length);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decode(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(depth));
        byteArrayOutputStream.writeBytes(Hex.decode(fingerprint));
        byteArrayOutputStream.writeBytes(Hex.decode(childNumber));
        byteArrayOutputStream.writeBytes(chainCode);
        byteArrayOutputStream.writeBytes(keyBytes);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    /**
     * Unserialize.
     *
     * @param serialized
     * @return extended public key
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public static ExtendedPublicKey unserialize(String serialized) throws IOException {
        byte[] bytes = Base58.decodeExtendedKey(serialized);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        byte[] prefixBytes = byteArrayInputStream.readNBytes(4);
        byte[] depthBytes = byteArrayInputStream.readNBytes(1);
        byte[] fingerprintBytes = byteArrayInputStream.readNBytes(4);
        byte[] childNumberBytes = byteArrayInputStream.readNBytes(4);
        byte[] chainCodeBytes = byteArrayInputStream.readNBytes(32);
        byte[] keyBytes = byteArrayInputStream.readNBytes(33);
        byte[] combinedKey = ByteUtils.concatenate(keyBytes, chainCodeBytes);
        return new ExtendedPublicKey(combinedKey, Hex.toHexString(prefixBytes), Hex.toHexString(depthBytes),
                Hex.toHexString(fingerprintBytes), Hex.toHexString(childNumberBytes));
    }

}
