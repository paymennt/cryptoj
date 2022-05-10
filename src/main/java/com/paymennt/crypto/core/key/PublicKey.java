/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.core.key;

import static com.paymennt.crypto.lib.SecP256K1.pow;
import static com.paymennt.crypto.lib.SecP256K1.sqrt;
import static java.math.BigInteger.TWO;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.valueOf;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import com.paymennt.crypto.lib.Base58;
import com.paymennt.crypto.lib.Hash160;
import com.paymennt.crypto.lib.SecP256K1;

/**
 */
public class PublicKey {

    /** uncompressed public key */
    private final byte[] uncompressedPublicKey;

    /** compressed public key */
    private final byte[] compressedPublicKey;

    /** elliptic curve point */
    private final ECPoint point;

    /**
     * @param point elliptic curve point
     */
    public PublicKey(ECPoint point) {
        this.point = point;
        this.uncompressedPublicKey = uncompressedPublicKey(point);
        this.compressedPublicKey = compressedPublicKey(point);
    }

    /**
     * @param compressedPublicKey the compressed public key
     * @return the public key
     */
    public static PublicKey fromCompressedPublicKey(byte[] compressedPublicKey) {
        BigInteger x = new BigInteger(1, ByteUtils.subArray(compressedPublicKey, 1, 33));
        SecP256K1FieldElement xElement = new SecP256K1FieldElement(x);

        boolean isEven = compressedPublicKey[0] == 2;
        ECFieldElement alpha = pow(xElement, valueOf(3)).add(new SecP256K1FieldElement(valueOf(7)));
        ECFieldElement beta = sqrt(alpha);
        ECFieldElement evenBeta;
        ECFieldElement oddBeta;
        if (beta.toBigInteger().mod(TWO).equals(ZERO)) {
            evenBeta = beta;
            oddBeta = new SecP256K1FieldElement(SecP256K1FieldElement.Q.subtract(beta.toBigInteger()));
        } else {
            oddBeta = beta;
            evenBeta = new SecP256K1FieldElement(SecP256K1FieldElement.Q.subtract(beta.toBigInteger()));
        }
        if (isEven) {
            return new PublicKey(SecP256K1.curve.createPoint(x, evenBeta.toBigInteger()).normalize());
        }
        return new PublicKey(SecP256K1.curve.createPoint(x, oddBeta.toBigInteger()).normalize());
    }

    /** 
     * @param point elliptic curve point
     * @return uncompressed public key
     */
    private byte[] uncompressedPublicKey(ECPoint point) {
        return point.getEncoded(false);
    }

    /** 
     * @param point elliptic curve point
     * @return compressed public key
     */
    private byte[] compressedPublicKey(ECPoint point) {
        return point.getEncoded(true);
    }

    /** 
     * @return uncompressed public key hex
     */
    public String uncompressedPublicKeyHex() {
        return Hex.toHexString(uncompressedPublicKey);
    }

    /** 
     * @return compressed public key hex
     */
    public String compressedPublicKeyHex() {
        return Hex.toHexString(compressedPublicKey);
    }

    /**
     * @param prefix of the address
     * @return the address
     */
    public String addressFromUncompressedPublicKey(String prefix) {
        byte[] hash160 = Hash160.hash(uncompressedPublicKey);
        return concat(prefix, hash160);
    }

    /**
     * @param prefix of the address
     * @return the address
     */
    public String addressFromCompressedPublicKey(String prefix) {
        byte[] hash160 = Hash160.hash(compressedPublicKey);
        return concat(prefix, hash160);
    }

    /**
     * @param prefix
     * @param hash160
     * @return
     */
    private String concat(String prefix, byte[] hash160) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(hash160);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    /**
     * @return compressed public key
     */
    public byte[] getCompressedPublicKey() {
        return compressedPublicKey;
    }

    /**
     * @return uncompressed public key
     */
    public byte[] getUncompressedPublicKey() {
        return uncompressedPublicKey;
    }

    /**
     * @return elliptic curve point
     */
    public ECPoint getPoint() {
        return point;
    }

    /**
     * @return x
     */
    public BigInteger getX() {
        return point.getAffineXCoord().toBigInteger();
    }

    /**
     * @return x hex
     */
    public String getXHex() {
        return Hex.toHexString(BigIntegers.asUnsignedByteArray(getX()));
    }
}
