/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;


/**
 * @author paymennt
 * 
 */
public class ByteUtils {
    
    /**  */
    public static final int UINT_32_LENGTH = 4;
    
    /**  */
    public static final int UINT_64_LENGTH = 8;

    /**
     * 
     *
     * @param buf 
     * @param offset 
     * @param length 
     * @return 
     */
    public static byte[] readBytes(byte[] buf, int offset, int length) {
        byte[] b = new byte[length];
        System.arraycopy(buf, offset, b, 0, length);
        return b;
    }

    /**
     * 
     *
     * @param buf 
     * @param offset 
     * @return 
     */
    public static BigInteger readUint64(byte[] buf, int offset) {
        return new BigInteger(reverseBytes(readBytes(buf, offset, UINT_64_LENGTH)));
    }

    /**
     * 
     *
     * @param b 
     * @param numBytes 
     * @return 
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        assert b.signum() >= 0;
        assert numBytes > 0;
        byte[] src = b.toByteArray();
        byte[] dest = new byte[numBytes];
        boolean isFirstByteOnlyForSign = src[0] == 0;
        int length = isFirstByteOnlyForSign ? src.length - 1 : src.length;
        assert length <= numBytes;
        int srcPos = isFirstByteOnlyForSign ? 1 : 0;
        int destPos = numBytes - length;
        System.arraycopy(src, srcPos, dest, destPos, length);
        return dest;
    }

    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static BigInteger bytesToBigInteger(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    /**
     * 
     *
     * @param val 
     * @param out 
     * @param offset 
     */
    public static void uint16ToByteArrayLE(int val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
    }

    /**
     * 
     *
     * @param val 
     * @param out 
     * @param offset 
     */
    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
    }

    /**
     * 
     *
     * @param val 
     * @param out 
     * @param offset 
     */
    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >> 8));
        out[offset + 3] = (byte) (0xFF & val);
    }

    /**
     * 
     *
     * @param val 
     * @param out 
     * @param offset 
     */
    public static void int64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
        out[offset + 4] = (byte) (0xFF & (val >> 32));
        out[offset + 5] = (byte) (0xFF & (val >> 40));
        out[offset + 6] = (byte) (0xFF & (val >> 48));
        out[offset + 7] = (byte) (0xFF & (val >> 56));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void uint16ToByteStreamLE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void uint16ToByteStreamBE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void uint32ToByteStreamBE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void int64ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 32)));
        stream.write((int) (0xFF & (val >> 40)));
        stream.write((int) (0xFF & (val >> 48)));
        stream.write((int) (0xFF & (val >> 56)));
    }

    /**
     * 
     *
     * @param val 
     * @param stream 
     * @throws IOException 
     */
    public static void uint64ToByteStreamLE(BigInteger val, OutputStream stream) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) {
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                stream.write(0);
        }
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @return 
     */
    public static int readUint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @return 
     */
    public static long readUint32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) | ((bytes[offset + 1] & 0xffl) << 8) | ((bytes[offset + 2] & 0xffl) << 16)
                | ((bytes[offset + 3] & 0xffl) << 24);
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @return 
     */
    public static long readInt64(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) | ((bytes[offset + 1] & 0xffl) << 8) | ((bytes[offset + 2] & 0xffl) << 16)
                | ((bytes[offset + 3] & 0xffl) << 24) | ((bytes[offset + 4] & 0xffl) << 32)
                | ((bytes[offset + 5] & 0xffl) << 40) | ((bytes[offset + 6] & 0xffl) << 48)
                | ((bytes[offset + 7] & 0xffl) << 56);
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @return 
     */
    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xffl) << 24) | ((bytes[offset + 1] & 0xffl) << 16)
                | ((bytes[offset + 2] & 0xffl) << 8) | (bytes[offset + 3] & 0xffl);
    }

    /**
     * 
     *
     * @param bytes 
     * @param offset 
     * @return 
     */
    public static int readUint16BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    /**
     * 
     *
     * @param is 
     * @return 
     */
    public static int readUint16FromStream(InputStream is) {
        try {
            return (is.read() & 0xff) | ((is.read() & 0xff) << 8);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /**
     * 
     *
     * @param is 
     * @return 
     */
    public static long readUint32FromStream(InputStream is) {
        try {
            return (is.read() & 0xffl) | ((is.read() & 0xffl) << 8) | ((is.read() & 0xffl) << 16)
                    | ((is.read() & 0xffl) << 24);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /**
     * 
     *
     * @param bytes 
     * @return 
     */
    public static byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    /**
     * 
     *
     * @param input 
     * @return 
     */
    public static byte[] sha256hash160(byte[] input) {
        byte[] sha256 = Sha256.hash(input);
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }
}
