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
 * The Class ByteUtils.
 */
public class ByteUtils {
    
    /** The Constant UINT_32_LENGTH. */
    public static final int UINT_32_LENGTH = 4;
    
    /** The Constant UINT_64_LENGTH. */
    public static final int UINT_64_LENGTH = 8;

    /**
     * Read bytes.
     *
     * @param buf the buf
     * @param offset the offset
     * @param length the length
     * @return the byte[]
     */
    public static byte[] readBytes(byte[] buf, int offset, int length) {
        byte[] b = new byte[length];
        System.arraycopy(buf, offset, b, 0, length);
        return b;
    }

    /**
     * Read uint 64.
     *
     * @param buf the buf
     * @param offset the offset
     * @return the big integer
     */
    public static BigInteger readUint64(byte[] buf, int offset) {
        return new BigInteger(reverseBytes(readBytes(buf, offset, UINT_64_LENGTH)));
    }

    /**
     * <p>
     * The regular {@link BigInteger#toByteArray()} includes the sign bit of the number and
     * might result in an extra byte addition. This method removes this extra byte.
     * </p>
     * <p>
     * Assuming only positive numbers, it's possible to discriminate if an extra byte
     * is added by checking if the first element of the array is 0 (0000_0000).
     * Due to the minimal representation provided by BigInteger, it means that the bit sign
     * is the least significant bit 0000_000<b>0</b> .
     * Otherwise the representation is not minimal.
     * For example, if the sign bit is 0000_00<b>0</b>0, then the representation is not minimal due to the rightmost zero.
     * </p>
     * This is the antagonist to {@link #bytesToBigInteger(byte[])}.
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
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
     * Converts an array of bytes into a positive BigInteger. This is the antagonist to
     * {@link #bigIntegerToBytes(BigInteger, int)}.
     *
     * @param bytes to convert into a BigInteger
     * @return the converted BigInteger
     */
    public static BigInteger bytesToBigInteger(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    /**
     *  Write 2 bytes to the byte array (starting at the offset) as unsigned 16-bit integer in little endian format.
     *
     * @param val the val
     * @param out the out
     * @param offset the offset
     */
    public static void uint16ToByteArrayLE(int val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
    }

    /**
     *  Write 4 bytes to the byte array (starting at the offset) as unsigned 32-bit integer in little endian format.
     *
     * @param val the val
     * @param out the out
     * @param offset the offset
     */
    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & val);
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
    }

    /**
     *  Write 4 bytes to the byte array (starting at the offset) as unsigned 32-bit integer in big endian format.
     *
     * @param val the val
     * @param out the out
     * @param offset the offset
     */
    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >> 8));
        out[offset + 3] = (byte) (0xFF & val);
    }

    /**
     *  Write 8 bytes to the byte array (starting at the offset) as signed 64-bit integer in little endian format.
     *
     * @param val the val
     * @param out the out
     * @param offset the offset
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
     *  Write 2 bytes to the output stream as unsigned 16-bit integer in little endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public static void uint16ToByteStreamLE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
    }

    /**
     *  Write 2 bytes to the output stream as unsigned 16-bit integer in big endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public static void uint16ToByteStreamBE(int val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /**
     *  Write 4 bytes to the output stream as unsigned 32-bit integer in little endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & val));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
    }

    /**
     *  Write 4 bytes to the output stream as unsigned 32-bit integer in big endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public static void uint32ToByteStreamBE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & val));
    }

    /**
     *  Write 8 bytes to the output stream as signed 64-bit integer in little endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
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
     *  Write 8 bytes to the output stream as unsigned 64-bit integer in little endian format.
     *
     * @param val the val
     * @param stream the stream
     * @throws IOException Signals that an I/O exception has occurred.
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
     *  Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in little endian format.
     *
     * @param bytes the bytes
     * @param offset the offset
     * @return the int
     */
    public static int readUint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    /**
     *  Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format.
     *
     * @param bytes the bytes
     * @param offset the offset
     * @return the long
     */
    public static long readUint32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) | ((bytes[offset + 1] & 0xffl) << 8) | ((bytes[offset + 2] & 0xffl) << 16)
                | ((bytes[offset + 3] & 0xffl) << 24);
    }

    /**
     *  Parse 8 bytes from the byte array (starting at the offset) as signed 64-bit integer in little endian format.
     *
     * @param bytes the bytes
     * @param offset the offset
     * @return the long
     */
    public static long readInt64(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffl) | ((bytes[offset + 1] & 0xffl) << 8) | ((bytes[offset + 2] & 0xffl) << 16)
                | ((bytes[offset + 3] & 0xffl) << 24) | ((bytes[offset + 4] & 0xffl) << 32)
                | ((bytes[offset + 5] & 0xffl) << 40) | ((bytes[offset + 6] & 0xffl) << 48)
                | ((bytes[offset + 7] & 0xffl) << 56);
    }

    /**
     *  Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in big endian format.
     *
     * @param bytes the bytes
     * @param offset the offset
     * @return the long
     */
    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xffl) << 24) | ((bytes[offset + 1] & 0xffl) << 16)
                | ((bytes[offset + 2] & 0xffl) << 8) | (bytes[offset + 3] & 0xffl);
    }

    /**
     *  Parse 2 bytes from the byte array (starting at the offset) as unsigned 16-bit integer in big endian format.
     *
     * @param bytes the bytes
     * @param offset the offset
     * @return the int
     */
    public static int readUint16BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    /**
     *  Parse 2 bytes from the stream as unsigned 16-bit integer in little endian format.
     *
     * @param is the is
     * @return the int
     */
    public static int readUint16FromStream(InputStream is) {
        try {
            return (is.read() & 0xff) | ((is.read() & 0xff) << 8);
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    /**
     *  Parse 4 bytes from the stream as unsigned 32-bit integer in little endian format.
     *
     * @param is the is
     * @return the long
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
     * Returns a copy of the given byte array in reverse order.
     *
     * @param bytes the bytes
     * @return the byte[]
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
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     *
     * @param input the input
     * @return the byte[]
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
