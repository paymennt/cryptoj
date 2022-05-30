/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Collectors;

import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.valueOf;
import static java.util.Arrays.copyOfRange;

/**
 * @author paymennt
 * 
 */
public class Base58 {
    
    /**  */
    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /**  */
    public static final char[] ALPHABET = BASE58_ALPHABET.toCharArray();
    
    /**  */
    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static String encode(byte[] key) {
        int zeroCount = 0;
        for (byte b : key) {
            if (b == 0) {
                zeroCount++;
            } else {
                break;
            }
        }
        BigInteger keyNumber = new BigInteger(1, key);
        String prefix = "1".repeat(zeroCount);
        String result = "";
        while (keyNumber.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divideAndRemainder = keyNumber.divideAndRemainder(valueOf(58));
            keyNumber = divideAndRemainder[0];
            int remainder = divideAndRemainder[1].intValueExact();
            result = BASE58_ALPHABET.substring(remainder, remainder + 1).concat(result);
        }
        return prefix.concat(result);
    }

    /**
     * 
     *
     * @param input 
     * @return 
     */
    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }
        // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            assert digit >= 0;
            input58[i] = (byte) digit;
        }
        // Count leading zeros.
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            ++zeros;
        }
        // Convert base-58 digits to base-256 digits.
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length;) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                ++inputStart; // optimization - skip leading zeros
            }
        }
        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            ++outputStart;
        }
        // Return decoded data (including original number of leading zeros).
        return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static String encodeWithChecksum(byte[] key) {
        byte[] checksum = Hash256.hash(key);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(key);
        byteArrayOutputStream.writeBytes(new byte[] { checksum[0], checksum[1], checksum[2], checksum[3] });
        return encode(byteArrayOutputStream.toByteArray());
    }

    /**
     * 
     *
     * @param wif 
     * @param compressed 
     * @return 
     */
    public static byte[] decodeWif(String wif, boolean compressed) {
        BigInteger number = ZERO;
        for (Character c : wif.toCharArray()) {
            number = number.multiply(valueOf(58));
            number = number.add(
                    valueOf(BASE58_ALPHABET.chars().mapToObj(ch -> (char) ch).collect(Collectors.toList()).indexOf(c)));
        }
        int length = 37;
        if (compressed) {
            length++;
        }
        byte[] combined = BigIntegers.asUnsignedByteArray(length, number);
        return copyOfRange(combined, 1, 33);
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static byte[] decodeWithChecksum(String key) {
        BigInteger number = ZERO;
        for (Character c : key.toCharArray()) {
            number = number.multiply(valueOf(58));
            number = number.add(
                    valueOf(BASE58_ALPHABET.chars().mapToObj(ch -> (char) ch).collect(Collectors.toList()).indexOf(c)));
        }
        byte[] combined = BigIntegers.asUnsignedByteArray(25, number);
        byte[] checksum = copyOfRange(combined, 21, 25);
        if (!isValidAddress(combined, checksum)) {
            throw new RuntimeException("Bad address");
        }
        return copyOfRange(combined, 1, 21);
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static byte[] decodeExtendedKey(String key) {
        BigInteger number = ZERO;
        for (Character c : key.toCharArray()) {
            number = number.multiply(valueOf(58));
            number = number.add(
                    valueOf(BASE58_ALPHABET.chars().mapToObj(ch -> (char) ch).collect(Collectors.toList()).indexOf(c)));
        }
        return BigIntegers.asUnsignedByteArray(number);
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static String decodeWithChecksumToHex(String key) {
        return Hex.toHexString(decodeWithChecksum(key));
    }

    /**
     * 
     *
     * @param combined 
     * @param checksum 
     * @return 
     */
    private static boolean isValidAddress(byte[] combined, byte[] checksum) {
        return Arrays.equals(copyOfRange(Hash256.hash(copyOfRange(combined, 0, 21)), 0, 4), checksum);
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static String encodeFromHex(String key) {
        return encode(Hex.decodeStrict(key));
    }

    /**
     * 
     *
     * @param key 
     * @return 
     */
    public static String encodeWithChecksumFromHex(String key) {
        return encodeWithChecksum(Hex.decodeStrict(key));
    }

    /**
     * 
     *
     * @param number 
     * @param firstDigit 
     * @param base 
     * @param divisor 
     * @return 
     */
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        // this is just long division which accounts for the base of the input digits
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
}
