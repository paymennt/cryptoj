/************************************************************************
 * Copyright PointCheckout, Ltd.
 */
package com.paymennt.crypto.lib;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.valueOf;
import static java.util.Objects.isNull;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

/**
 * The Class Bech32.
 */
public class Bech32 {
    
    /** The Constant BECH32_ALPHABET. */
    private static final String BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    /** The Constant BECH32. */
    public static final int BECH32 = 1;
    
    /** The Constant BECH32M. */
    public static final int BECH32M = 2;
    
    /** The Constant BECH32M_CONST. */
    private static final int BECH32M_CONST = 0x2bc830a3;
    
    /**
     * Creates the checksum.
     *
     * @param hrp the hrp
     * @param data the data
     * @param spec the spec
     * @return the list
     */
    public static List<Integer> createChecksum(
        String hrp,
        List<Integer> data,
        int spec
    ) {
        List<Integer> values = new ArrayList<>(hrpExpand(hrp));
        values.addAll(data);
        values.addAll(List.of(0, 0, 0, 0, 0, 0));
        BigInteger constant = spec == BECH32M ? valueOf(BECH32M_CONST) : ONE;
        BigInteger polymod = polymod(values).xor(constant);
        List<Integer> checksum = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            checksum.add(
                (polymod.shiftRight(valueOf(5).multiply(valueOf(5).subtract(valueOf(i))).intValueExact()))
                    .and(valueOf(31)).intValueExact()
            );
        }
        return checksum;
    }
    
    /**
     * Hrp expand.
     *
     * @param hrp the hrp
     * @return the list
     */
    public static List<Integer> hrpExpand(String hrp) {
        List<Integer> list = new ArrayList<>();
        for (char c : hrp.toCharArray()) {
            list.add(c >> 5);
        }
        list.add(0);
        for (char c : hrp.toCharArray()) {
            list.add(c & 31);
        }
        return list;
    }
    
    /**
     * Polymod.
     *
     * @param values the values
     * @return the big integer
     */
    public static BigInteger polymod(List<Integer> values) {
        BigInteger[] generator = new BigInteger[] {
            new BigInteger(1, Hex.decode("3b6a57b2")),
            new BigInteger(1, Hex.decode("26508e6d")),
            new BigInteger(1, Hex.decode("1ea119fa")),
            new BigInteger(1, Hex.decode("3d4233dd")),
            new BigInteger(1, Hex.decode("2a1462b3"))
        };
        BigInteger checksum = ONE;
        for (Integer value : values) {
            BigInteger top = checksum.shiftRight(25);
            checksum = checksum.and(new BigInteger(1, Hex.decode("01ffffff"))).shiftLeft(5).xor(valueOf(value));
            for (int i = 0; i < 5; i++) {
                if (!top.shiftRight(i).and(ONE).equals(ZERO)) {
                    checksum = checksum.xor(generator[i]);
                } else {
                    checksum = checksum.xor(ZERO);
                }
            }
        }
        return checksum;
    }
    
    /**
     * Encode.
     *
     * @param hrp the hrp
     * @param witnessVersion the witness version
     * @param witnessProgram the witness program
     * @return the string
     */
    public static String encode(
        String hrp,
        int witnessVersion,
        byte[] witnessProgram
    ) {
        int spec = witnessVersion == 0 ? BECH32 : BECH32M;
        ArrayList<Integer> combinedProgram = new ArrayList<>();
        combinedProgram.add(witnessVersion);
        combinedProgram.addAll(BitsConverter.convertBits(witnessProgram, 8, 5, true));
        String result = bech32Encode(hrp, combinedProgram, spec);
        String[] decoded = decode(hrp, result);
        if (isNull(decoded[0]) || isNull(decoded[1])) {
            return null;
        }
        return result;
    }
    
    /**
     * Bech 32 encode.
     *
     * @param hrp the hrp
     * @param combinedProgram the combined program
     * @param spec the spec
     * @return the string
     */
    private static String bech32Encode(
        String hrp,
        ArrayList<Integer> combinedProgram,
        int spec
    ) {
        ArrayList<Integer> combined = new ArrayList<>(combinedProgram);
        combined.addAll(createChecksum(hrp, combinedProgram, spec));
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(hrp);
        stringBuilder.append("1");
        for (Integer i : combined) {
            stringBuilder.append(BECH32_ALPHABET.charAt(i));
        }
        return stringBuilder.toString();
    }
    
    /**
     * Decode.
     *
     * @param hrp the hrp
     * @param address the address
     * @return the string[]
     */
    @SuppressWarnings("unchecked")
    public static String[] decode(
        String hrp,
        String address
    ) {
        Object[] hrpAddress = bech32Decode(address);
        String hrpGot = (String) hrpAddress[0];
        List<Integer> data = (List<Integer>) hrpAddress[1];
        BigInteger spec = (BigInteger) hrpAddress[2];
        if (!hrpGot.equals(hrp)) {
            return new String[] {
                null, null
            };
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        data.subList(1, data.size()).forEach(byteArrayOutputStream::write);
        
        List<Integer> decoded = BitsConverter.convertBits(byteArrayOutputStream.toByteArray(), 5, 8, false);
        if (isNull(decoded) || decoded.size() < 2 || decoded.size() > 40) {
            return new String[] {
                null, null
            };
        }
        if (data.get(0) > 16) {
            return new String[] {
                null, null
            };
        }
        if (data.get(0) == 0 && decoded.size() != 20 && decoded.size() != 32) {
            return new String[] {
                null, null
            };
        }
        if ((data.get(0) == 0 && !spec.equals(valueOf(BECH32)))
            || (data.get(0) != 0 && !spec.equals(valueOf(BECH32M)))) {
            return new String[] {
                null, null
            };
        }
        ByteArrayOutputStream decodedBytes = new ByteArrayOutputStream();
        decoded.forEach(decodedBytes::write);
        return new String[] {
            String.valueOf(data.get(0)), Hex.toHexString(decodedBytes.toByteArray())
        };
    }
    
    /**
     * Bech 32 decode.
     *
     * @param address the address
     * @return the object[]
     */
    private static Object[] bech32Decode(String address) {
        int position = address.lastIndexOf("1");
        if (!isValidAddress(address, position)) {
            return new Object[] {
                null, null
            };
        }
        
        address = address.toLowerCase();
        String hrp = address.substring(0, position);
        List<Integer> data = new ArrayList<>();
        for (char c : address.substring(position + 1).toCharArray()) {
            data.add(BECH32_ALPHABET.indexOf(c));
        }
        BigInteger spec = verifyChecksum(hrp, data);
        if (isNull(spec)) {
            return new Object[] {
                null, null
            };
        }
        return new Object[] {
            hrp, data.subList(0, data.size() - 6), spec
        };
    }
    
    /**
     * Checks if is valid address.
     *
     * @param address the address
     * @param position the position
     * @return true, if is valid address
     */
    private static boolean isValidAddress(
        String address,
        int position
    ) {
        for (char c : address.toCharArray()) {
            if (c < 33 || c > 126) {
                return false;
            }
        }
        if (position < 1 || position + 7 > address.length() || address.length() > 90) {
            return false;
        }
        return !isMixedCase(address);
    }
    
    /**
     * Verify checksum.
     *
     * @param hrp the hrp
     * @param data the data
     * @return the big integer
     */
    private static BigInteger verifyChecksum(
        String hrp,
        List<Integer> data
    ) {
        ArrayList<Integer> combined = new ArrayList<>(hrpExpand(hrp));
        combined.addAll(data);
        BigInteger constant = polymod(combined);
        if (constant.equals(ONE)) {
            return valueOf(BECH32);
        }
        if (constant.equals(valueOf(BECH32M_CONST))) {
            return valueOf(BECH32M);
        }
        return null;
    }
    
    /**
     * Checks if is mixed case.
     *
     * @param address the address
     * @return true, if is mixed case
     */
    private static boolean isMixedCase(String address) {
        return !address.toLowerCase().equals(address) && !address.toUpperCase().equals(address);
    }
}
