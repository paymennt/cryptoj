package com.paymennt.crypto.bip39;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Generate and Process Mnemonic codes
 */
public class MnemonicGenerator {

    public static final String SPACE_JP = "\u3000";

    public static byte[] getSeedFromWordlist(String words, String password) {

        if (password == null) {
            password = "";
        }

        // validate that things look alright
        String[] wordsList = words.split(" ");
        if (wordsList.length < 12) {
            throw new IllegalArgumentException("Must be at least 12 words");
        }
        if (wordsList.length > 24) {
            throw new IllegalArgumentException("Must be less than 24 words");
        }

        // check all the words are found
        for (String word : wordsList) {
            if (WordList.ENGLISH.getWordIndex(word.trim().toCharArray()) < 0) {
                throw new IllegalArgumentException("Unknown word: " + word);

            }
        }

        // check the checksum

        String salt = "mnemonic" + password;
        return pbkdf2HmacSha512(words.trim().toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 2048, 512);
    }

    private static byte[] pbkdf2HmacSha512(
            final char[] password,
            final byte[] salt,
            final int iterations,
            final int keyLength) {

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();
            return res;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

}
