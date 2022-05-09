package com.paymennt.crypto.core.mnemonic;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import com.paymennt.crypto.core.key.ExtendedPrivateKey;
import com.paymennt.crypto.core.key.ExtendedPublicKey;
import com.paymennt.crypto.core.lib.BitsConverter;
import com.paymennt.crypto.core.lib.HMacSha512;

public class MnemonicSeed {
    
    private final char[] mnemonicPhrase;
    private final char[] passPhrase;
    private final WordList wordlist;
    
    public MnemonicSeed(char[] mnemonicPhrase) {
        this(mnemonicPhrase, new char[0], WordList.ENGLISH);
    }
    
    public MnemonicSeed(char[] mnemonicPhrase, char[] passPhrase) {
        this(mnemonicPhrase, passPhrase, WordList.ENGLISH);
    }
    
    public MnemonicSeed(char[] mnemonicPhrase, char[] passPhrase, WordList wordlist) {
        this.mnemonicPhrase = mnemonicPhrase;
        this.passPhrase = passPhrase;
        this.wordlist = wordlist;
    }
    
    /**
     * @return count of words in mnemonic phrase
     */
    public int getPhraseWordCount() {
        int count = 1;
        for (char c : this.mnemonicPhrase) {
            if (c == ' ')
                count += 1;
        }
        return count;
    }
    
    /**
     * @param prefix
     * @return
     */
    public ExtendedPrivateKey getMasterPrivateKey(String prefix) {
        return ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", toSeed()), //
            0, //
            "00000000", //
            BigInteger.ZERO, //
            prefix
        );
    }
    
    /**
     * @param prefix
     * @return
     */
    public ExtendedPublicKey getMasterPublicKey(String prefix) {
        return ExtendedPublicKey.fromPrivateKey(
            //
            HMacSha512.hash("Bitcoin seed", toSeed()), //
            0, //
            "00000000", //
            BigInteger.ZERO, //
            prefix
        );
    }
    
    /**
     * @return
     */
    public String toSeedHex() {
        return Hex.toHexString(toSeed());
    }
    
    /**
     * @return
     */
    public byte[] toSeed() {
        PKCS5S2ParametersGenerator pkcs5S2ParametersGenerator =
            new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
        pkcs5S2ParametersGenerator.init(
            //
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(this.mnemonicPhrase),
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(
                //
                ArrayUtils.addAll("mnemonic".toCharArray(), this.passPhrase)
            ), //
            2048
        );
        return ((KeyParameter) pkcs5S2ParametersGenerator.generateDerivedParameters(512)).getKey();
    }
    
    /**
     * @return
     */
    public byte[] toEntropy() {
        List<Integer> indexes = new LinkedList<>();
        for (int i = 0, j = 0; i <= this.mnemonicPhrase.length; i++) {
            if (i == this.mnemonicPhrase.length || this.mnemonicPhrase[i] == ' ') {
                indexes.add(
                    this.wordlist.getWordIndex(
                        //
                        Arrays.copyOfRange(this.mnemonicPhrase, j, i) //
                    )
                );
                j = i + 1;
            }
        }
        indexes = BitsConverter.convertBits(indexes, 11, 8, true);
        
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        indexes.forEach(byteArrayOutputStream::write);
        byte[] combined = byteArrayOutputStream.toByteArray();
        
        return ByteUtils.subArray(combined, 0, combined.length - 1);
    }
    
    /**
     * @param mnemonicPhraseOther
     * @return
     */
    public boolean compareSeedPhrase(char[] mnemonicPhraseOther) {
        return Arrays.equals(this.mnemonicPhrase, mnemonicPhraseOther);
    }
    
}
