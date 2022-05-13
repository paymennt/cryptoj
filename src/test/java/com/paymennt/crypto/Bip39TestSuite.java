package com.paymennt.crypto;

import static org.junit.Assert.assertEquals;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.Bip39;
import com.paymennt.crypto.bip32.wallet.Bip39.Chain;
import com.paymennt.crypto.bip32.wallet.Bip39.Purpose;
import com.paymennt.crypto.bip32.wallet.HdAddress;
import com.paymennt.crypto.bip39.Language;
import com.paymennt.crypto.bip39.MnemonicGenerator;
import com.paymennt.crypto.lib.Bech32;
import com.paymennt.crypto.lib.Hash160;

/**
 * @author asendar
 *
 */
public class Bip39TestSuite {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void generateBitcoinAddress() {

        String words = "chase forward bone horn faith kitten steel bind mutual tide wreck novel priority card saddle";
        String passphrase = "kitten";

        Bip39 addressGenerator = new Bip39();
        MnemonicGenerator mnemonicGen = new MnemonicGenerator();

        byte[] seed = mnemonicGen.getSeedFromWordlist(words, passphrase, Language.ENGLISH);

        HdAddress hdAddress = addressGenerator.getRootAddressFromSeed(//
                seed, //
                Network.MAINNET, //
                CoinType.BITCOIN, //
                Purpose.BIP84, //
                0, //
                Chain.EXTERNAL//
        );

        byte[] publicKey = addressGenerator.getAddress(hdAddress, 5).getPublicKey().getPublicKey();
        byte[] hash160 = Hash160.hash(publicKey);

        // derivation path: m/84'/0'/0'/0/5 
        // address: bc1qn944d0p7k2rfmw3qev6j9v0p93dplw4t2lc7lv
        // public: 03e34e239c8e6e3955bacda0c688ad00129c3e327f59f75170332e6b1d9dd15418
        // private: KzPFYWAGGYdD54sGyKCRXGYoitQKs3H3otP72Atiatj4pqDx63DM
        assertEquals("bc1qn944d0p7k2rfmw3qev6j9v0p93dplw4t2lc7lv", Bech32.encode("bc", 0, hash160));
        assertEquals("03e34e239c8e6e3955bacda0c688ad00129c3e327f59f75170332e6b1d9dd15418", Hex.toHexString(publicKey));
    }

}
