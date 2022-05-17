package com.paymennt.crypto;

import static org.junit.Assert.assertEquals;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.AbstractWallet;
import com.paymennt.crypto.bip32.wallet.AbstractWallet.Chain;
import com.paymennt.crypto.bip32.wallet.AbstractWallet.Purpose;
import com.paymennt.crypto.lib.Bech32;
import com.paymennt.crypto.lib.Hash160;

/**
 * @author asendar
 *
 */
public class Bip39TestSuite {

    private static AbstractWallet wallet;

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());

        String words = "chase forward bone horn faith kitten steel bind mutual tide wreck novel priority card saddle";
        String passphrase = "kitten";

        wallet = new AbstractWallet(words, passphrase, Purpose.BIP84, Network.MAINNET, CoinType.BITCOIN) {

            @Override
            public String getAddress(int account, Chain chain, Integer index) {

                byte[] hash160 = Hash160.hash(getPublicKey(account, chain, index).getPublicKey());
                return Bech32.encode("bc", 0, hash160);
            }
        };
    }

    @Test
    public void testWalletAddress() {

        // derivation path: m/84'/0'/0'/0/5 
        // address: bc1qn944d0p7k2rfmw3qev6j9v0p93dplw4t2lc7lv
        assertEquals("bc1qn944d0p7k2rfmw3qev6j9v0p93dplw4t2lc7lv", wallet.getAddress(0, Chain.EXTERNAL, 5));
    }

    @Test
    public void testWalletPublicKey() {

        // derivation path: m/84'/0'/0'/0/11 
        // public: 027476ebfc5fadf2e44df5d53d04eef907a591a74c9d104836dd85ffd1cf8555e5
        assertEquals("027476ebfc5fadf2e44df5d53d04eef907a591a74c9d104836dd85ffd1cf8555e5",
                Hex.toHexString(wallet.getPublicKey(0, Chain.EXTERNAL, 11).getPublicKey()));
    }

}
