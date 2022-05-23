/**
 * 
 */
package com.paymennt.crypto.bip32.wallet;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.paymennt.crypto.CoinType;
import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.key.HdPrivateKey;
import com.paymennt.crypto.bip32.wallet.key.HdPublicKey;
import com.paymennt.crypto.bip39.Language;
import com.paymennt.crypto.bip39.MnemonicGenerator;

/**
 * @author asendar
 *
 */
public abstract class AbstractWallet {

    private HdAddress rootAddress;

    protected AbstractWallet(String words, String passphrase, Purpose purpose, Network network, CoinType coinType) {

        Security.addProvider(new BouncyCastleProvider());

        byte[] seed = MnemonicGenerator.getSeedFromWordlist(words, passphrase, Language.ENGLISH);

        HdAddress masterAddress = HdKeyGenerator.getAddressFromSeed(seed, network, coinType);
        HdAddress purposeAddress = HdKeyGenerator.getAddress(masterAddress, purpose.bip, true);
        this.rootAddress = HdKeyGenerator.getAddress(purposeAddress, coinType.getCoinType(network), true);

    }

    protected HdAddress getHdAddress(int account, Chain chain, Integer index) {
        HdAddress accountAddress = HdKeyGenerator.getAddress(this.rootAddress, account, true);
        HdAddress chainAddress = HdKeyGenerator.getAddress(accountAddress, chain.getChainCode(),
                this.rootAddress.getCoinType().getAlwaysHardened());

        if (index == null)
            return chainAddress;

        return HdKeyGenerator.getAddress(chainAddress, index, this.rootAddress.getCoinType().getAlwaysHardened());
    }

    public HdPrivateKey getPrivateKey(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPrivateKey();
    }

    public HdPublicKey getPublicKey(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPublicKey();
    }

    public String getPath(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPath();
    }

    /**
     * This should return coin specific address
     */
    public abstract String getAddress(int account, Chain chain, Integer index);

    /*******************************************************************************************************************
     * enums
     */
    public enum Purpose {

        /** BIP 44 */
        BIP44(44),

        /** BIP 49 */
        BIP49(49),

        /** BIP 84 */
        BIP84(84);

        /** BIP */
        private final int bip;

        /**
         * @param bip
         */
        Purpose(int bip) {
            this.bip = bip;
        }

        public int getBip() {
            return this.bip;
        }

        /**
         * @param bip
         * @return purpose
         */
        public static Purpose getPurposeForBip(int bip) {
            for (Purpose purpose : Purpose.values())
                if (purpose.bip == bip)
                    return purpose;
            return null;
        }
    }

    public enum Chain {

        /** external. */
        EXTERNAL(0),

        /** change. */
        CHANGE(1);

        /** chain code. */
        private final int chainCode;

        /**
         * @param chainCode
         */
        Chain(int chainCode) {
            this.chainCode = chainCode;
        }

        public int getChainCode() {
            return this.chainCode;
        }

        /**
         * @param chainCode
         * @return chain
         */
        protected static Chain getChainForChainCode(int chainCode) {
            for (Chain chain : Chain.values())
                if (chain.chainCode == chainCode)
                    return chain;
            return null;
        }
    }
}
