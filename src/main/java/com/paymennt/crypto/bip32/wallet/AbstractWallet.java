/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto.bip32.wallet;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.paymennt.crypto.CoinType;
import com.paymennt.crypto.bip32.Network;
import com.paymennt.crypto.bip32.wallet.key.HdPrivateKey;
import com.paymennt.crypto.bip32.wallet.key.HdPublicKey;
import com.paymennt.crypto.bip39.MnemonicGenerator;

/**
 * @author asendar
 *
 */
public abstract class AbstractWallet {

    /**  */
    private HdAddress rootAddress;

    /**
     * 
     *
     * @param words 
     * @param passphrase 
     * @param purpose 
     * @param network 
     * @param coinType 
     */
    protected AbstractWallet(String words, String passphrase, Purpose purpose, Network network, CoinType coinType) {

        Security.addProvider(new BouncyCastleProvider());

        byte[] seed = MnemonicGenerator.getSeedFromWordlist(words, passphrase);

        HdAddress masterAddress = HdKeyGenerator.getAddressFromSeed(seed, network, coinType);
        HdAddress purposeAddress = HdKeyGenerator.getAddress(masterAddress, purpose.bip, true);
        this.rootAddress = HdKeyGenerator.getAddress(purposeAddress, coinType.getCoinType(network), true);

    }

    /**
     * 
     *
     * @param account 
     * @param chain 
     * @param index 
     * @return 
     */
    protected HdAddress getHdAddress(int account, Chain chain, Integer index) {
        HdAddress accountAddress = HdKeyGenerator.getAddress(this.rootAddress, account, true);
        HdAddress chainAddress = HdKeyGenerator.getAddress(accountAddress, chain.getChainCode(),
                this.rootAddress.getCoinType().getAlwaysHardened());

        if (index == null)
            return chainAddress;

        return HdKeyGenerator.getAddress(chainAddress, index, this.rootAddress.getCoinType().getAlwaysHardened());
    }

    /**
     * 
     *
     * @param account 
     * @param chain 
     * @param index 
     * @return 
     */
    public HdPrivateKey getPrivateKey(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPrivateKey();
    }

    /**
     * 
     *
     * @param account 
     * @param chain 
     * @param index 
     * @return 
     */
    public HdPublicKey getPublicKey(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPublicKey();
    }

    /**
     * 
     *
     * @param account 
     * @param chain 
     * @param index 
     * @return 
     */
    public String getPath(int account, Chain chain, Integer index) {
        return getHdAddress(account, chain, index).getPath();
    }

    /**
     * 
     *
     * @param account 
     * @param chain 
     * @param index 
     * @return 
     */
    public abstract String getAddress(int account, Chain chain, Integer index);

    /**
     * 
     */
    public enum Purpose {

        /**  */
        BIP44(44),

        /**  */
        BIP49(49),

        /**  */
        BIP84(84);

        /**  */
        private final int bip;

        /**
         * 
         *
         * @param bip 
         */
        Purpose(int bip) {
            this.bip = bip;
        }

        /**
         * 
         *
         * @return 
         */
        public int getBip() {
            return this.bip;
        }

        /**
         * 
         *
         * @param bip 
         * @return 
         */
        public static Purpose getPurposeForBip(int bip) {
            for (Purpose purpose : Purpose.values())
                if (purpose.bip == bip)
                    return purpose;
            return null;
        }
    }

    /**
     * 
     */
    public enum Chain {

        /**  */
        EXTERNAL(0),

        /**  */
        CHANGE(1);

        /**  */
        private final int chainCode;

        /**
         * 
         *
         * @param chainCode 
         */
        Chain(int chainCode) {
            this.chainCode = chainCode;
        }

        /**
         * 
         *
         * @return 
         */
        public int getChainCode() {
            return this.chainCode;
        }

        /**
         * 
         *
         * @param chainCode 
         * @return 
         */
        protected static Chain getChainForChainCode(int chainCode) {
            for (Chain chain : Chain.values())
                if (chain.chainCode == chainCode)
                    return chain;
            return null;
        }
    }
}
