/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.paymennt.crypto.bip32.wallet;

import com.paymennt.crypto.CoinType;
import com.paymennt.crypto.bip32.Network;

/**
 * Utility class for bip 39 paths
 */
public class Bip39 {
    private HdKeyGenerator hdKeyGenerator = new HdKeyGenerator();

    /**
     * Get a root account address for a given seed
     */
    public HdAddress getRootAddressFromSeed(
            byte[] seed,
            Network network,
            CoinType coinType,
            Purpose purpose,
            long account,
            Chain chain) {
        HdAddress masterAddress = hdKeyGenerator.getAddressFromSeed(seed, network, coinType);
        HdAddress purposeAddress = hdKeyGenerator.getAddress(masterAddress, purpose.bip, true);
        HdAddress coinTypeAddress = hdKeyGenerator.getAddress(purposeAddress, coinType.getCoinType(), true);
        HdAddress accountAddress = hdKeyGenerator.getAddress(coinTypeAddress, account, true);
        HdAddress changeAddress =
                hdKeyGenerator.getAddress(accountAddress, chain.getChainCode(), coinType.getAlwaysHardened());

        return changeAddress;
    }

    public HdAddress getAddress(HdAddress address, int index) {
        return hdKeyGenerator.getAddress(address, index, address.getCoinType().getAlwaysHardened());
    }

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
