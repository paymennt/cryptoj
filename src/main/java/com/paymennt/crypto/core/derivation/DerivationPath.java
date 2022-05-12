/************************************************************************
 * Copyright PointCheckout, Ltd.
 */

package com.paymennt.crypto.core.derivation;

import org.apache.commons.lang3.StringUtils;

import com.paymennt.crypto.core.Coin;

/**
 * @author bashar
 */
public class DerivationPath {

    /** purpose. */
    private final Purpose purpose;

    /** coin. */
    private final Coin coin;

    /** account. */
    private final int account;

    /** chain. */
    private final Chain chain;

    /**
     *
     * @param purpose
     * @param coin
     * @param account
     * @param chain
     */
    public DerivationPath(Purpose purpose, Coin coin, int account, Chain chain) {
        this.purpose = purpose;
        this.coin = coin;
        this.account = account;
        this.chain = chain;
    }

    /**
     * @param path
     */
    public DerivationPath(String path) {
        String[] pathParts = path.split("/");
        assert pathParts.length == 5;
        for (int i = 0; i < pathParts.length; i++) {
            pathParts[i] = pathParts[i].replace("'", "");
        }

        // m
        assert StringUtils.equals(pathParts[0], "m");

        // purpose
        this.purpose = Purpose.getPurposeForBip(pathParts[1]);
        assert this.purpose != null : String.format("Bip % is not found", pathParts[1]);

        // coin_type
        assert StringUtils.isNumeric(pathParts[2]) : String.format("Coin type % must be an integer", pathParts[2]);
        this.coin = Coin.getCoinForDerivationPathCoinType(Integer.valueOf(pathParts[2]));
        assert this.coin != null : String.format("Coin type % is not found", pathParts[2]);

        // account
        this.account = Integer.parseInt(pathParts[3]);

        // chain
        this.chain = Chain.getChainForChainCode(pathParts[4]);
        assert this.chain != null : String.format("Chain code % is not found", pathParts[2]);

    }

    /**
     * m / purpose' / coin_type' / account' / chain / address_index.
     *
     * @return the path
     */
    public String getPath() {
        return new StringBuilder() //
                .append("m").append("/") //
                .append(this.purpose.bip).append("'/") // purpose - hardened
                .append(this.coin.getDerivationPath()).append("'/") // coin type - hardened
                .append(this.account).append("'/") // account number - hardened
                .append(this.chain.chainCode) // chain code
                .toString();
    }

    /**
     * @author bash83
     */
    public enum Purpose {
    	
        /** BIP 39 */
        BIP39("39"),

        /** BIP 44 */
        BIP44("44"),

        /** BIP 49 */
        BIP49("49"),

        /** BIP 84 */
        BIP84("84");

        /** BIP */
        protected final String bip;

        /**
         * @param bip
         */
        Purpose(String bip) {
            this.bip = bip;
        }

        /**
         * @param bip
         * @return purpose
         */
        public static Purpose getPurposeForBip(String bip) {
            for (Purpose purpose : Purpose.values())
                if (StringUtils.equals(purpose.bip, bip))
                    return purpose;
            return null;
        }
    }

    /**
     * @author bash83
     */
    public enum Chain {

        /** external. */
        EXTERNAL("0"),

        /** change. */
        CHANGE("1");

        /** chain code. */
        protected final String chainCode;

        /**
         * @param chainCode
         */
        Chain(String chainCode) {
            this.chainCode = chainCode;
        }

        /**
         * @param chainCode
         * @return chain
         */
        protected static Chain getChainForChainCode(String chainCode) {
            for (Chain chain : Chain.values())
                if (StringUtils.equals(chain.chainCode, chainCode))
                    return chain;
            return null;
        }
    }
}
