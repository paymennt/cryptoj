/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */

package com.paymennt.crypto.core.derivation;

import org.apache.commons.lang3.StringUtils;

import com.paymennt.crypto.core.Coin;

/**
 * @author bashar
 *
 */
public class DerivationPath {
    
    private final Purpose purpose;
    private final Coin coin;
    private final int account;
    private final Chain chain;
    
    public DerivationPath(Purpose purpose, Coin coin, int account, Chain chain) {
        this.purpose = purpose;
        this.coin = coin;
        this.account = account;
        this.chain = chain;
    }
    
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
     * m / purpose' / coin_type' / account' / chain / address_index
     * @return
     */
    public String getPath() {
        return new StringBuilder() //
            .append("m").append("/") //
            .append(this.purpose.bip).append("'/") // purpose - hardened
            .append(this.coin.getDerivationPathCoinType()).append("'/") // coin type - hardened
            .append(this.account).append("'/") // account number - hardened
            .append(this.chain.chainCode) // chain code
            .toString();
    }
    
    /**
     * @author bash83
     *
     */
    public enum Purpose {
        BIP44("44"),
        BIP49("49"),
        BIP84("84");
        
        protected final String bip;
        
        Purpose(String bip) {
            this.bip = bip;
        }
        
        public static Purpose getPurposeForBip(String bip) {
            for (Purpose purpose : Purpose.values())
                if (StringUtils.equals(purpose.bip, bip))
                    return purpose;
            return null;
        }
    }
    
    /**
     * @author bash83
     *
     */
    public enum Chain {
        EXTERNAL("0"),
        CHANGE("1");
        
        protected final String chainCode;
        
        Chain(String chainCode) {
            this.chainCode = chainCode;
        }
        
        protected static Chain getChainForChainCode(String chainCode) {
            for (Chain chain : Chain.values())
                if (StringUtils.equals(chain.chainCode, chainCode))
                    return chain;
            return null;
        }
    }
}
