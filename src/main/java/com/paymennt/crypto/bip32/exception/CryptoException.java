/************************************************************************ 
 * Copyright PointCheckout, Ltd.
 * 
 */
package com.paymennt.crypto.bip32.exception;

/**
 * @author paymennt
 * 
 */
public class CryptoException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2036521227578435119L;

	public CryptoException(String message) {
		super(message);
	}

	public CryptoException(String message, Throwable cause) {
		super(message, cause);
	}

	public CryptoException(Throwable cause) {
		super(cause);
	}
}
