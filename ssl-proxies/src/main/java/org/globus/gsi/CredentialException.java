package org.globus.gsi;

import java.security.GeneralSecurityException;

/**
 * Exception signaling a credential failure.
 *
 * @version ${version}
 * @since 1.0
 */
public class CredentialException extends GeneralSecurityException {

	private static final long serialVersionUID = 1L;

	public CredentialException(String msg) {
        super(msg);
    }

    public CredentialException(String msg, Throwable ex) {
        super(msg, ex);
    }

    public CredentialException(Throwable ex) {
        super(ex);
    }
}
