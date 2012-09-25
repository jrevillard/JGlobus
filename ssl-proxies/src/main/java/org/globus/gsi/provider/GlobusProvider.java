package org.globus.gsi.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import org.globus.gsi.stores.PEMKeyStore;
import org.globus.gsi.stores.ResourceCertStore;
import org.globus.gsi.trustmanager.PKITrustManagerFactory;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;


/**
 * This is a security provider for the Globus SSL support. This supplies a
 * CertStore, CertValidator and KeyStore implementation
 * 
 * @version ${version}
 * @since 1.0
 */
public final class GlobusProvider extends Provider {

	public static final String PROVIDER_NAME = "Globus";
	public static final String CERTSTORE_TYPE = "PEMFilebasedCertStore";
	public static final String CERT_PATH_VALIDATOR_TYPE = "X509ProxyPath";
	public static final String KEYSTORE_TYPE = "PEMFilebasedKeyStore";
	public static final String TRUSTMANAGER_TYPE = "GlobusTrustManager";

	private static final long serialVersionUID = -6275241207604782362L;

	/**
	 * Create Provider and add Components to the java security framework.
	 */
	public GlobusProvider() {

		super(PROVIDER_NAME, 1.0, "Globus Security Providers");
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				put("CertStore.PEMFilebasedCertStore", ResourceCertStore.class
						.getName());
				put("CertPathValidator.X509ProxyPath",
						X509ProxyCertPathValidator.class.getName());
				put("KeyStore.PEMFilebasedKeyStore", PEMKeyStore.class
						.getName());
				put("TrustManagerFactory.GSI",
						PKITrustManagerFactory.class.getCanonicalName());
				return null;
			}
		});

	}

}
