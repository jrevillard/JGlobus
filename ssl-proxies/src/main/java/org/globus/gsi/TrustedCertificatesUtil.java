package org.globus.gsi;

import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;

import org.globus.common.CoGProperties;
import org.globus.gsi.provider.GlobusProvider;
import org.globus.gsi.provider.simple.SimpleMemoryCertStoreParams;
import org.globus.gsi.provider.simple.SimpleMemoryProvider;
import org.globus.gsi.stores.ResourceCertStoreParameters;

/**
 * This is a helper class to create convert TrustCertificates
 * @deprecated
 */
public class TrustedCertificatesUtil {

    static {
        Security.addProvider(new GlobusProvider());
        Security.addProvider(new SimpleMemoryProvider());
    }
    
    /**
     * Create a CertStore object from TrustedCertificates.
     * The store only loads  trusted certificates, no signing policies
     */
    public static CertStore createCertStore(TrustedCertificates tc) throws Exception {
        
        CertStore store = null;        
        if (tc == null) {
            String caCertPattern = "file:" + CoGProperties.getDefault().getCaCertLocations() + "/*.0";
            CertStoreParameters params = new ResourceCertStoreParameters(caCertPattern,null);
            store = CertStore.getInstance(GlobusProvider.CERTSTORE_TYPE, params);
        } else {
            SimpleMemoryCertStoreParams params = new SimpleMemoryCertStoreParams(tc.getCertificates(), null);
            params.setCerts(tc.getCertificates());
            store = CertStore.getInstance(SimpleMemoryProvider.CERTSTORE_TYPE, params, SimpleMemoryProvider.PROVIDER_NAME);
        }        
        return store;
    }
}
