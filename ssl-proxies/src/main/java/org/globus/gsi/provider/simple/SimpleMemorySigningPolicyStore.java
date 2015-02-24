package org.globus.gsi.provider.simple;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.bc.X500NameHelper;
import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.provider.SigningPolicyStoreException;
import org.globus.gsi.util.CertificateUtil;


/**
 * @deprecated
 */
public class SimpleMemorySigningPolicyStore implements SigningPolicyStore {
    private static Log logger = LogFactory.getLog(SimpleMemorySigningPolicyStore.class);


    private Map<String, SigningPolicy> store;

    public SimpleMemorySigningPolicyStore(SigningPolicy[] policies) {
        store = new ConcurrentHashMap<String,SigningPolicy>();
        int numPolicies = 0;
        if (policies != null) {
        	numPolicies = policies.length;
            for (SigningPolicy policy : policies) {
                if (policy != null) {
                	X500Name name  = new X500Name(policy.getCASubjectDN().getName());
                	String globus_name = X500NameHelper.toString(name);
                    store.put(globus_name, policy);
                    logger.debug("Adding to policy store: " + globus_name);
                }
            }
        }
        logger.debug("Loaded " +  store.size() + " policies of " + numPolicies);
    }

    public SigningPolicy getSigningPolicy(X500Principal caPrincipal) throws SigningPolicyStoreException {
    	SigningPolicy policy = store.get(CertificateUtil.toGlobusID(caPrincipal.getName()));
    	if (policy != null) {
    		X500Name name  = new X500Name(policy.getCASubjectDN().getName());
    		String globus_name = X500NameHelper.toString(name);
			logger.debug("Getting from policy store: " + globus_name);
			policy = store.get(globus_name);
    	}
    	return policy;
    }

}
