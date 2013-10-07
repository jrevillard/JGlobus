/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.gsi.trustmanager;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.GSIConstants.CertificateType;
import org.globus.gsi.X509ProxyCertPathParameters;
import org.globus.gsi.X509ProxyCertPathValidatorResult;
import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.proxy.ProxyPolicyHandler;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;

/**
 * Implementation of the CertPathValidatorSpi and the logic for X.509 Proxy Path Validation.
 *
 * @version ${version}
 * @since 1.0
 */
public class X509ProxyCertPathValidator extends CertPathValidatorSpi {

    public static final String BASIC_CONSTRAINT_OID = "2.5.29.19";
    public static final String KEY_USAGE_OID = "2.5.29.15";

    protected KeyStore keyStore;
    protected CertStore certStore;
    protected SigningPolicyStore policyStore;

    private X509Certificate identityCert;
    private boolean limited;
    private boolean rejectLimitedProxy;
    private Map<String, ProxyPolicyHandler> policyHandlers;

    /**
     * Validates the specified certification path using the specified algorithm parameter set.
     * <p/>
     * The <code>CertPath</code> specified must be of a type that is supported by the validation algorithm, otherwise
     * an <code>InvalidAlgorithmParameterException</code> will be thrown. For example, a <code>CertPathValidator</code>
     * that implements the PKIX algorithm validates <code>CertPath</code> objects of type X.509.
     *
     * @param certPath the <code>CertPath</code> to be validated
     * @param params   the algorithm parameters
     * @return the result of the validation algorithm
     * @throws java.security.cert.CertPathValidatorException
     *          if the <code>CertPath</code> does not validate
     * @throws java.security.InvalidAlgorithmParameterException
     *          if the specified parameters or the type of the
     *          specified <code>CertPath</code> are inappropriate for this <code>CertPathValidator</code>
     */
	public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params)
            throws CertPathValidatorException, InvalidAlgorithmParameterException {

        if (certPath == null) {
            throw new IllegalArgumentException(
                    "Certificate path cannot be null");
        }

		List<? extends Certificate> list = certPath.getCertificates();
        if (list.size() < 1) {
            throw new IllegalArgumentException(
                    "Certificate path cannot be empty");
        }

        parseParameters(params);

        // find the root trust anchor. Validate signatures and see if the
        // chain ends in one of the trust root certificates
        CertPath trustedCertPath = TrustedCertPathFinder.findTrustedCertPath(this.keyStore, certPath);

        // rest of the validation
        return validate(trustedCertPath);
    }

    /**
     * Dispose of the current validation state.
     */
    public void clear() {
        this.identityCert = null;
        this.limited = false;
    }

    protected void parseParameters(CertPathParameters params) throws InvalidAlgorithmParameterException {

        if (!(params instanceof X509ProxyCertPathParameters)) {
            throw new IllegalArgumentException("Parameter of type " + X509ProxyCertPathParameters.class.getName()
                    + " required");
        }
        X509ProxyCertPathParameters parameters = (X509ProxyCertPathParameters) params;
        this.keyStore = parameters.getTrustStore();
        this.certStore = parameters.getCrlStore();
        this.policyStore = parameters.getSigningPolicyStore();
        this.rejectLimitedProxy = parameters.isRejectLimitedProxy();
        this.policyHandlers = parameters.getPolicyHandlers();
    }

    /**
     * Validates the certificate path and does the following for each certificate in the chain: method
     * checkCertificate() In addition: a) Validates if the issuer type of each certificate is correct b) CA path
     * constraints c) Proxy path constraints
     * <p/>
     * If it is of type proxy, check following: a) proxy constraints b) restricted proxy else if certificate, check the
     * following: a) keyusage
     *
     * @param certPath The CertPath to validate.
     * @return The results of the validation.
     * @throws CertPathValidatorException If the CertPath is invalid.
     */
    protected CertPathValidatorResult validate(CertPath certPath) throws CertPathValidatorException {

        List<? extends Certificate> certificates = certPath.getCertificates();
        if (certificates.size() == 0) {
            return null;
        }

        int proxyDepth = 0;

        X509Certificate cert = (X509Certificate) certificates.get(0);
        X509CertificateHolder certHolder;
        CertificateType certType;
		try {
			certHolder = new X509CertificateHolder(cert.getEncoded());
		    certType = getCertificateType(certHolder);
		    
		    // validate the first certificate in chain
		    checkCertificate(cert, certType);

		    boolean isProxy = ProxyCertificateUtil.isProxy(certType);
		    if (isProxy) {
		        proxyDepth++;
		    }
		} catch (CertificateEncodingException e) {
			throw new CertPathValidatorException("Path validation failed for " + cert.getSubjectDN() + ": " + e.getMessage(),
                    e, certPath, 0);
		} catch (IOException e) {
			throw new CertPathValidatorException("Path validation failed for " + cert.getSubjectDN() + ": " + e.getMessage(),
                    e, certPath, 0);
		}

        for (int i = 1; i < certificates.size(); i++) {

            boolean certIsProxy = ProxyCertificateUtil.isProxy(certType);
            X509Certificate issuerCert = (X509Certificate) certificates.get(i);
            X509CertificateHolder issuerCertHolder;
			try {
				issuerCertHolder = new X509CertificateHolder(issuerCert.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
			} catch (IOException e) {
				throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
			}
            CertificateType issuerCertType = getCertificateType(issuerCertHolder);

            proxyDepth = validateCert(certHolder, certType, issuerCertHolder, issuerCertType, proxyDepth, i, certIsProxy);

            if (certIsProxy) {
				try {
                	checkProxyConstraints(certPath, certHolder, certType, issuerCertHolder, i);
				} catch (CertPathValidatorException e) {
                    throw new CertPathValidatorException("Path validation failed for " + cert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i - 1);
                }
            } else {
                try {
                    checkKeyUsage(issuerCertHolder);
                } catch (IOException e) {
                    throw new CertPathValidatorException("Key usage check failed on " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
                } catch (CertPathValidatorException e) {
                    throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                            e, certPath, i);
                }
            }

            try {
                checkCertificate(issuerCert, issuerCertType);
            } catch (CertPathValidatorException e) {
                throw new CertPathValidatorException("Path validation failed for " + issuerCert.getSubjectDN() + ": " + e.getMessage(),
                        e, certPath, i);
            }

            cert = issuerCert;
            certType = issuerCertType;
            certHolder = issuerCertHolder;

        }

        return new X509ProxyCertPathValidatorResult(this.identityCert,
                this.limited);

    }

    private CertificateType getCertificateType(X509CertificateHolder certificateHolder) throws CertPathValidatorException {
        CertificateType issuerCertType;
        try {

        	issuerCertType = CertificateUtil.getCertificateType(certificateHolder);
        } catch (CertificateException e) {
            throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
        } catch (IOException e) {
            throw new CertPathValidatorException(
                    "Error obtaining certificate type", e);
        }
        return issuerCertType;
    }

    private int validateCert(X509CertificateHolder certHolder, CertificateType certType, X509CertificateHolder issuerCertHolder, CertificateType issuerCertType,
                             int proxyDepth, int i, boolean certIsProxy) throws CertPathValidatorException {
        if (issuerCertType == CertificateType.CA) {
            validateCACert(certHolder, issuerCertHolder, proxyDepth, i, certIsProxy);
        } else if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType)
                || ProxyCertificateUtil.isGsi4Proxy(issuerCertType)) {
            return validateGsiProxyCert(certHolder, certType, issuerCertHolder, issuerCertType, proxyDepth);
        } else if (ProxyCertificateUtil.isGsi2Proxy(issuerCertType)) {
            return validateGsi2ProxyCert(certHolder, certType, issuerCertHolder, proxyDepth);
        } else if (issuerCertType == CertificateType.EEC) {
            validateEECCert(certHolder, certType, issuerCertHolder);
        } else {
            // this should never happen?
            throw new CertPathValidatorException("UNknown issuer type " + issuerCertType
                    + " for certificate " + issuerCertHolder.getSubject());
        }
        return proxyDepth;
    }

    private void checkProxyConstraints(CertPath certPath, X509CertificateHolder certHolder, CertificateType certType, X509CertificateHolder issuerCertHolder, int i)
            throws CertPathValidatorException {

        // check all the proxy & issuer constraints
        if (ProxyCertificateUtil.isGsi3Proxy(certType)
                || ProxyCertificateUtil.isGsi4Proxy(certType)) {
            try {
                checkProxyConstraints(certHolder, issuerCertHolder);
            } catch (IOException e) {
                throw new CertPathValidatorException("Proxy constraint check failed on " + certHolder.getSubject(), e);
            }
            if ((certType == CertificateType.GSI_3_RESTRICTED_PROXY)
                    || (certType == CertificateType.GSI_4_RESTRICTED_PROXY)) {
                try {
                    checkRestrictedProxy(certHolder, certPath, i);
                } catch (IOException e) {
                    throw new CertPathValidatorException("Restricted proxy check failed on " + certHolder.getSubject(), e);
                }
            }
        }
    }

    private void validateEECCert(X509CertificateHolder certHolder, CertificateType certType,
                                 X509CertificateHolder issuerCertHolder) throws CertPathValidatorException {
        if (!ProxyCertificateUtil.isProxy(certType)) {
            throw new CertPathValidatorException("EEC can only sign another proxy certificate. Violated by "
                    + issuerCertHolder.getSubject() + " issuing " + certHolder.getSubject());
        }
    }


    private int validateGsi2ProxyCert(X509CertificateHolder certHolder, CertificateType certType,
                                      X509CertificateHolder issuerCertificateHolder, int proxyDepth) throws CertPathValidatorException {
        // PC can sign EEC or another PC only
        if (!ProxyCertificateUtil.isGsi2Proxy(certType)) {
            throw new CertPathValidatorException(
                    "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                            + issuerCertificateHolder.getSubject() + " issuing " + certHolder.getSubject());
        }
        return proxyDepth + 1;
    }

    private int validateGsiProxyCert(X509CertificateHolder certHolder, CertificateType certType,
                                     X509CertificateHolder issuerCertHolder,
                                     CertificateType issuerCertType, int proxyDepth)
            throws CertPathValidatorException {
        if (ProxyCertificateUtil.isGsi3Proxy(issuerCertType)) {
            if (!ProxyCertificateUtil.isGsi3Proxy(certType)) {
                throw new CertPathValidatorException(
                        "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                                + issuerCertHolder.getSubject() + " issuing " + certHolder.getSubject());
            }
        } else if (ProxyCertificateUtil.isGsi4Proxy(issuerCertType) && !ProxyCertificateUtil.isGsi4Proxy(certType)) {
            throw new CertPathValidatorException(
                    "Proxy certificate can only sign another proxy certificate of same type. Violated by "
                            + issuerCertHolder.getSubject() + " issuing " + certHolder.getSubject());
        }
        int pathLen;
        try {
            pathLen = ProxyCertificateUtil.getProxyPathConstraint(issuerCertHolder);
        } catch (IOException e) {
            throw new CertPathValidatorException("Error obtaining proxy path constraint", e);
        }
        if (pathLen == 0) {
            throw new CertPathValidatorException(
                    "Proxy path length constraint violated of certificate " + issuerCertHolder.getSubject());
        }
        if (pathLen < Integer.MAX_VALUE
                && proxyDepth > pathLen) {
            throw new CertPathValidatorException(
                    "Proxy path length constraint violated of certificate " + issuerCertHolder.getSubject());
        }
        return proxyDepth + 1;
    }

    private void validateCACert(
            X509CertificateHolder certHolder, X509CertificateHolder issuerCertHolder, int proxyDepth, int i,
            boolean certIsProxy) throws CertPathValidatorException {
        // PC can only be signed by EEC or PC
        if (certIsProxy) {
            throw new CertPathValidatorException(
                    "Proxy certificate can be signed only by EEC or Proxy "
                            + "Certificate. Certificate " + certHolder.getSubject() + " violates this.");
        }

        try {
            int pathLen =
                    CertificateUtil.getCAPathConstraint(issuerCertHolder);
            if (pathLen < Integer.MAX_VALUE
                    && (i - proxyDepth - 1) > pathLen) {
                throw new CertPathValidatorException("Path length constraint of certificate "
                        + issuerCertHolder.getSubject() + " violated");
            }
        } catch (IOException e) {
            throw new CertPathValidatorException("Error obtaining CA Path constraint", e);
        }
    }

    protected void checkRestrictedProxy(X509CertificateHolder proxy, CertPath certPath, int index)
            throws CertPathValidatorException, IOException {


        ProxyCertInfo info = ProxyCertificateUtil.getProxyCertInfo(proxy);
        ProxyPolicy policy = info.getProxyPolicy();

        String pl = policy.getPolicyLanguage().getId();

        ProxyPolicyHandler handler = null;
        if (this.policyHandlers != null) {
            handler = this.policyHandlers.get(pl);
        }

        if (handler == null) {
            throw new CertPathValidatorException("Unknown policy, no handler registered to validate policy " + pl);

        }

        handler.validate(info, certPath, index);

    }

    protected void checkKeyUsage(X509CertificateHolder issuersCertHolder)
            throws CertPathValidatorException, IOException {

        KeyUsage issuerKeyUsage = CertificateUtil.getKeyUsage(issuersCertHolder);
        if (issuerKeyUsage != null){
        	int bits = issuerKeyUsage.getBytes()[0] & 0xff;
        	if((bits & KeyUsage.keyCertSign) != KeyUsage.keyCertSign){
        		throw new CertPathValidatorException("Certificate " + issuersCertHolder.getSubject() + " violated key usage policy.");
            }
        }
    }


    // COMMENT enable the checkers again when ProxyPathValidator starts working!
    protected List<CertificateChecker> getCertificateCheckers() {
        List<CertificateChecker> checkers = new ArrayList<CertificateChecker>();
        checkers.add(new DateValidityChecker());
        checkers.add(new UnsupportedCriticalExtensionChecker());
        checkers.add(new IdentityChecker(this));
        // NOTE: the (possible) refresh of the CRLs happens when we call getDefault.
        // Hence, we must recreate crlsList for each call to checkCertificate
        // Sadly, this also means that the amount of work necessary for checkCertificate
        // can be arbitrarily large (if the CRL is indeed refreshed).
        //
        // Note we DO NOT use this.certStore by default!  TODO: This differs from the unit test
        CertificateRevocationLists crlsList = CertificateRevocationLists.getDefaultCertificateRevocationLists();
        checkers.add(new CRLChecker(crlsList, this.keyStore, true));
        checkers.add(new SigningPolicyChecker(this.policyStore));
        return checkers;
    }

    /*
     * Method to check following for any given certificate
     *
     * a) Date validity, is it valid for the curent time (see DateValidityChecker)
     * b) Any unsupported critical extensions (see UnsupportedCriticalExtensionChecker)
     * c) Identity of certificate (see IdentityChecker)
     * d) Revocation (see CRLChecker)
     * e) Signing policy (see SigningPolicyChecker)
     *
     */

    private void checkCertificate(X509Certificate cert, CertificateType certType)
            throws CertPathValidatorException {
        for (CertificateChecker checker : getCertificateCheckers()) {
            checker.invoke(cert, certType);
        }
    }

    protected void checkProxyConstraints(X509CertificateHolder proxy, X509CertificateHolder issuer) throws CertPathValidatorException, IOException {
    	Extension proxyKeyUsage = null;
    	Extension proxyExtension;
        if (proxy.hasExtensions()) {
        	@SuppressWarnings("unchecked")
			List<ASN1ObjectIdentifier> e = proxy.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : e) {
                proxyExtension = proxy.getExtension(oid);
                if (oid.equals(Extension.subjectAlternativeName)
                        || oid.equals(Extension.issuerAlternativeName)) {
                    // No Alt name extensions - 3.2 & 3.5
                    throw new CertPathValidatorException(
                            "Proxy violation: no Subject or Issuer Alternative Name");
                } else if (oid.equals(Extension.basicConstraints)) {
                    // Basic Constraint must not be true - 3.8
                    BasicConstraints basicExt =
                            CertificateUtil.getBasicConstraints(proxyExtension);
                    if (basicExt.isCA()) {
                        throw new CertPathValidatorException(
                                "Proxy violation: Basic Constraint CA is set to true");
                    }
                } else if (oid.equals(Extension.keyUsage)) {
                    proxyKeyUsage = proxyExtension;

                    checkKeyUsage(issuer, proxyExtension);
                }
            }
        }
        if (issuer.hasExtensions()) {
            @SuppressWarnings("unchecked")
			List<ASN1ObjectIdentifier> e = issuer.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : e) {
            	proxyExtension = issuer.getExtension(oid);
                checkExtension(oid, proxyExtension, proxyKeyUsage);
			}
        }

    }

    private void checkKeyUsage(X509CertificateHolder issuer, Extension proxyExtension) throws IOException, CertPathValidatorException {
        KeyUsage keyUsage = CertificateUtil.getKeyUsage(proxyExtension);
        int keyUsageBits = keyUsage.getBytes()[0] & 0xff;

        // these must not be asserted
        if(((keyUsageBits & KeyUsage.nonRepudiation) == KeyUsage.nonRepudiation)||((keyUsageBits & KeyUsage.keyCertSign) == KeyUsage.keyCertSign)){
        	throw new CertPathValidatorException("Proxy violation: Key usage is asserted.");
        }
    }

    private void checkExtension(ASN1ObjectIdentifier oid, Extension proxyExtension, Extension proxyKeyUsage) throws CertPathValidatorException {
        if (oid.equals(Extension.keyUsage)) {
            // If issuer has it then proxy must have it also
            if (proxyKeyUsage == null) {
                throw new CertPathValidatorException(
                        "Proxy violation: Issuer has key usage, but proxy does not");
            }
            // If issuer has it as critical so does the proxy
            if (proxyExtension.isCritical() && !proxyKeyUsage.isCritical()) {
                throw new CertPathValidatorException(
                        "Proxy voilation: issuer key usage is critical, but proxy certificate's is not");
            }
        }
    }

    public X509Certificate getIdentityCertificate() {
        return this.identityCert;
    }

    public void setLimited(boolean limited) {
        this.limited = limited;
    }

    // COMMENT: added a way to get 'limited'
    public boolean isLimited() {
        return this.limited;
    }

    public void setIdentityCert(X509Certificate identityCert) {
        this.identityCert = identityCert;
    }

    public boolean isRejectLimitedProxy() {
        return this.rejectLimitedProxy;
    }
}

