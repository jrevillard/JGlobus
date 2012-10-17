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
package org.globus.gsi.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.common.CoGProperties;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.GSIConstants.CertificateType;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.TrustedCertificatesUtil;
import org.globus.gsi.bc.GlobusStyle;
import org.globus.gsi.bc.X500NameHelper;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.util.I18n;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public final class CertificateUtil {
    public static final int DEFAULT_USAGE_LENGTH = 9;

    private static String provider;
    private static Log logger;

    private static I18n i18n = I18n.getI18n("org.globus.gsi.errors", CertificateUtil.class.getClassLoader());


    static {
        Security.addProvider(new BouncyCastleProvider());
        setProvider("BC");
        logger = LogFactory.getLog(CertificateLoadUtil.class.getCanonicalName());
        installSecureRandomProvider();
    }

    private CertificateUtil() {
        //this should not be constructed;
    }

    /**
     * A no-op function that can be used to force the class
     * to load and initialize.
     */
    public static void init() {
        CertificateLoadUtil.init();
    }

    /**
     * Sets a provider name to use for loading certificates
     * and for generating key pairs.
     *
     * @param providerName provider name to use.
     */
    public static void setProvider(String providerName) {
        provider = providerName;
    }

    /**
     * Installs SecureRandom provider. 
     * This function is automatically called when this class is loaded.
     */
    public static void installSecureRandomProvider() {
        CoGProperties props = CoGProperties.getDefault();
        String providerName = props.getSecureRandomProvider();
        try {
            Class<?> providerClass = Class.forName(providerName);
            Security.insertProviderAt( (Provider)providerClass.newInstance(), 
                                       1 );
        } catch (Exception e) {
            logger.debug("Unable to install PRNG. Using default PRNG.",e);
        }
    }

    /**
     * Return CA Path constraint
     *
     * @param crt
     * @return
     * @throws IOException
     */
    public static int getCAPathConstraint(X509CertificateHolder crt)
            throws IOException {

        List<?> extensions = crt.getExtensionOIDs();
        if (extensions == null) {
            return -1;
        }
        
        Extension proxyExtension = crt.getExtension(Extension.basicConstraints);
        if (proxyExtension != null) {
            BasicConstraints basicExt = getBasicConstraints(proxyExtension);
            if (basicExt.isCA()) {
                BigInteger pathLen = basicExt.getPathLenConstraint();
                return (pathLen == null) ? Integer.MAX_VALUE : pathLen.intValue();
            } else {
                return -1;
            }
        }
        return -1;
    }
    
    /**
     * Generates a key pair of given algorithm and strength.
     *
     * @param algorithm the algorithm of the key pair.
     * @param bits the strength
     * @return <code>KeyPair</code> the generated key pair.
     * @exception GeneralSecurityException if something goes wrong.
     */
    public static KeyPair generateKeyPair(String algorithm, int bits) 
        throws GeneralSecurityException {
        KeyPairGenerator generator = null;
        if (provider == null) {
            generator = KeyPairGenerator.getInstance(algorithm);
        } else {
            generator = KeyPairGenerator.getInstance(algorithm, provider);
        }
        generator.initialize(bits);
        return generator.generateKeyPair();
    }
    

    /**
     * Returns certificate type of the given certificate. 
     * Please see {@link #getCertificateType(TBSCertificateStructure,
     * TrustedCertificates) getCertificateType} for details for 
     * determining the certificate type.
     *
     * @param cert the certificate to get the type of.
     * @param trustedCerts the trusted certificates to double check the 
     *                     {@link GSIConstants#EEC GSIConstants.EEC} 
     *                     certificate against.
     * @return the certificate type as determined by 
     *             {@link #getCertificateType(TBSCertificateStructure, 
     *              TrustedCertificates) getCertificateType}.
     * @exception CertificateException if something goes wrong.
     * @deprecated
     */
    public static GSIConstants.CertificateType getCertificateType(X509Certificate cert,
					 TrustedCertificates trustedCerts)
	throws CertificateException {
        try {
            return getCertificateType(cert, TrustedCertificatesUtil.createCertStore(trustedCerts));
	} catch (Exception e) {
	    throw new CertificateException("", e);
	}
    }

    /**
     * Returns the certificate type of the given certificate. 
     * Please see {@link #getCertificateType(TBSCertificateStructure,
     * TrustedCertificates) getCertificateType} for details for 
     * determining the certificate type.
     *
     * @param cert the certificate to get the type of.
     * @param trustedCerts the trusted certificates to double check the 
     *                     {@link GSIConstants#EEC GSIConstants.EEC} 
     *                     certificate against.
     * @return the certificate type as determined by 
     *             {@link #getCertificateType(TBSCertificateStructure, 
     *              TrustedCertificates) getCertificateType}.
     * @exception CertificateException if something goes wrong.
     */
    public static GSIConstants.CertificateType getCertificateType(X509Certificate cert, CertStore trustedCerts) throws CertificateException {
        try {
            GSIConstants.CertificateType type = getCertificateType(cert);

            // check subject of the cert in trusted cert list
            // to make sure the cert is not a ca cert
            if (type == GSIConstants.CertificateType.EEC) {
                X509CertSelector selector = new X509CertSelector();
                selector.setSubject(cert.getSubjectX500Principal());
                Collection<?> c = trustedCerts.getCertificates(selector);
                if (c != null && c.size() > 0) {
                    type = GSIConstants.CertificateType.CA;
                }
            }
            return type;
        } catch (Exception e) {
            // but this should not happen
            throw new CertificateException("", e);
        }
    }

    /**
     * Returns certificate type of the given certificate. <BR> The
     * certificate type is {@link org.globus.gsi.GSICertificateType#CA
     * CertificateType.CA} <B>only</B> if the certificate contains a
     * BasicConstraints extension and it is marked as CA.<BR> A certificate is a
     * GSI-2 proxy when the subject DN of the certificate ends with
     * <I>"CN=proxy"</I> (certificate type {@link org.globus.gsi.GSICertificateType#GSI_2_PROXY
     * CertificateType.GSI_2_PROXY}) or <I>"CN=limited proxy"</I> (certificate
     * type {@link org.globus.gsi.GSICertificateType#GSI_2_LIMITED_PROXY
     * CertificateType.LIMITED_PROXY}) component and the issuer DN of the
     * certificate matches the subject DN without the last proxy <I>CN</I>
     * component.<BR> A certificate is a GSI-3 proxy when the subject DN of the
     * certificate ends with a <I>CN</I> component, the issuer DN of the
     * certificate matches the subject DN without the last <I>CN</I> component
     * and the certificate contains {@link fr.maatg.pandora.clients.applets.proxyinitialisation.newglobus.gsi.proxy.ext.globus.security.proxyExtension.ProxyCertInfo
     * ProxyCertInfo} critical extension. The certificate type is {@link
     * org.globus.gsi.GSICertificateType#GSI_3_IMPERSONATION_PROXY
     * CertificateType.GSI_3_IMPERSONATION_PROXY} if the policy language of the
     * {@link fr.maatg.pandora.clients.applets.proxyinitialisation.newglobus.gsi.proxy.ext.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#IMPERSONATION
     * ProxyPolicy.IMPERSONATION} OID. The certificate type is {@link
     * org.globus.gsi.GSICertificateType#GSI_3_LIMITED_PROXY
     * CertificateType.GSI_3_LIMITED_PROXY} if the policy language of the {@link
     * fr.maatg.pandora.clients.applets.proxyinitialisation.newglobus.gsi.proxy.ext.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo} extension
     * is set to {@link org.globus.security.proxyExtension.ProxyPolicy#LIMITED
     * ProxyPolicy.LIMITED} OID. The certificate type is {@link
     * org.globus.gsi.GSICertificateType#GSI_3_INDEPENDENT_PROXY
     * CertificateType.GSI_3_INDEPENDENT_PROXY} if the policy language of the
     * {@link fr.maatg.pandora.clients.applets.proxyinitialisation.newglobus.gsi.proxy.ext.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to {@link org.globus.security.proxyExtension.ProxyPolicy#INDEPENDENT
     * ProxyPolicy.INDEPENDENT} OID. The certificate type is {@link
     * org.globus.gsi.GSICertificateType#GSI_3_RESTRICTED_PROXY
     * CertificateType.GSI_3_RESTRICTED_PROXY} if the policy language of the
     * {@link fr.maatg.pandora.clients.applets.proxyinitialisation.newglobus.gsi.proxy.ext.globus.security.proxyExtension.ProxyCertInfo ProxyCertInfo}
     * extension is set to any other OID then the above.<BR> The certificate
     * type is {@link org.globus.gsi.GSICertificateType#EEC
     * CertificateType.EEC} if the certificate is not a CA certificate or a
     * GSI-2 or GSI-3 proxy.
     *
     * @param cert the certificate to get the type of.
     * @return the certificate type. The certificate type is determined by rules
     *         described above.
     * @throws java.io.IOException if something goes wrong.
     * @throws java.security.cert.CertificateException
     *                             for proxy certificates, if the issuer DN of
     *                             the certificate does not match the subject DN
     *                             of the certificate without the last <I>CN</I>
     *                             component. Also, for GSI-3 proxies when the
     *                             <code>ProxyCertInfo</code> extension is not
     *                             marked as critical.
     */
    public static CertificateType getCertificateType(X509Certificate crt) throws CertificateException {
    	X509CertificateHolder certificateHolder;
		try {
			certificateHolder = new X509CertificateHolder(crt.getEncoded());
			return getCertificateType(certificateHolder);
		} catch (IOException e) {
			throw new CertificateException(e);
		}
    	
    }
    
    
    public static CertificateType getCertificateType(X509CertificateHolder crt) throws CertificateException, IOException {
    	if(crt.hasExtensions()){
	        Extension ext = crt.getExtension(Extension.basicConstraints);
	        if (ext != null) {
	            BasicConstraints basicExt = getBasicConstraints(ext);
	            if (basicExt.isCA()) {
	                return CertificateType.CA;
	            }
	        }
    	}

        CertificateType type = CertificateType.EEC;

        X500Name x500name = crt.getSubject();
        //Needed to put the RDN array in the expected order.
		RDN[] rdns = new X500Name(GlobusStyle.INSTANCE, CertificateUtil.toGlobusID(x500name.toString())).getRDNs();
		AttributeTypeAndValue attributeTypeAndValue;
		if(rdns[0].isMultiValued()){
			AttributeTypeAndValue[] attributeTypeAndValues = rdns[0].getTypesAndValues();
			attributeTypeAndValue = attributeTypeAndValues[attributeTypeAndValues.length -1];
		}else{
			attributeTypeAndValue = rdns[0].getFirst();
		}
		if (BCStyle.CN.equals(attributeTypeAndValue.getType())) {
			// Finish by CN=
			String value = IETFUtils.valueToString(attributeTypeAndValue.getValue());
			if (value.equalsIgnoreCase("proxy")) {
				type = CertificateType.GSI_2_PROXY;
			} else if (value.equalsIgnoreCase("limited proxy")) {
				type = CertificateType.GSI_2_LIMITED_PROXY;
			} else if (crt.hasExtensions()) {
				boolean gsi4 = true;
				// GSI_4
				Extension proxyCertInfosExtension = crt.getExtension(ProxyCertInfo.OID);
				if (proxyCertInfosExtension == null) {
					// GSI_3
					proxyCertInfosExtension = crt.getExtension(ProxyCertInfo.OLD_OID);
					gsi4 = false;
				}
				if (proxyCertInfosExtension != null) {
					if (proxyCertInfosExtension.isCritical()) {
						ProxyCertInfo proxyCertExt = ProxyCertificateUtil.getProxyCertInfo(proxyCertInfosExtension);
						ProxyPolicy proxyPolicy = proxyCertExt.getProxyPolicy();
						ASN1ObjectIdentifier oid = proxyPolicy.getPolicyLanguage();
						if (ProxyPolicy.IMPERSONATION.equals(oid)) {
							if (gsi4) {
								type = GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
							} else {
								type = GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
							}
						} else if (ProxyPolicy.INDEPENDENT.equals(oid)) {
							if (gsi4) {
								type = GSIConstants.CertificateType.GSI_4_INDEPENDENT_PROXY;
							} else {
								type = GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY;
							}
						} else if (ProxyPolicy.LIMITED.equals(oid)) {
							if (gsi4) {
								type = GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
							} else {
								type = GSIConstants.CertificateType.GSI_3_LIMITED_PROXY;
							}
						} else {
							if (gsi4) {
								type = GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY;
							} else {
								type = GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY;
							}
						}
						ASN1Set entry = X500NameHelper.getLastNameEntry(x500name);
						
						X500NameHelper iss = new X500NameHelper(crt.getIssuer());
						iss.add(ASN1Set.getInstance(entry.getEncoded()));
						X500Name subject = iss.getAsName();
						if (!subject.equals(crt.getSubject())) {
							String err = i18n.getMessage("proxyDNErr");
							throw new CertificateException(err);
						}
					} else {
						String err = i18n.getMessage("proxyCertCritical");
						throw new CertificateException(err);
					}
				}
			}
		}
		return type;
    }

    /**
     * Creates a <code>BasicConstraints</code> object from given extension.
     *
     * @param ext the extension.
     * @return the <code>BasicConstraints</code> object.
     * @throws IOException if something fails.
     */
    public static BasicConstraints getBasicConstraints(Extension ext) throws IOException{
        return BasicConstraints.getInstance(ext.getParsedValue().toASN1Primitive().getEncoded());
    }


    /**
     * Converts the ASN1-encoded byte array into a <code>ASN1Primitive</code>.
     *
     * @param data the ASN1-encoded byte array to convert.
     * @return the ASN1Primitive.
     * @throws IOException if conversion fails
     */
    public static ASN1Primitive toASN1Primitive(byte[] data) throws IOException {
        return  ASN1Primitive.fromByteArray(data);
    }

    /**
     * Gets the KeyUsage extension or <code>null</code> 
     * if the certificate does not have this extension.
     *
     * @throws IOException if failed to extract the KeyUsage extension value.
     * @see java.security.cert.X509Certificate#getKeyUsage
     */
    public static KeyUsage getKeyUsage(X509CertificateHolder crt) throws IOException {
    	
        if (!crt.hasExtensions()) {
            return null;
        }
        Extension extension = crt.getExtension(Extension.keyUsage);
        return (extension != null) ? getKeyUsage(extension) : null;
    }

    /**
     * Gets the KeyUsage extension
     *
     * @throws IOException if failed to extract the KeyUsage extension value.
     * @see java.security.cert.X509Certificate#getKeyUsage
     */
    public static KeyUsage getKeyUsage(Extension ext) throws IOException {
        try{
        	return (KeyUsage) KeyUsage.getInstance(ext.getParsedValue());
        }catch (Exception e) {
			throw new IOException(e);
		}
    }
    
	/**
	 * Returns the subject DN of the given certificate in the Globus format.
	 * 
	 * @param cert
	 *            the certificate to get the subject of. The certificate
	 *            must be of <code>X509CertificateObject</code> type.
	 * @return the subject DN of the certificate in the Globus format.
	 */
	public static String getIdentity(X509Certificate cert) {
		if (cert == null) {
			return null;
		}
		return CertificateUtil.toGlobusID(cert.getSubjectX500Principal());
	}

	/**
	 * Finds the identity certificate in the given chain and
	 * returns the subject DN of that certificate in the Globus format.
	 * 
	 * @param chain
	 *            the certificate chain to find the identity
	 *            certificate in. The certificates must be
	 *            of <code>X509CertificateObject</code> type.
	 * @return the subject DN of the identity certificate in
	 *         the Globus format.
	 * @exception CertificateException
	 *                if something goes wrong.
	 */
	public static String getIdentity(X509Certificate[] chain) throws CertificateException {
		return getIdentity(getIdentityCertificate(chain));
	}

	/**
	 * Finds the identity certificate in the given chain.
	 * The identity certificate is the first certificate in the
	 * chain that is not an impersonation proxy (full or limited)
	 * 
	 * @param chain
	 *            the certificate chain to find the identity
	 *            certificate in.
	 * @return the identity certificate.
	 * @exception CertificateException
	 *                if something goes wrong.
	 */
	public static X509Certificate getIdentityCertificate(X509Certificate[] chain) throws CertificateException {

		if (chain == null) {
			throw new IllegalArgumentException(i18n.getMessage("certChainNull"));
		}
		for (int i = 0; i < chain.length; i++) {
			CertificateType certType = CertificateUtil.getCertificateType(chain[i]);
			if (!ProxyCertificateUtil.isImpersonationProxy(certType)) {
				return chain[i];
			}
		}
		return null;
	}

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus 
     * format "/CN=A/OU=B/O=C".<BR>
     * This function might return incorrect Globus-formatted ID when one of
     * the RDNs in the DN contains commas.
     * @see #toGlobusID(String, boolean)
     *
     * @param dn the DN to convert to Globus format.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(String dn) {
    	return CertificateUtil.toGlobusID(new X500Principal(dn));
    }

    /**
     * Converts the specified principal into Globus format.
     * If the principal is of unrecognized type a simple string-based
     * conversion is made using the {@link #toGlobusID(String) toGlobusID()}
     * function.
     *
     * @see #toGlobusID(String)
     *
     * @param name the principal to convert to Globus format.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(Principal name) {
    	return CertificateUtil.toGlobusID(name.getName());
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus format
     * "/O=C/OU=B/CN=A" <BR>.
     *
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(X500Principal principal) {
    	X500Name x500Name = new X500Name(BCStyle.INSTANCE, principal.getName());
        return new X500Name(GlobusStyle.INSTANCE, x500Name.getRDNs()).toString();
    }

    /**
     * Converts Globus DN format "/O=C/OU=B/CN=A" into an X500Principal
     * representation, which accepts RFC 2253 or 1779 formatted DN's and also
     * attribute types as defined in RFC 2459 (e.g. "CN=A,OU=B,O=C"). This
     * method should allow the forward slash, "/", to occur in attribute values
     * (see GFD.125 section 3.2.2 -- RFC 2252 allows "/" in PrintableStrings).
     * @param globusID DN in Globus format
     * @return the X500Principal representation of the given DN
     */
    public static X500Principal toPrincipal(String globusID) {
        if (globusID == null) {
            return null;
        }
    	X500Name globusX500Name = new X500Name(GlobusStyle.INSTANCE, globusID.trim());
        return new X500Principal(new X500Name(BCStyle.INSTANCE, globusX500Name.getRDNs()).toString());
    }

    // JGLOBUS-91 
    public static CertPath getCertPath(X509Certificate[] certs) throws CertificateException {

        CertificateFactory factory;
		try {
			factory = CertificateFactory.getInstance("X.509", "BC");
		} catch (NoSuchProviderException e) {
			throw new CertificateException(e);
		}
        return factory.generateCertPath(Arrays.asList(certs));
    }

    
}
