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
package org.globus.gsi.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestHolder;
import org.bouncycastle.pkcs.PKCSException;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.VersionUtil;
import org.globus.gsi.X509Credential;
import org.globus.gsi.proxy.ext.GlobusProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;
import org.globus.util.I18n;

/**
 * Provides certificate processing API such as creating new certificates, certificate requests, etc.
 */
public class BouncyCastleCertProcessingFactory {

    private static I18n i18n = I18n.getI18n("org.globus.gsi.errors", BouncyCastleCertProcessingFactory.class
        .getClassLoader());

    private static BouncyCastleCertProcessingFactory factory;

    protected BouncyCastleCertProcessingFactory() {
    }

    /**
     * Returns an instance of this class..
     * 
     * @return <code>BouncyCastleCertProcessingFactory</code> instance.
     */
    public static synchronized BouncyCastleCertProcessingFactory getDefault() {
        if (factory == null) {
            factory = new BouncyCastleCertProcessingFactory();
        }
        return factory;
    }

    /**
     * Creates a proxy certificate from the certificate request.
     * 
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, int, Extensions, String)
     *      createCertificate
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType) throws IOException,
        GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, certType, (X509Extensions) null,
            null);
    }

    /**
     * Creates a proxy certificate from the certificate request.
     * 
     * @see #createCertificate(InputStream, X509Certificate, PrivateKey, int, GSIConstants.CertificateType, Extensions, String)
     *      createCertificate
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet)
        throws IOException, GeneralSecurityException {
        return createCertificate(certRequestInputStream, cert, privateKey, lifetime, certType, extSet, null);
    }

    /**
     * Creates a proxy certificate from the certificate request. (Signs a certificate request creating a new
     * certificate) (DOES NOT CLOSE THE INPUT STREAM)
     * 
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, Extensions,
     *      String) createProxyCertificate
     * @param certRequestInputStream
     *            the input stream to read the certificate request from.
     * @param cert
     *            the issuer certificate
     * @param privateKey
     *            the private key to sign the new certificate with.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link GSIConstants#CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link GSIConstants#CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate
     * @exception IOException
     *                if error reading the certificate request
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Certificate createCertificate(InputStream certRequestInputStream, X509Certificate cert,
        PrivateKey privateKey, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet,
        String cnValue) throws IOException, GeneralSecurityException {

    	// derin MUST NOT BE CLOSED (i.e myproxy usage)
        @SuppressWarnings("resource")
		ASN1InputStream derin = new ASN1InputStream(certRequestInputStream);
        DERObject reqInfo = derin.readObject();

        PKCS10CertificationRequestHolder certReq = new PKCS10CertificationRequestHolder(reqInfo.getEncoded());

        boolean rs;
		try {
			AsymmetricKeyParameter asymmetricKeyParameter =  PublicKeyFactory.createKey(certReq.getSubjectPublicKeyInfo());
			BcRSAContentVerifierProviderBuilder bcRSAContentVerifierProviderBuilder = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder());
			ContentVerifierProvider  contentVerifierProvider = bcRSAContentVerifierProviderBuilder.build(asymmetricKeyParameter);
			rs = certReq.isSignatureValid(contentVerifierProvider);
		} catch (OperatorCreationException e) {
			throw new GeneralSecurityException(e);
		} catch (PKCSException e) {
			throw new GeneralSecurityException(e);
		}

        if (!rs) {
            String err = i18n.getMessage("certReqVerification");
            throw new GeneralSecurityException(err);
        }

        return createProxyCertificate(cert, privateKey, certReq.getSubjectPublicKeyInfo(), lifetime, certType, extSet, cnValue);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     * 
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, Extensions, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, certType, (X509Extensions) null, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key.
     * 
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, Extensions, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType, X509Extensions extSet) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, certType, extSet, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key. A set of X.509
     * extensions can be optionally included in the new proxy certificate. This function automatically creates
     * a "RSA"-based key pair.
     * 
     * @see #createProxyCertificate(X509Certificate, PrivateKey, PublicKey, int, int, Extensions,
     *      String) createProxyCertificate
     * @param certs
     *            the certificate chain for the new proxy credential. The top-most certificate
     *            <code>cert[0]</code> will be designated as the issuing certificate.
     * @param privateKey
     *            the private key of the issuing certificate. The new proxy certificate will be signed with
     *            that private key.
     * @param bits
     *            the strength of the key pair for the new proxy certificate.
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            the type of proxy credential to create
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link GSIConstants#CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link GSIConstants#CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * @param cnValue
     *            the value of the CN component of the subject of the new proxy credential. If null, the
     *            defaults will be used depending on the proxy certificate type created.
     * @return <code>GlobusCredential</code> the new proxy credential.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.CertificateType certType, X509Extensions extSet, String cnValue) throws GeneralSecurityException {

        X509Certificate[] bcCerts = getX509CertificateObjectChain(certs);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(bits);
        KeyPair keyPair = keyGen.genKeyPair();

        X509Certificate newCert = createProxyCertificate(bcCerts[0], privateKey, keyPair.getPublic(), lifetime,
            certType, extSet, cnValue);

        X509Certificate[] newCerts = new X509Certificate[bcCerts.length + 1];
        newCerts[0] = newCert;
        System.arraycopy(certs, 0, newCerts, 1, certs.length);

        return new X509Credential(keyPair.getPrivate(), newCerts);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, Extensions, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.DelegationType delegType) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegType, (X509Extensions) null, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     *
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, Extensions, String)
     *      createCredential
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
        GSIConstants.DelegationType delegType, X509Extensions extSet) throws GeneralSecurityException {
        return createCredential(certs, privateKey, bits, lifetime, delegType, extSet, null);
    }

    /**
     * Creates a new proxy credential from the specified certificate chain and a private key,
     * using the given delegation mode.
     * @see #createCredential(X509Certificate[], PrivateKey, int, int, GSIConstants.CertificateType, Extensions, String)
     */
    public X509Credential createCredential(X509Certificate[] certs, PrivateKey privateKey, int bits, int lifetime,
       GSIConstants.DelegationType delegType, X509Extensions extSet, String cnValue) throws GeneralSecurityException {

        X509Certificate[] bcCerts = getX509CertificateObjectChain(certs);

        return createCredential(bcCerts, privateKey, bits, lifetime, decideProxyType(bcCerts[0], delegType), extSet, cnValue);
    }

    /**
     * Creates a proxy certificate. A set of X.509 extensions can be optionally included in the new proxy
     * certificate. <BR>
     * If a GSI-2 proxy is created, the serial number of the proxy certificate will be the same as of the
     * issuing certificate. Also, none of the extensions in the issuing certificate will be copied into the
     * proxy certificate.<BR>
     * If a GSI-3 or GSI 4 proxy is created, the serial number of the proxy certificate will be picked
     * randomly. If the issuing certificate contains a <i>KeyUsage</i> extension, the extension will be copied
     * into the proxy certificate with <i>keyCertSign</i> and <i>nonRepudiation</i> bits turned off. No other
     * extensions are currently copied.
     * 
     * The methods defaults to creating GSI 4 proxy
     * 
     * @param issuerCert
     *            the issuing certificate
     * @param issuerKey
     *            private key matching the public key of issuer certificate. The new proxy certificate will be
     *            signed by that key.
     * @param publicKey
     *            the public key of the new certificate
     * @param lifetime
     *            lifetime of the new certificate in seconds. If 0 (or less then) the new certificate will
     *            have the same lifetime as the issuing certificate.
     * @param certType
     *            can be one of {@link GSIConstants#CertificateType#DELEGATION_LIMITED GSIConstants.CertificateTypeDELEGATION_LIMITED},
     *            {@link GSIConstants#CertificateType#DELEGATION_FULL GSIConstants.CertificateTypeDELEGATION_FULL},
     * 
     *            {@link GSIConstants#CertificateType#GSI_2_LIMITED_PROXY GSIConstants.CertificateType.GSI_2_LIMITED_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_2_PROXY GSIConstants.CertificateType.GSI_2_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_3_IMPERSONATION_PROXY GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_3_LIMITED_PROXY GSIConstants.CertificateType.GSI_3_LIMITED_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_3_INDEPENDENT_PROXY GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_3_RESTRICTED_PROXY GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY}.
     *            {@link GSIConstants#CertificateType#GSI_4_IMPERSONATION_PROXY GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_4_LIMITED_PROXY GSIConstants.CertificateType.GSI_3_LIMITED_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_4_INDEPENDENT_PROXY GSIConstants.CertificateType.GSI_4_INDEPENDENT_PROXY},
     *            {@link GSIConstants#CertificateType#GSI_4_RESTRICTED_PROXY GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY}.
     * 
     *            If {@link GSIConstants#CertificateType#DELEGATION_LIMITED GSIConstants.CertificateTypeDELEGATION_LIMITED} and if
     *            {@link VersionUtil#isGsi2Enabled() CertUtil.isGsi2Enabled} returns true then a GSI-2 limited
     *            proxy will be created. Else if {@link VersionUtil#isGsi3Enabled() CertUtil.isGsi3Enabled}
     *            returns true then a GSI-3 limited proxy will be created. If not, a GSI-4 limited proxy will
     *            be created.
     * 
     *            If {@link GSIConstants#CertificateType#DELEGATION_FULL GSIConstants.CertificateTypeDELEGATION_FULL} and if
     *            {@link VersionUtil#isGsi2Enabled() CertUtil.isGsi2Enabled} returns true then a GSI-2 full proxy
     *            will be created. Else if {@link VersionUtil#isGsi3Enabled() CertUtil.isGsi3Enabled} returns
     *            true then a GSI-3 full proxy will be created. If not, a GSI-4 full proxy will be created.
     * 
     * @param extSet
     *            a set of X.509 extensions to be included in the new proxy certificate. Can be null. If
     *            delegation mode is {@link GSIConstants#CertificateType#GSI_3_RESTRICTED_PROXY
     *            GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY} or {@link GSIConstants#CertificateType#GSI_4_RESTRICTED_PROXY
     *            GSIConstants.GSI_4_RESTRICTED_PROXY} then
     *            {@link org.globus.gsi.proxy.ext.ProxyCertInfoExtension ProxyCertInfoExtension} must be
     *            present in the extension set.
     * 
     * @param cnValue
     *            the value of the CN component of the subject of the new certificate. If null, the defaults
     *            will be used depending on the proxy certificate type created.
     * @return <code>X509Certificate</code> the new proxy certificate.
     * @exception GeneralSecurityException
     *                if a security error occurs.
     */
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
            PublicKey publicKey, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet,
            String cnValue) throws GeneralSecurityException {

    		return createProxyCertificate(issuerCert_, issuerKey, publicKey, lifetime, certType, extSet, cnValue, new BouncyCastleProvider());

        }
    
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
        PublicKey publicKey, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet,
        String cnValue, Provider securityProvider) throws GeneralSecurityException {
    	
    	try {
			return createProxyCertificate(issuerCert_, issuerKey, SubjectPublicKeyInfo.getInstance(ASN1Sequence.fromByteArray(publicKey.getEncoded())), lifetime, certType, extSet, cnValue, securityProvider);
		} catch (IOException e) {
			throw new GeneralSecurityException(e.getMessage());
		}
    }
    
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
    		SubjectPublicKeyInfo subjectPublicKeyInfo, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet,
            String cnValue) throws GeneralSecurityException {
    	return createProxyCertificate(issuerCert_, issuerKey, subjectPublicKeyInfo, lifetime, certType, extSet, cnValue, new BouncyCastleProvider());
    }
    
    public X509Certificate createProxyCertificate(X509Certificate issuerCert_, PrivateKey issuerKey,
    		SubjectPublicKeyInfo subjectPublicKeyInfo, int lifetime, GSIConstants.CertificateType certType, X509Extensions extSet,
            String cnValue, Provider securityProvider) throws GeneralSecurityException {
        	
    	X509Certificate issuerCert = issuerCert_;
        if (!(issuerCert_ instanceof X509CertificateObject)) {
            issuerCert = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(issuerCert.getEncoded()));
        }
        
        BigInteger serialNum = null;
        String delegDN = null;
        boolean gt3_4 = false;

        if (ProxyCertificateUtil.isGsi3Proxy(certType) || ProxyCertificateUtil.isGsi4Proxy(certType)) {
        	gt3_4 =true;
            Random rand = new Random();
            delegDN = String.valueOf(Math.abs(rand.nextInt()));
            serialNum = new BigInteger(20, rand);
        } else if (certType == GSIConstants.CertificateType.GSI_2_LIMITED_PROXY) {
            delegDN = "limited proxy";
            serialNum = issuerCert.getSerialNumber();
        } else if (certType == GSIConstants.CertificateType.GSI_2_PROXY) {
            delegDN = "proxy";
            serialNum = issuerCert.getSerialNumber();
        } else {
            String err = i18n.getMessage("unsupportedProxy", certType);
            throw new IllegalArgumentException(err);
        }

        X500Name issuerDN = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500NameHelper issuer = new X500NameHelper(issuerDN);
        X500NameHelper subject = new X500NameHelper(issuerDN);
        subject.add(BCStyle.CN, (cnValue == null) ? delegDN : cnValue);

        GregorianCalendar date = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
        /* Allow for a five minute clock skew here. */
        date.add(Calendar.MINUTE, -5);
        Date notBefore = date.getTime();

        /* If hours = 0, then cert lifetime is set to user cert */
        Date notAfter = null;
        if (lifetime <= 0) {
        	notAfter = issuerCert.getNotAfter();
        } else {
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            notAfter = date.getTime();
        }
        try {
        	RDN[] rdns = issuer.getAsName().getRDNs();
        	X500Name realIssuer = new X500Name(BCStyle.INSTANCE, rdns);
        	
            rdns = subject.getAsName().getRDNs();
        	X500Name realSubject = new X500Name(BCStyle.INSTANCE, rdns);
        	
        	MyX509v3CertificateBuilder certBuilder = new MyX509v3CertificateBuilder(realIssuer, serialNum, notBefore, notAfter, realSubject, subjectPublicKeyInfo);
	        
	        X509Extension x509Ext = null;        
	        if (gt3_4) {
	        	ASN1ObjectIdentifier extOID = null;
				if (extSet != null) {
					x509Ext = extSet.getExtension(ProxyCertInfo.OID);
					extOID = ProxyCertInfo.OID;
					if (x509Ext == null) {
						x509Ext = extSet.getExtension(ProxyCertInfo.OLD_OID);
						extOID = ProxyCertInfo.OLD_OID;
					}
				}
	
				if (x509Ext == null) {
					extOID = null;
					// create ProxyCertInfo extension
					ProxyPolicy policy = null;
					if (ProxyCertificateUtil.isLimitedProxy(certType)) {
						policy = new ProxyPolicy(ProxyPolicy.LIMITED);
					} else if (ProxyCertificateUtil.isIndependentProxy(certType)) {
						policy = new ProxyPolicy(ProxyPolicy.INDEPENDENT);
					} else if (ProxyCertificateUtil.isImpersonationProxy(certType)) {
						// since limited has already been checked, this should work.
						policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION);
					} else if ((certType == GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY)
							|| (certType == GSIConstants.CertificateType.GSI_4_RESTRICTED_PROXY)) {
						throw new IllegalArgumentException("Proxy restricted");
					} else {
						throw new IllegalArgumentException("Invalid Proxy Type");
					}

					ProxyCertInfo proxyCertInfo = new ProxyCertInfo(policy);
					if (ProxyCertificateUtil.isGsi4Proxy(certType)) {
						// RFC compliant OID
						x509Ext = new ProxyCertInfoExtension(proxyCertInfo);
						extOID = ProxyCertInfo.OID;
					} else {
						// old OID
						x509Ext = new GlobusProxyCertInfoExtension(proxyCertInfo);
						extOID = ProxyCertInfo.OLD_OID;
					}
				}
	
	            // add ProxyCertInfo extension to the new cert
	        	certBuilder.addExtension(extOID, x509Ext.isCritical(), x509Ext.getParsedValue());
	        }
	        
	        // handle KeyUsage in issuer cert
            X509CertificateHolder crt = new X509CertificateHolder(issuerCert.getEncoded());
            if (crt.hasExtensions()) {
                X509Extension ext;

                // handle key usage ext
                ext = crt.getExtension(X509Extension.keyUsage);
                if (ext != null) {

                    // TBD: handle this better
                    if (extSet != null && (extSet.getExtension(X509Extension.keyUsage) != null)) {
                        String err = i18n.getMessage("keyUsageExt");
                        throw new GeneralSecurityException(err);
                    }

                    DERBitString bits = (DERBitString) ext.getParsedValue().toASN1Object();

                    byte[] bytes = bits.getBytes();

                    // make sure they are disabled
                    if ((bytes[0] & KeyUsage.nonRepudiation) != 0) {
                        bytes[0] ^= KeyUsage.nonRepudiation;
                    }

                    if ((bytes[0] & KeyUsage.keyCertSign) != 0) {
                        bytes[0] ^= KeyUsage.keyCertSign;
                    }

                    bits = new DERBitString(bytes, bits.getPadBits());

                    certBuilder.addExtension(X509Extension.keyUsage, ext.isCritical(), bits);
                }
            }
	
	        // add specified extensions
			if (extSet != null) {
				Enumeration<?> oids = extSet.oids();
				while (oids.hasMoreElements()) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) oids.nextElement();
					// skip ProxyCertInfo extension
					if (oid.equals(ProxyCertInfo.OID) || oid.equals(ProxyCertInfo.OLD_OID)) {
						continue;
					}
					x509Ext = extSet.getExtension(oid);
					certBuilder.addExtension(oid, x509Ext.isCritical(), x509Ext.getParsedValue());
				}
			}
	        
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(securityProvider).build(issuerKey);
			X509CertificateHolder x509CertificateHolder = certBuilder.build(contentSigner);
			
//			try {
//				ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(securityProvider).build(issuerCert);
//				if (!x509CertificateHolder.isSignatureValid(contentVerifierProvider)){
//				    throw new GeneralSecurityException("signature invalid");
//				}
//			} catch (CertException e) {
//				throw new GeneralSecurityException(e);
//			}			
	        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
        } catch (IOException e) {
            // but this should not happen
            throw new GeneralSecurityException(e);
        } catch (OperatorCreationException e) {
        	throw new GeneralSecurityException(e);
		}
    }

    /**
     * Loads a X509 certificate from the specified input stream. Input stream must contain DER-encoded
     * certificate. (DOES NOT CLOSE THE STREAM)
     * 
     * @param in
     *            the input stream to read the certificate from.
     * @return <code>X509Certificate</code> the loaded certificate.
     * @exception GeneralSecurityException
     *                if certificate failed to load.
     */
    public X509Certificate loadCertificate(InputStream in) throws IOException, GeneralSecurityException {
        //derin MUST NOT BE CLOSED (c.f myproxy usage)
    	@SuppressWarnings("resource")
		ASN1InputStream derin = new ASN1InputStream(in);
        DERObject certInfo = derin.readObject();
        ASN1Sequence seq = ASN1Sequence.getInstance(certInfo);
        return new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate(new X509CertificateHolder(seq.getEncoded()));
    }

    /**
     * Creates a certificate request from the specified subject DN and a key pair. The
     * <I>"SHA1WithRSAEncryption"</I> is used as the signing algorithm of the certificate request.
     * 
     * @param subject
     *            the subject of the certificate request
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(String subject, KeyPair keyPair) throws GeneralSecurityException {
        X500Name name = new X500Name(subject);
        return createCertificateRequest(name, "SHA1WithRSAEncryption", keyPair);
    }

    /**
     * Creates a certificate request from the specified certificate and a key pair. The certificate's subject
     * DN with <I>"CN=proxy"</I> name component appended to the subject is used as the subject of the
     * certificate request. Also the certificate's signing algorithm is used as the certificate request
     * signing algorithm.
     * 
     * @param cert
     *            the certificate to create the certificate request from.
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(X509Certificate cert, KeyPair keyPair) throws GeneralSecurityException {
        String issuer = cert.getSubjectX500Principal().getName();
        X500Name subjectDN = new X500Name(issuer + ",CN=proxy");
        String sigAlgName = cert.getSigAlgName();
        return createCertificateRequest(subjectDN, sigAlgName, keyPair);
    }

    /**
     * Creates a certificate request from the specified subject name, signing algorithm, and a key pair.
     * 
     * @param subjectDN
     *            the subject name of the certificate request.
     * @param sigAlgName
     *            the signing algorithm name.
     * @param keyPair
     *            the key pair of the certificate request
     * @return the certificate request.
     * @exception GeneralSecurityException
     *                if security error occurs.
     */
    public byte[] createCertificateRequest(X500Name subjectDN, String sigAlgName, KeyPair keyPair) throws GeneralSecurityException {
		try {
			MyPKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new MyPKCS10CertificationRequestBuilder(subjectDN, new SubjectPublicKeyInfo((ASN1Sequence)ASN1Sequence.fromByteArray(keyPair.getPublic().getEncoded())));
			PKCS10CertificationRequestHolder certReq = pkcs10CertificationRequestBuilder.build(new JcaContentSignerBuilder(sigAlgName).setProvider("BC").build(keyPair.getPrivate()));
			boolean rs = certReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(keyPair.getPublic()));
			if (!rs) {
	            String err = i18n.getMessage("certReqVerification");
	            throw new GeneralSecurityException(err);
	        }
	        return certReq.getEncoded();
		} catch (Exception e) {
			throw new GeneralSecurityException(e);
		}
    }

    /**
     * Given a delegation mode and an issuing certificate, decides an
     * appropriate certificate type to use for proxies
     * @param issuerCert the issuing certificate of a prospective proxy
     * @param delegType the desired delegation mode
     * @return the appropriate certificate type for proxies or
     * GSIConstants#CertificateType#UNDEFINED when
     * GSIConstants#DelegationType#NONE was specified
     * @throws CertificateException when failing to get the certificate type
     * of the issuing certificate
     */
    public static GSIConstants.CertificateType decideProxyType(
            X509Certificate issuerCert, GSIConstants.DelegationType delegType)
            throws CertificateException {
        GSIConstants.CertificateType proxyType = GSIConstants.CertificateType.UNDEFINED;
        if (delegType == GSIConstants.DelegationType.LIMITED) {
            GSIConstants.CertificateType type = CertificateUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_3_LIMITED_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
            } else {
                // default to RFC compliant proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.CertificateType.GSI_2_LIMITED_PROXY;
                } else {
                    proxyType = VersionUtil.isGsi3Enabled() ?
                          GSIConstants.CertificateType.GSI_3_LIMITED_PROXY
                        : GSIConstants.CertificateType.GSI_4_LIMITED_PROXY;
                }
            }
        } else if (delegType == GSIConstants.DelegationType.FULL) {
            GSIConstants.CertificateType type = CertificateUtil.getCertificateType(issuerCert);
            if (ProxyCertificateUtil.isGsi4Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi3Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY;
            } else if (ProxyCertificateUtil.isGsi2Proxy(type)) {
                proxyType = GSIConstants.CertificateType.GSI_2_PROXY;
            } else {
                // Default to RFC complaint proxy
                if (VersionUtil.isGsi2Enabled()) {
                    proxyType = GSIConstants.CertificateType.GSI_2_PROXY;
                } else {
                    proxyType = (VersionUtil.isGsi3Enabled()) ?
                          GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY
                        : GSIConstants.CertificateType.GSI_4_IMPERSONATION_PROXY;
                }
            }
        }
        return proxyType;
    }

    /**
     * Returns a chain of X509Certificate's that are instances of X509CertificateObject
     * This is related to http://bugzilla.globus.org/globus/show_bug.cgi?id=4933
     * @param certs input certificate chain
     * @return a new chain where all X509Certificate's are instances of X509CertificateObject
     * @throws GeneralSecurityException when failing to get load certificate from encoding
     */
    protected X509Certificate[] getX509CertificateObjectChain(X509Certificate[] certs)
            throws GeneralSecurityException {
        X509Certificate[] bcCerts = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            if (!(certs[i] instanceof X509CertificateObject)) {
                bcCerts[i] = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(certs[i].getEncoded()));
            } else {
                bcCerts[i] = certs[i];
            }
        }
        return bcCerts;
    }
    
    /**
     * FIXME:
	 * This class is a copy of {@link X509v3CertificateBuilder}. The modification is in the constructor in order to
	 * fill the Subject and Issuer using a {@link X509Principal} instead of a {@link X500Name}. The hash produced server
	 * side is different in both cases (i.e: MyProxy server).
	 */
	public class MyX509v3CertificateBuilder
	{
	    private V3TBSCertificateGenerator   tbsGen;
	    private X509ExtensionsGenerator     extGenerator;
	
	    /**
	     * Create a builder for a version 3 certificate.
	     *
	     * @param issuer the certificate issuer
	     * @param serial the certificate serial number
	     * @param notBefore the date before which the certificate is not valid
	     * @param notAfter the date after which the certificate is not valid
	     * @param subject the certificate subject
	     * @param publicKeyInfo the info structure for the public key to be associated with this certificate.
	     */
	    public MyX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
	    {
	        tbsGen = new V3TBSCertificateGenerator();
	        tbsGen.setSerialNumber(new DERInteger(serial));
	        //---- MODIF ---			
	        X500Principal originalIssuer = new X500Principal(issuer.toString());
	        X509Principal x509NameIssuer = null;
			try {
				x509NameIssuer = new X509Principal(originalIssuer.getEncoded());
			} catch (IOException e) {
				throw new IllegalStateException("cannot construct certificate x509NameIssuer");
			}
			//---- END MODIF ---
	        tbsGen.setIssuer(x509NameIssuer);
	        tbsGen.setStartDate(new Time(notBefore));
	        tbsGen.setEndDate(new Time(notAfter));
	        //---- MODIF ---
	        X500Principal originalSubject = new X500Principal(subject.toString());
	        X509Principal x509NameSubject = null;
			try {
				x509NameSubject = new X509Principal(originalSubject.getEncoded());
			} catch (IOException e) {
				throw new IllegalStateException("cannot construct certificate x509NameSubject");
			}
			//---- END MODIF ---
	        tbsGen.setSubject(x509NameSubject);
	        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
	
	        extGenerator = new X509ExtensionsGenerator();
	    }
	
	    /**
	     * Add a given extension field for the standard extensions tag (tag 3)
	     *
	     * @param oid the OID defining the extension type.
	     * @param isCritical true if the extension is critical, false otherwise.
	     * @param value the ASN.1 structure that forms the extension's value.
	     * @return this builder object.
	     */
	    public MyX509v3CertificateBuilder addExtension(
	        ASN1ObjectIdentifier oid,
	        boolean isCritical,
	        ASN1Encodable value)
	    {
	        extGenerator.addExtension(oid, isCritical, value);
	
	        return this;
	    }
	
	    /**
	     * Add a given extension field for the standard extensions tag (tag 3)
	     * copying the extension value from another certificate.
	     *
	     * @param oid the OID defining the extension type.
	     * @param isCritical true if the copied extension is to be marked as critical, false otherwise.
	     * @param certHolder the holder for the certificate that the extension is to be copied from.
	     * @return this builder object.
	     */
	    public MyX509v3CertificateBuilder copyAndAddExtension(
	        ASN1ObjectIdentifier oid,
	        boolean isCritical,
	        X509CertificateHolder certHolder)
	    {
	        X509CertificateStructure cert = certHolder.toASN1Structure();
	
	        X509Extension extension = cert.getTBSCertificate().getExtensions().getExtension(oid);
	
	        if (extension == null)
	        {
	            throw new NullPointerException("extension " + oid + " not present");
	        }
	
	        extGenerator.addExtension(oid, isCritical, extension.getValue().getOctets());
	
	        return this;
	    }
	
	    /**
	     * Generate an X.509 certificate, based on the current issuer and subject
	     * using the passed in signer.
	     *
	     * @param signer the content signer to be used to generate the signature validating the certificate.
	     * @return a holder containing the resulting signed certificate.
	     */
	    public X509CertificateHolder build(
	        ContentSigner signer)
	    {
	        tbsGen.setSignature(signer.getAlgorithmIdentifier());
	
	        if (!extGenerator.isEmpty())
	        {
	            tbsGen.setExtensions(extGenerator.generate());
	        }
	        TBSCertificateStructure tbsCert = tbsGen.generateTBSCertificate();
	        try {
				return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCert)));
			} catch (IOException e) {
				throw new IllegalStateException("cannot produce certificate signature");
			}
	      
	    }
	    
	    private byte[] generateSig(ContentSigner signer, ASN1Encodable tbsObj) throws IOException   {
	            OutputStream sOut = signer.getOutputStream();

	            sOut.write(tbsObj.getDEREncoded());

	            sOut.close();

	            return signer.getSignature();
	        }

        private X509CertificateStructure generateStructure(TBSCertificateStructure tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature) {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(tbsCert);
            v.add(sigAlgId);
            v.add(new DERBitString(signature));

            return X509CertificateStructure.getInstance(new DERSequence(v));
        }
	}
	
    /**
     * FIXME:
	 * This class is a copy of {@link PKCS10CertificationRequestBuilder}. The modification is in the constructor in order to
	 * fill the Subject and Issuer using a {@link X509Principal} instead of a {@link X500Name}. The hash produced server
	 * side is different in both cases (i.e: MyProxy server).
	 */
	public class MyPKCS10CertificationRequestBuilder
	{
	    private SubjectPublicKeyInfo publicKeyInfo;
	    private X500Name subject;
	    private List<Attribute> attributes = new ArrayList<Attribute>();

	    /**
	     * Basic constructor.
	     *
	     * @param subject the X.500 Name defining the certificate subject this request is for.
	     * @param publicKeyInfo the info structure for the public key to be associated with this subject.
	     */
	    public MyPKCS10CertificationRequestBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
	    {
	        this.subject = subject;
	        this.publicKeyInfo = publicKeyInfo;
	    }

	    /**
	     * Add an attribute to the certification request we are building.
	     *
	     * @param attrType the OID giving the type of the attribute.
	     * @param attrValue the ASN.1 structure that forms the value of the attribute.
	     * @return this builder object.
	     */
	    public MyPKCS10CertificationRequestBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
	    {
	        attributes.add(new Attribute(attrType, new DERSet(attrValue)));

	        return this;
	    }

	    /**
	     * Add an attribute with multiple values to the certification request we are building.
	     *
	     * @param attrType the OID giving the type of the attribute.
	     * @param attrValues an array of ASN.1 structures that form the value of the attribute.
	     * @return this builder object.
	     */
	    public MyPKCS10CertificationRequestBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable[] attrValues)
	    {
	        attributes.add(new Attribute(attrType, new DERSet(attrValues)));

	        return this;
	    }

	    /**
	     * Generate an PKCS#10 request based on the past in signer.
	     *
	     * @param signer the content signer to be used to generate the signature validating the certificate.
	     * @return a holder containing the resulting PKCS#10 certification request.
	     */
	    public PKCS10CertificationRequestHolder build(
	        ContentSigner signer)
	    {
	        CertificationRequestInfo info;

	        //---- MODIF ---
	        X500Principal originalSubject = new X500Principal(subject.toString());
	        X509Principal x509NameSubject = null;
			try {
				x509NameSubject = new X509Principal(originalSubject.getEncoded());
			} catch (IOException e) {
				throw new IllegalStateException("cannot construct certificate x509NameSubject");
			}
			//---- END MODIF ---
	        
	        if (attributes.isEmpty())
	        {
	            info = new CertificationRequestInfo(x509NameSubject, publicKeyInfo, null);
	        }
	        else
	        {
	            ASN1EncodableVector v = new ASN1EncodableVector();

	            for (Iterator<Attribute> it = attributes.iterator(); it.hasNext();)
	            {
	                v.add(Attribute.getInstance(it.next()));
	            }

	            info = new CertificationRequestInfo(x509NameSubject, publicKeyInfo, new DERSet(v));
	        }

	        try
	        {
	            OutputStream sOut = signer.getOutputStream();

	            sOut.write(info.getDEREncoded());

	            sOut.close();

	            return new PKCS10CertificationRequestHolder(new CertificationRequest(info, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature())));
	        }
	        catch (IOException e)
	        {
	            throw new IllegalStateException("cannot produce certification request signature");
	        }
	    }
	}

}
