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
package org.globus.gsi;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PasswordException;
import org.bouncycastle.openssl.PasswordFinder;
import org.globus.common.CoGProperties;
import org.globus.gsi.GSIConstants.CertificateType;
import org.globus.gsi.bc.GlobusStyle;
import org.globus.gsi.stores.ResourceSigningPolicyStore;
import org.globus.gsi.stores.Stores;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;
import org.globus.gsi.util.CertificateIOUtil;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;

/**
 * FILL ME
 * <p/>
 * This class equivalent was called GlobusCredential in CoG -maybe a better name?
 * 
 * @author ranantha@mcs.anl.gov
 */
// COMMENT: Added methods from GlobusCredential
// COMMENT: Do we need the getDefaultCred functionality?
public class X509Credential implements Serializable {

	private static final long serialVersionUID = 1L;
	private static Log logger = LogFactory.getLog(X509Credential.class.getCanonicalName());
    private PrivateKey privateKey;
    private final String privateKeyFile;
    private X509Certificate[] certChain;

    
    private static X509Credential defaultCred;
    private static long credentialLastModified = -1;
    // indicates if default credential was explicitely set
    // and if so - if the credential expired it try
    // to load the proxy from a file.
    private static boolean credentialSet = false;
    private static File credentialFile = null;

    static {
        new ProviderLoader();
    }

    public X509Credential(PrivateKey initKey, X509Certificate[] initCertChain) {

        if (initKey == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        if ((initCertChain == null) || (initCertChain.length < 1)) {
            throw new IllegalArgumentException("At least one public certificate required");
        }

        this.certChain = new X509Certificate[initCertChain.length];
        System.arraycopy(initCertChain, 0, this.certChain, 0, initCertChain.length);
        this.privateKey = initKey;
        this.privateKeyFile = null;
    }
    
    /**
     * Creates a {@link X509Credential} using the input streams. The private key must NOT be encrypted
     * @param in
     * @throws CredentialException
     */
    public X509Credential(InputStream certInputStream, InputStream keyInputStream) throws CredentialException {
    	try{
    		this.privateKey = CertificateLoadUtil.loadPrivateKey(keyInputStream, null, true);
    	} catch (IOException e) {
			throw new CredentialException("No Private Key found or Encrypted one",e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Private Key found", e);
		}
    	try {
			this.certChain = CertificateLoadUtil.loadCertificates(certInputStream, true);
		} catch (IOException e) {
			throw new CredentialException("No Certificate found", e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Certificate found", e);
		}
    	this.privateKeyFile = null;
    }
    
    public X509Credential(String certFile, String keyFile) throws CredentialException {
    	try {
			this.certChain = CertificateLoadUtil.loadCertificates(certFile);
		} catch (IOException e) {
			throw new CredentialException("No Certificate found", e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Certificate found", e);
		}
    	try{
    		this.privateKey = CertificateLoadUtil.loadPrivateKey(keyFile, null);
    	}catch (PasswordException e) {
			// Ok, the keystore needs a password, we will decrypt it later.
    	}catch (PEMException e) {
    		if("no PasswordFinder specified".equals(e.getMessage())){
    			// Ok, the keystore needs a password, we will decrypt it later.
    		}else{
    			throw new CredentialException("Cannot understand the private key format.", e);
    		}
		} catch (IOException e) {
			throw new CredentialException("No Private Key found", e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Private Key found", e);
		}
    	this.privateKeyFile = keyFile;
    }
    
    /**
     * Creates a {@link X509Credential} using an input stream. The private key must NOT be encrypted
     * @param in
     * @throws CredentialException
     */
    public X509Credential(InputStream in) throws CredentialException {
    	try{
    		if(!in.markSupported()){
    			in =  new BufferedInputStream(in);
        	}
    		in.mark(in.available());
    		this.privateKey = CertificateLoadUtil.loadPrivateKey(in, null, false);
    	} catch (IOException e) {
			throw new CredentialException("No Private Key found or Encrypted one",e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Private Key found", e);
		}
    	
    	try {
    		in.reset();
			this.certChain = CertificateLoadUtil.loadCertificates(in, true);
		} catch (IOException e) {
			throw new CredentialException("No Certificate found",e);
		} catch (GeneralSecurityException e) {
			throw new CredentialException("No Certificate found",e);
		}
    	this.privateKeyFile = null;
    }

    public X509Credential(String proxyFile) throws CredentialException {
    	this(proxyFile,proxyFile);
    }

    public X509Certificate[] getCertificateChain() {
        X509Certificate[] returnArray = new X509Certificate[this.certChain.length];
        System.arraycopy(this.certChain, 0, returnArray, 0, this.certChain.length);
        return returnArray;
    }

    public PrivateKey getPrivateKey() throws CredentialException {

        return getPrivateKey(null);
    }

    public PrivateKey getPrivateKey(final String password) throws CredentialException {
    	if(this.privateKey == null){
    		try {
				this.privateKey = CertificateLoadUtil.loadPrivateKey(privateKeyFile, new PasswordFinder() {
					
					public char[] getPassword() {
						if(password == null){
							return null;
						}
						return password.toCharArray();
					}
				});
			} catch (PasswordException e) {
				throw new CredentialException("Key encrypted, password required");
			} catch (IOException e) {
				throw new CredentialException(e.getMessage(), e);
			} catch (GeneralSecurityException e) {
				throw new CredentialException(e.getMessage(), e);
			}
    	}
        return this.privateKey;
    }

    public boolean isEncryptedKey() {
        return (this.privateKey == null);
    }

    /**
     * Save the certificate and the private key to provided output stream (Do NOT close the stream)
     */
    public void save(OutputStream out) throws IOException, CredentialException {
    	CertificateIOUtil.writeCertificateChainAndPrivateKey(getPrivateKey(), this.certChain, out, false);
    }

    public void writeToFile(File file) throws IOException, CredentialException {
        writeToFile(file, file);
    }

    public void writeToFile(File certFile, File keyFile) throws IOException, CredentialException {
    	if(certFile.equals(keyFile)){
    		save(new FileOutputStream(certFile));
    	}else{
    		CertificateIOUtil.writePrivateKey(getPrivateKey(), keyFile);
    		CertificateIOUtil.writeCertificateChain(certChain, certFile);
    	}
    }

    public Date getNotBefore() {
        Date notBefore = this.certChain[0].getNotBefore();
        for (int i = 1; i < this.certChain.length; i++) {
            Date date = this.certChain[i].getNotBefore();
            if (date.before(notBefore)) {
                notBefore = date;
            }
        }
        return notBefore;
    }

    /**
     * Returns the number of certificates in the credential without the self-signed certificates.
     * 
     * @return number of certificates without counting self-signed certificates
     */
    public int getCertNum() {
        for (int i = this.certChain.length - 1; i >= 0; i--) {
            if (!this.certChain[i].getSubjectX500Principal().equals(this.certChain[i].getIssuerX500Principal())) {
                return i + 1;
            }
        }
        return this.certChain.length;
    }

    /**
     * Returns strength of the private/public key in bits.
     * 
     * @return strength of the key in bits. Returns -1 if unable to determine it.
     */
    public int getStrength() throws CredentialException {
        return getStrength(null);
    }

    /**
     * Returns strength of the private/public key in bits.
     * 
     * @return strength of the key in bits. Returns -1 if unable to determine it.
     */
    public int getStrength(String password) throws CredentialException {
        getPrivateKey(password);
        if("RSA".equals(privateKey.getAlgorithm())){
        	return ((RSAPrivateKey)privateKey).getModulus().bitLength();      	
        }else if("DSA".equals(privateKey.getAlgorithm())){
        	return -1;
        }else{
        	return -2;
        }
    }

    /**
     * Returns the subject DN of the first certificate in the chain.
     * 
     * @return subject DN.
     */
    public String getSubject() {
        return GlobusStyle.INSTANCE.toString(new X500Name(this.certChain[0].getSubjectX500Principal().getName()));
    }

    /**
     * Returns the issuer DN of the first certificate in the chain.
     * 
     * @return issuer DN.
     */
    public String getIssuer() {
        return GlobusStyle.INSTANCE.toString(new X500Name(this.certChain[0].getIssuerX500Principal().getName()));
    }

    /**
     * Returns the certificate type of the first certificate in the chain. Returns -1 if unable to determine
     * the certificate type (an error occurred)
     * 
     * @see BouncyCastleUtil#getCertificateType(X509Certificate)
     * 
     * @return the type of first certificate in the chain. -1 if unable to determine the certificate type.
     */
    public CertificateType getProxyType() {
        try {
            return CertificateUtil.getCertificateType(this.certChain[0]);
        } catch (CertificateException e) {
            logger.error("Error getting certificate type.", e);
            return CertificateType.UNDEFINED;
		}
    }

    /**
     * Returns time left of this credential. The time left of the credential is based on the certificate with
     * the shortest validity time.
     * 
     * @return time left in seconds. Returns 0 if the certificate has expired.
     */
    public long getTimeLeft() {
        Date earliestTime = null;
        for (int i = 0; i < this.certChain.length; i++) {
            Date time = this.certChain[i].getNotAfter();
            if (earliestTime == null || time.before(earliestTime)) {
                earliestTime = time;
            }
        }
        long diff = (earliestTime.getTime() - System.currentTimeMillis()) / 1000;
        return (diff < 0) ? 0 : diff;
    }
    
    /**
     * Returns the identity of this credential. 
     * @see #getIdentityCertificate()
     *
     * @return The identity cert in Globus format (e.g. /C=US/..). Null,
     *         if unable to get the identity (an error occurred)
     */
    public String getIdentity() {
    try {
        return CertificateUtil.getIdentity(this.certChain);
    } catch (CertificateException e) {
            logger.debug("Error getting certificate identity.", e);
        return null;
    }
    }

    /**
     * Returns the identity certificate of this credential. The identity certificate is the first certificate
     * in the chain that is not an impersonation proxy certificate.
     * 
     * @return <code>X509Certificate</code> the identity cert. Null, if unable to get the identity certificate
     *         (an error occurred)
     */
    public X509Certificate getIdentityCertificate() {
        try {
            return CertificateUtil.getIdentityCertificate(this.certChain);
        } catch (CertificateException e) {
            logger.debug("Error getting certificate identity.", e);
            return null;
        }
    }

    /**
     * Returns the path length constraint. The shortest length in the chain of
     * certificates is returned as the credential's path length.
     *
     * @return The path length constraint of the credential. -1 is any error
     *         occurs.
     */
    public int getPathConstraint() {

        int pathLength = Integer.MAX_VALUE;
        try {
            for (int i=0; i<this.certChain.length; i++) {
                int length = ProxyCertificateUtil.getProxyPathConstraint(this.certChain[i]);
                // if length is one, then no proxy cert extension exists, so
                // path length is -1
                if (length == -1) {
                    length = Integer.MAX_VALUE;
                }
                if (length < pathLength) {
                    pathLength = length;
                }
            }
        } catch (Exception e) {
            logger.warn("Error retrieving path length.", e);
            pathLength = -1;
        }
        return pathLength;
    }
    
    /**
     * Verifies the validity of the credentials. All certificate path validation is performed using trusted
     * certificates in default locations.
     * 
     * @exception CredentialException
     *                if one of the certificates in the chain expired or if path validation fails.
     */
    public void verify() throws CredentialException {
    	verify(null);    	
    }
    	
    	
    /**
     * Verifies the validity of the credentials. 
     * 
     * @param caCertsLocation
     * 				The directory where to find the CA certificates. If <code>null</code>, path validation is performed using trusted
     * 				certificates in default locations.
     * @throws CredentialException
     * 				if one of the certificates in the chain expired or if path validation fails.
     */
    public void verify(String caCertsLocation) throws CredentialException {
        try {
        	if(caCertsLocation == null){
            	caCertsLocation = "file:" + CoGProperties.getDefault().getCaCertLocations();
        	}else{
        		caCertsLocation = "file:" + caCertsLocation;
        	}

            KeyStore keyStore = Stores.getTrustStore(caCertsLocation + "/" + Stores.getDefaultCAFilesPattern());
            CertStore crlStore = Stores.getCRLStore(caCertsLocation + "/" + Stores.getDefaultCRLFilesPattern()); 
            ResourceSigningPolicyStore sigPolStore = Stores.getSigningPolicyStore(caCertsLocation + "/" + Stores.getDefaultSigningPolicyFilesPattern());
            
            X509ProxyCertPathParameters parameters = new X509ProxyCertPathParameters(keyStore, crlStore, sigPolStore, false);
            X509ProxyCertPathValidator validator = new X509ProxyCertPathValidator();
            validator.engineValidate(CertificateUtil.getCertPath(certChain), parameters);
        } catch (Exception e) {
            throw new CredentialException(e);
        }
    }


    /**
     * Returns the default credential. The default credential is usually the user proxy certificate. <BR>
     * The credential will be loaded on the initial call. It must not be expired. All subsequent calls to this
     * function return cached credential object. Once the credential is cached, and the underlying file
     * changes, the credential will be reloaded.
     * 
     * @return the default credential.
     * @exception CredentialException
     *                if the credential expired or some other error with the credential.
     */
    public synchronized static X509Credential getDefaultCredential() throws CredentialException {
        if (defaultCred == null) {
            reloadDefaultCredential();
        } else if (!credentialSet) {
            if (credentialFile.lastModified() == credentialLastModified) {
                defaultCred.verify();
            } else {
                defaultCred = null;
                reloadDefaultCredential();
            }
        }
        return defaultCred;
    }

    private static void reloadDefaultCredential() 
        throws CredentialException {
        String proxyLocation = CoGProperties.getDefault().getProxyFile();
        defaultCred = new X509Credential(proxyLocation);
        credentialFile = new File(proxyLocation);
        credentialLastModified = credentialFile.lastModified();
        defaultCred.verify();
    }
    
    
    /**
     * Sets default credential.
     * 
     * @param cred
     *            the credential to set a default.
     */
    public synchronized static void setDefaultCredential(X509Credential cred) {
        defaultCred = cred;
        credentialSet = (cred != null);
    }

    // COMMENT: In case of an exception because of missing password with an 
    // encrypted key: put in -1 as strength
    public String toString() {
        String lineSep = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();
        buf.append("subject    : ").append(getSubject()).append(lineSep);
        buf.append("issuer     : ").append(getIssuer()).append(lineSep);
        int strength = -1;
        try {
            strength = this.getStrength();
        } catch(Exception e) {}
        buf.append("strength   : ").append(strength).append(lineSep);
        buf.append("timeleft   : ").append(getTimeLeft() + " sec").append(lineSep);
        buf.append("proxy type : ").append(ProxyCertificateUtil.getProxyTypeAsString(getProxyType()));
        return buf.toString();
    }
}
