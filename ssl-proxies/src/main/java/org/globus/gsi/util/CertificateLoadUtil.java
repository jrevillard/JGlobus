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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.globus.gsi.X509Credential;

/**
 * Contains various security-related utility methods.
 */
public final class CertificateLoadUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
        logger = LogFactory.getLog(CertificateLoadUtil.class.getCanonicalName());
        setProvider("BC");
    }

    private static Log logger;
    private static String provider;

    private CertificateLoadUtil() {
        //This should not be created.
    }

    /**
     * A no-op function that can be used to force the class to load and
     * initialize.
     */
    public static void init() {
    }

    /**
     * Sets a provider name to use for loading certificates and for generating
     * key pairs.
     *
     * @param providerName provider name to use.
     */
    public static void setProvider(String providerName) {
        provider = providerName;
        logger.debug("Provider set to : " + providerName);
    }

    /**
     * Returns appropriate <code>CertificateFactory</code>. If <I>provider</I>
     * was set a provider-specific <code>CertificateFactory</code> will be used.
     * Otherwise, a default <code>CertificateFactory</code> will be used.
     *
     * @return <code>CertificateFactory</code>
     */
    protected static CertificateFactory getCertificateFactory()
            throws GeneralSecurityException {
        if (provider == null) {
            return CertificateFactory.getInstance("X.509");
        } else {
            return CertificateFactory.getInstance("X.509", provider);
        }
    }

    /**
     * Loads a X509 certificate from the specified input stream. Input stream
     * must contain DER-encoded certificate.
     *
     * @param in the input stream to read the certificate from.
     * @return <code>X509Certificate</code> the loaded certificate.
     * @throws GeneralSecurityException if certificate failed to load.
     */
    public static X509Certificate loadCertificate(InputStream in)
            throws GeneralSecurityException {
        return (X509Certificate) getCertificateFactory().generateCertificate(in);
    }

    /**
     * Loads multiple X.509 certificates from the specified file.
     *
     * @param file the certificate file to load the certificate from.
     * @return an array of certificates loaded from the file.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate[] loadCertificates(String file) throws IOException, GeneralSecurityException {

        if (file == null) {
            throw new IllegalArgumentException("Certificate file is null");
        }
        BufferedReader reader = new BufferedReader(new FileReader(file));
        X509Certificate[] x509Certificates = loadCertificates(reader);
        if(x509Certificates == null){
        	throw new GeneralSecurityException("No certificate data");
        }
        return x509Certificates;
    }
    
    /**
     * Loads multiple X.509 certificates from the specified stream.
     *
     * @param inputStream the inputStream to load the certificate from.
     * @param closeStream if <code>false</code>, the stream will not be closed.
     * @return an array of certificates loaded from the file.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static X509Certificate[] loadCertificates(InputStream inputStream, boolean closeStream) throws IOException, GeneralSecurityException {

        if (inputStream == null) {
            throw new IllegalArgumentException("Certificate InputStream is null");
        }
        if(!closeStream){
        	inputStream = new NotClosableInputStream(inputStream);
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        X509Certificate[] x509Certificates = loadCertificates(reader);
        if(x509Certificates == null){
        	throw new GeneralSecurityException("No certificate data");
        }
        return x509Certificates;
    }

    /**
     * Loads the PEM certificates from the specified reader.
     * <p/>
     * This function does close the input reader.
     *
     * @param reader the stream from which load the certificate.
     * @return the loaded certificate or null if there was no data in the
     *         reader or the reader is closed.
     * @throws IOException              if I/O error occurs
     */
    public static X509Certificate[] loadCertificates(BufferedReader reader) throws IOException {
    	if (reader == null) {
			throw new IllegalArgumentException("The reader must not be null.");
		}
    	MyPEMReader pemReader = null;
    	try {
	    	if(!reader.ready()){
	    		//No data;
	    		return null;
	    	}
			pemReader = new MyPEMReader(reader);
			Object pemObject = null;
			ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>(3);
			while ((pemObject = pemReader.readObject()) != null) {
				if(pemObject instanceof X509Certificate){
					certificates.add((X509Certificate)pemObject);
				}
			}
			if(!certificates.isEmpty()){
				return certificates.toArray(new X509Certificate[certificates.size()]);
			}
		}finally{
			if(pemReader != null){
				try{
					pemReader.close();
				}catch (IOException e) {}
			}
		}
    	throw new IOException("Certificate not well formatted");
    }
    
    /**
     * Loads a Java KeyStore from the specified file and return an {@link X509Credential} from it.
     * <p/>
     * This function does close the input stream.
     * 
     * @param keystorePath the Keytore path.
     * @param storePasswd keystore password (can be <code>null</code>)
     * @param keyPasswd private key password (can be <code>null</code>)
     * @param keyAlias private key alias or <code>null</code>. In case of <code>null</code>, alias will be autodetected,
	 * however this will work only it the keystore contains exactly one key entry.
     * @param type type of the keystore, "JKS" or "PKCS12". <code>null</code> value is forbidden,
     * @return The {@link X509Credential} loaded from the Keystore.
     * @throws IOException if the keystore can not be read
     * @throws KeyStoreException if the keystore can not be parsed or if passwords are incorrect
     */
    public static X509Credential loadKeystore(String keystorePath, char[] storePasswd, char[] keyPasswd, String keyAlias, String type) throws IOException, KeyStoreException {
    	InputStream inputStream = new BufferedInputStream(new FileInputStream(keystorePath));
    	return loadKeystore(inputStream, storePasswd, keyPasswd, keyAlias, type);
    }

    /**
     * Loads a Java KeyStore from the specified input stream and return an {@link X509Credential} from it.
     * <p/>
     * This function does close the input stream.
     * 
     * @param inputStream the stream from which load the Keytore.
     * @param storePasswd keystore password (can be <code>null</code>)
     * @param keyPasswd private key password (can be <code>null</code>)
     * @param keyAlias private key alias or <code>null</code>. In case of <code>null</code>, alias will be autodetected,
	 * however this will work only it the keystore contains exactly one key entry.
     * @param type type of the keystore, "JKS" or "PKCS12". <code>null</code> value is forbidden,
     * @return The {@link X509Credential} loaded from the Keystore.
     * @throws IOException if the keystore can not be read
     * @throws KeyStoreException if the keystore can not be parsed or if passwords are incorrect
     */
    public static X509Credential loadKeystore(InputStream inputStream, char[] storePasswd, char[] keyPasswd, String keyAlias, String type) throws IOException, KeyStoreException {
    	if (inputStream == null) {
			throw new IllegalArgumentException("The inputStream must not be null.");
		}
    	if (type == null) {
			throw new IllegalArgumentException("The Keystore type must not be null: PKCS12 or JKS");
		}
    	try{
    		KeyStore ks;
	    	if (type.equalsIgnoreCase("PKCS12")){
				try {
					ks = KeyStore.getInstance(type, BouncyCastleProvider.PROVIDER_NAME);
				} catch (NoSuchProviderException e) {
					throw new IllegalStateException("Bouncy Castle provider is not available :BUG!", e);
				}
	    	}else{
				ks = KeyStore.getInstance(type);
	    	}
	    	ks.load(inputStream, storePasswd);
	    	if(keyAlias == null){
		    	Enumeration<String> aliases = ks.aliases();
				String ret = null;
				while (aliases.hasMoreElements()){
					String alias = aliases.nextElement();
					if (ks.isKeyEntry(alias)){
						if (ret == null){
							ret = alias;
						}else{
							throw new KeyStoreException("Key alias was not " +
									"provided and the keystore contains more then one key entry: " 
									+ alias + " and " + ret + " at least.");
						}
					}
				}
				if (ret == null){
					throw new KeyStoreException("The keystore doesn't contain any key entry");
				}
				keyAlias = ret;
	    	}else{
	    		if (!ks.containsAlias(keyAlias)){
	    			throw new KeyStoreException("Key alias '" + keyAlias + "' does not exist in the keystore");
	    		}
	    	}
	    	
    		Key key = ks.getKey(keyAlias, keyPasswd);
			if (key == null){
				throw new KeyStoreException("Key alias '" + keyAlias + "' is not an alias of a key entry, but an alias of a certificate entry");
			}
			if (!(key instanceof PrivateKey)){
				throw new KeyStoreException("Key under the alias '" + keyAlias + "' is not a PrivateKey but " + key.getClass());
			}
			PrivateKey privateKey = (PrivateKey) key;
	    	
			Certificate[] certificates = ks.getCertificateChain(keyAlias);
			if (certificates == null){
				throw new KeyStoreException("There is no certificate associated with the private for the alias '" + keyAlias + "'");
			}
			X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
			for (int i = 0; i < x509Certificates.length; i++) {
				x509Certificates[i] = (X509Certificate) certificates[i];
			}
			return new X509Credential(privateKey, x509Certificates);
	    } catch (UnrecoverableKeyException e){
			throw new KeyStoreException("Key's password seems to be incorrect", e);
		} catch (NoSuchAlgorithmException e){
			throw new KeyStoreException("Key is encrypted or uses an unsupported algorithm", e);
		} catch (CertificateException e) {
			throw new KeyStoreException("Keystore certificate is invalid", e);
		} finally {
			inputStream.close();
		}
		
    }
    
    /**
     * Loads a private key from the specified file.
     *
     * @param file the private key file to load the private key from.
     * @param passwordFinder the password finder object which allows the {@link PEMReader} to decrypt the private key. (Can be null if not needed)
     * @return an array of certificates loaded from the file.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static PrivateKey loadPrivateKey(String file, PasswordFinder passwordFinder) throws IOException, GeneralSecurityException {
        if (file == null) {
            throw new IllegalArgumentException("Private Key file is null");
        }
        BufferedReader reader = new BufferedReader(new FileReader(file));
        PrivateKey privateKey = loadPrivateKey(reader, passwordFinder);
        if(privateKey == null){
        	throw new GeneralSecurityException("No private key data");
        }
        return privateKey;
    }
    
    /**
     * Loads a private key from the specified stream.
     *
     * @param file the private key file to load the private key from.
     * @param passwordFinder the password finder object which allows the {@link PEMReader} to decrypt the private key. (Can be null if not needed)
     * @param closeStream if <code>false</code>, the stream will not be closed.
     * @return an array of certificates loaded from the file.
     * @throws IOException              if I/O error occurs
     * @throws GeneralSecurityException if security problems occurs.
     */
    public static PrivateKey loadPrivateKey(InputStream inputStream, PasswordFinder passwordFinder, boolean closeStream) throws IOException, GeneralSecurityException {
        if (inputStream == null) {
            throw new IllegalArgumentException("Private Key Input Stream is null");
        }
        if(!closeStream){
        	inputStream = new NotClosableInputStream(inputStream);
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        PrivateKey privateKey = loadPrivateKey(reader, passwordFinder);
        if(privateKey == null){
        	throw new GeneralSecurityException("No private key data");
        }
        return privateKey;
    }
    
    /**
     * Loads the private key from the specified reader.
     * <p/>
     * This function does close the input reader.
     *
     * @param reader the stream from which load the certificate.
     * @param passwordFinder the password finder object which allows the {@link PEMReader} to decrypt the private key. (Can be null if not needed)
     * @return the loaded private key or null if there was no private key in the
     *         reader or the reader is closed.
     * @throws IOException              if I/O error occurs
     */
    public static PrivateKey loadPrivateKey(BufferedReader reader, PasswordFinder passwordFinder) throws IOException {
    	if (reader == null) {
			throw new IllegalArgumentException("The reader must not be null.");
		}
    	MyPEMReader pemReader = null;
		Object pemObject = null;
		try {
			if(!reader.ready()){
	    		//No data;
	    		return null;
	    	}
			pemReader = new MyPEMReader(reader, passwordFinder);
			while ((pemObject = pemReader.readObject()) != null) {
				if(pemObject instanceof KeyPair){
					return ((KeyPair)pemObject).getPrivate();
				}else if(pemObject instanceof PrivateKey){
					return (PrivateKey)pemObject;
				}
			}
		}finally{
			try{
				reader.close();
			}catch (IOException e) {}
			if(pemReader != null){
				try{
					pemReader.close();
				}catch (IOException e) {}
			}
		}
		throw new IOException("Private key not well formatted");
    }



    public static X509CRL loadCrl(String file) throws IOException, GeneralSecurityException {

        if (file == null) {
            throw new IllegalArgumentException("crlFileNull");
            //i18n.getMessage("crlFileNull"));
        }
        return loadCrl(new BufferedReader(new FileReader(file)));
    }

    public static X509CRL loadCrl(InputStream in) throws IOException, GeneralSecurityException {
    	return loadCrl(new BufferedReader(new InputStreamReader(in)));
    }
    
    private static X509CRL loadCrl(BufferedReader br) throws IOException, GeneralSecurityException{
    	MyPEMReader pemReader = null;
		Object pemObject = null;
		try {
			pemReader = new MyPEMReader(br);
			pemObject = pemReader.readObject();
			if(pemObject instanceof X509CRL){
				return (X509CRL)pemObject;
			}else if(pemObject instanceof CRL){
				throw new IllegalArgumentException("The provided input stream is a CRL but for the moment only X509CRL are accepted");
			}
		}finally{
			if(pemReader != null){
				try{
					pemReader.close();
				}catch (IOException e) {}
			}
		}
		
		throw new GeneralSecurityException("noCrlsData");
        //i18n.getMessage("noCrlData"));
    }

    public static Collection<X509Certificate> getTrustedCertificates(KeyStore keyStore, X509CertSelector selector) throws KeyStoreException {

        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isCertificateEntry(alias)) {
                //XXX: If a specific impl of keystore requires refresh, this would be a good place to add it.
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Cert =
                            (X509Certificate) certificate;
                    if (selector == null) {
                        certificates.add(x509Cert);
                    } else if (selector.match(certificate)) {
                        certificates.add(x509Cert);
                    }
                }

            }
        }
        return certificates;
    }
    
    private static class NotClosableInputStream extends FilterInputStream {

		public NotClosableInputStream(InputStream in) {
			super(in);
		}

		@Override
		public void close() throws IOException {
			// Do not close nor flush
		}
	}
    
	/**
	 * Class copied from Bouncycastle 1.47 to replace the bugged version from Bouncycastle 1.46
	 * TODO: Remove it once update to JGlobus 1.47 or later done.
	 * @author Jerome Revillard
	 *
	 */
	private static class MyPEMReader extends PEMReader {
		private static final String BEGIN = "-----BEGIN ";
		private static final String END = "-----END ";

	    /**
	     * Create a new MyPEMReader
	     *
	     * @param reader the Reader
	     */
		public MyPEMReader(Reader reader) {
			super(reader);
		}
		
		/**
	     * Create a new MyPEMReader with a password finder
	     *
	     * @param reader  the Reader
	     * @param pFinder the password finder
	     */
	    public MyPEMReader(
	        Reader reader,
	        PasswordFinder pFinder){
	        super(reader, pFinder, "BC");
	    }

		public PemObject readPemObject() throws IOException {
			String line = readLine();

			while (line != null && !line.startsWith(BEGIN)) {
				line = readLine();
			}

			if (line != null) {
				line = line.substring(BEGIN.length());
				int index = line.indexOf('-');
				String type = line.substring(0, index);

				if (index > 0) {
					return loadObject(type);
				}
			}

			return null;
		}

		private PemObject loadObject(String type) throws IOException {
			String line;
			String endMarker = END + type;
			StringBuffer buf = new StringBuffer();
			List<PemHeader> headers = new ArrayList<PemHeader>();

			while ((line = readLine()) != null) {
				if (line.indexOf(":") >= 0) {
					int index = line.indexOf(':');
					String hdr = line.substring(0, index);
					String value = line.substring(index + 1).trim();

					headers.add(new PemHeader(hdr, value));

					continue;
				}

				if (line.indexOf(endMarker) != -1) {
					break;
				}

				buf.append(line.trim());
			}

			if (line == null) {
				throw new IOException(endMarker + " not found");
			}

			return new PemObject(type, headers, Base64.decode(buf.toString()));
		}
	}
}
