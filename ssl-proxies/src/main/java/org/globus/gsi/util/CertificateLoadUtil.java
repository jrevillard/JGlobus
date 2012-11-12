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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
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
        X509Certificate[] x509Certificates = readCertificates(reader);
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
        X509Certificate[] x509Certificates = readCertificates(reader);
        if(x509Certificates == null){
        	throw new GeneralSecurityException("No certificate data");
        }
        return x509Certificates;
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
        PrivateKey privateKey = readPrivateKey(reader, passwordFinder);
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
        PrivateKey privateKey = readPrivateKey(reader, passwordFinder);
        if(privateKey == null){
        	throw new GeneralSecurityException("No private key data");
        }
        return privateKey;
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
    public static X509Certificate[] readCertificates(BufferedReader reader) throws IOException {
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
    public static PrivateKey readPrivateKey(BufferedReader reader, PasswordFinder passwordFinder) throws IOException {
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
