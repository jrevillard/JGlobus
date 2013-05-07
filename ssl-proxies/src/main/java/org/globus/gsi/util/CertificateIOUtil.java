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

import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Fill Me
 */
public final class CertificateIOUtil {
	private static Log logger = LogFactory.getLog(CertificateIOUtil.class.getCanonicalName());
	
	private static MessageDigest md5;

    private CertificateIOUtil() {
        //This should not be instantiated
    }
	
    private static void init() {
        if (md5 == null) {
            try {
                md5 = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                logger.error("", e);
            }
        }
    }

    /**
     * Returns equivalent of:
     * openssl x509 -in "cert-file" -hash -noout
     *
     * @param subjectDN
     * @return hash for certificate names
     */
    public static String nameHash(X500Principal subjectDN) {
        try {
            return hash(encodePrincipal(subjectDN));
        } catch (Exception e) {
            logger.error("", e);
            return null;
        }
    }

    /**
     * Returns equivalent of: openssl x509 -in "cert-file" -hash -noout
     *
     * @param subjectDN
     * @return hash for certificate names
     */
    public static String nameHash(X500Name subjectDN) {
        try {
            return hash(encodePrincipal(subjectDN));
        } catch (Exception e) {
            logger.error("", e);
            return null;
        }
    }

    public static byte[] encodePrincipal(X500Principal subject) throws IOException {
        return subject.getEncoded();
    }

    public static byte[] encodePrincipal(X500Name subject) throws IOException {
        return subject.getDEREncoded();
    }

    private synchronized static String hash(byte[] data) {
        init();
        if (md5 == null) {
            return null;
        }

        md5.reset();
        md5.update(data);

        byte[] md = md5.digest();

        long ret = (fixByte(md[0]) | (fixByte(md[1]) << 8L));
        ret = ret | fixByte(md[2]) << 16L;
        ret = ret | fixByte(md[3]) << 24L;
        ret = ret & 0xffffffffL;

        return Long.toHexString(ret);
    }
    
    private static long fixByte(byte b) {
        return (b < 0) ? (long) (b + 256) : (long) b;
    }

	/**
	 * Writes certificate to the specified file in PEM format.
	 * 
	 */
	public static void writeCertificate(X509Certificate cert, File path) throws IOException {
		writeCertificate(cert, new FileOutputStream(path));
	}

	/**
	 * Writes certificate to the specified output stream in PEM format (closes the Stream).
	 * 
	 */
	public static void writeCertificate(X509Certificate cert, OutputStream out) throws IOException {
		writeCertificate(cert, out, true);
	}
	
	/**
	 * Writes certificate to the specified output stream in PEM format.
	 * 
	 */
	public static void writeCertificate(X509Certificate cert, OutputStream out, boolean closeTheStream) throws IOException {
		if (!closeTheStream) {
			write(new NotClosableOutputStream(out), cert);
		} else {
			write(out, cert);
		}
	}
	
	/**
	 * Writes certificate chain to the specified file in PEM format.
	 * 
	 */
	public static void writeCertificateChain(X509Certificate[] certChain, File path) throws IOException {
		writeCertificateChain(certChain, new FileOutputStream(path));
	}

	/**
	 * Writes certificate chain to the specified output stream in PEM format (closes the Stream).
	 * 
	 */
	public static void writeCertificateChain(X509Certificate[] certChain, OutputStream out) throws IOException {
		writeCertificateChain(certChain, out, true);
	}
	
	/**
	 * Writes certificate chain to the specified output stream in PEM format.
	 * 
	 */
	public static void writeCertificateChain(X509Certificate[] certChain, OutputStream out, boolean closeTheStream) throws IOException {
		if (!closeTheStream) {
			write(new NotClosableOutputStream(out), null, certChain, true);
		} else {
			write(out, null, certChain, true);
		}
	}

	/**
	 * Writes private key to the specified file in PEM format.
	 * 
	 */
	public static void writePrivateKey(PrivateKey privateKey, File path) throws IOException {
		writePrivateKey(privateKey, new FileOutputStream(path));
	}

	/**
	 * Writes private key to the specified output stream in PEM format (closes the Stream).
	 * 
	 */
	public static void writePrivateKey(PrivateKey privateKey, OutputStream out) throws IOException {
		writePrivateKey(privateKey, out, true);
	}
	
	/**
	 * Writes private key to the specified output stream in PEM format.
	 * 
	 */
	public static void writePrivateKey(PrivateKey privateKey, OutputStream out, boolean closeTheStream) throws IOException {
		if (!closeTheStream) {
			write(new NotClosableOutputStream(out), privateKey, null, true);
		} else {
			write(out, privateKey, null, true);
		}
	}

	/**
	 * Writes certificate chain and private key to the specified output stream in PEM format. (Close the stream)
	 * 
	 */
	public static void writeCertificateChainAndPrivateKey(PrivateKey privateKey, X509Certificate[] certChain,
			OutputStream out) throws IOException {
		writeCertificateChainAndPrivateKey(privateKey, certChain, out, true);
	}

	/**
	 * Writes certificate chain and private key to the specified output stream in PEM format.
	 * 
	 */
	public static void writeCertificateChainAndPrivateKey(PrivateKey privateKey, X509Certificate[] certChain,
			OutputStream out, boolean closeTheStream) throws IOException {
		if (!closeTheStream) {
			write(new NotClosableOutputStream(out), privateKey, certChain, true);
		} else {
			write(out, privateKey, certChain, true);
		}
	}
	
	private static void write(OutputStream out, X509Certificate cert) throws IOException {
		PEMWriter pemWriter = null;
		try {
			pemWriter = new PEMWriter(new OutputStreamWriter(out));
			pemWriter.writeObject(cert);
			pemWriter.flush();
		} finally {
			if (pemWriter != null) {
				pemWriter.close();
			}
		}	
	}

	private static void write(OutputStream out, PrivateKey privateKey, X509Certificate[] certChain,
			boolean skipSelfSigned) throws IOException {
		PEMWriter pemWriter = null;
		try {
			pemWriter = new PEMWriter(new OutputStreamWriter(out));
			if (certChain != null) {
				pemWriter.writeObject(certChain[0]);
			}
			if (privateKey != null) {
				pemWriter.writeObject(privateKey);
			}
			if (certChain != null) {
				for (int i = 1; i < certChain.length; i++) {
					// This will skip the self-signed certificates?
					if (!skipSelfSigned) {
						if (certChain[i].getSubjectX500Principal().equals(certChain[i].getIssuerX500Principal())) {
							continue;
						}
					}
					pemWriter.writeObject(certChain[i]);
				}
			}
			pemWriter.flush();
		} finally {
			if (pemWriter != null) {
				pemWriter.close();
			}
		}
	}

	private static class NotClosableOutputStream extends FilterOutputStream {

		public NotClosableOutputStream(OutputStream out) {
			super(out);
		}

		@Override
		public void close() throws IOException {
			// Do not close nor flush
		}
	}
}

