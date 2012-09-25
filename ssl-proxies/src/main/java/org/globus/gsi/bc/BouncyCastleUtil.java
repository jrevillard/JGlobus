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
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.gsi.GSIConstants.CertificateType;
import org.globus.gsi.util.CertificateUtil;
import org.globus.gsi.util.ProxyCertificateUtil;
import org.globus.util.I18n;

// COMMENT: BCB: removed methods createCertificateType(...) that took a TBSCertificateStructure as parameter
/**
 * A collection of various utility functions.
 */
public class BouncyCastleUtil {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static I18n i18n = I18n.getI18n("org.globus.gsi.errors", BouncyCastleUtil.class.getClassLoader());

	/**
	 * Converts the DER-encoded byte array into a <code>DERObject</code>.
	 * 
	 * @param data
	 *            the DER-encoded byte array to convert.
	 * @return the DERObject.
	 * @exception IOException
	 *                if conversion fails
	 */
	public static ASN1Primitive toDERObject(byte[] data) throws IOException {
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream derInputStream = new ASN1InputStream(inStream);
		return derInputStream.readObject();
	}
	
	/**
	 * Extracts the value of a certificate extension.
	 * 
	 * @param ext
	 *            the certificate extension to extract the value from.
	 * @exception IOException
	 *                if extraction fails.
	 */
	public static ASN1Primitive getExtensionObject(Extension ext) {
		return ext.getParsedValue().toASN1Primitive();
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

		String subjectDN = cert.getSubjectX500Principal().getName();
		X500Name name = new X500Name(GlobusStyle.INSTANCE,subjectDN);
		return name.toString();
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
}
