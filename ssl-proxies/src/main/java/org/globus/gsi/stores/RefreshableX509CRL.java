package org.globus.gsi.stores;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Set;


/**
 * @author Jerome Revillard
 *
 */
public class RefreshableX509CRL extends X509CRL{
	private final ResourceCRL resourceCRL;
	private X509CRL x509crl;
	
	public RefreshableX509CRL(ResourceCRL resourceCRL, X509CRL x509crl) {
		this.resourceCRL = resourceCRL;
		this.x509crl = x509crl;
	}
	
	private void refresh() throws CRLException{
		//Refresh the CRL if needed
		try {
			this.x509crl = resourceCRL.getSecurityObject().x509crl;
		} catch (ResourceStoreException e) {
			throw new CRLException(e);
		}
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509Extension#hasUnsupportedCriticalExtension()
	 */
	public boolean hasUnsupportedCriticalExtension() {
		return x509crl.hasUnsupportedCriticalExtension();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509Extension#getCriticalExtensionOIDs()
	 */
	public Set<String> getCriticalExtensionOIDs() {
		return x509crl.getCriticalExtensionOIDs();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509Extension#getNonCriticalExtensionOIDs()
	 */
	public Set<String> getNonCriticalExtensionOIDs() {
		return x509crl.getNonCriticalExtensionOIDs();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509Extension#getExtensionValue(java.lang.String)
	 */
	public byte[] getExtensionValue(String oid) {
		return x509crl.getExtensionValue(oid);
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getEncoded()
	 */
	@Override
	public byte[] getEncoded() throws CRLException {
		refresh();
		return x509crl.getEncoded();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#verify(java.security.PublicKey)
	 */
	@Override
	public void verify(PublicKey key) throws CRLException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		refresh();
		x509crl.verify(key);
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#verify(java.security.PublicKey, java.lang.String)
	 */
	@Override
	public void verify(PublicKey key, String sigProvider) throws CRLException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException, SignatureException {
		refresh();
		x509crl.verify(key, sigProvider);
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getVersion()
	 */
	@Override
	public int getVersion() {
		return x509crl.getVersion();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getIssuerDN()
	 */
	@Override
	public Principal getIssuerDN() {
		return x509crl.getIssuerDN();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getThisUpdate()
	 */
	@Override
	public Date getThisUpdate() {
		return x509crl.getThisUpdate();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getNextUpdate()
	 */
	@Override
	public Date getNextUpdate() {
		return x509crl.getNextUpdate();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getRevokedCertificate(java.math.BigInteger)
	 */
	@Override
	public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
		return x509crl.getRevokedCertificate(serialNumber);
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getRevokedCertificates()
	 */
	@Override
	public Set<? extends X509CRLEntry> getRevokedCertificates() {
		return x509crl.getRevokedCertificates();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getTBSCertList()
	 */
	@Override
	public byte[] getTBSCertList() throws CRLException {
		refresh();
		return x509crl.getTBSCertList();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getSignature()
	 */
	@Override
	public byte[] getSignature() {
		return x509crl.getSignature();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getSigAlgName()
	 */
	@Override
	public String getSigAlgName() {
		return x509crl.getSigAlgName();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getSigAlgOID()
	 */
	@Override
	public String getSigAlgOID() {
		return x509crl.getSigAlgOID();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.X509CRL#getSigAlgParams()
	 */
	@Override
	public byte[] getSigAlgParams() {
		return x509crl.getSigAlgParams();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.CRL#toString()
	 */
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return x509crl.toString();
	}

	/* (non-Javadoc)
	 * @see java.security.cert.CRL#isRevoked(java.security.cert.Certificate)
	 */
	@Override
	public boolean isRevoked(Certificate cert) {
		return x509crl.isRevoked(cert);
	}
}
