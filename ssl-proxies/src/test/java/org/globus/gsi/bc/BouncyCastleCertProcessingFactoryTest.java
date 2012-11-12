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
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.globus.gsi.GSIConstants.CertificateType;
import org.globus.gsi.X509Credential;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.ProxyPolicy;

public class BouncyCastleCertProcessingFactoryTest extends TestCase {

    private String proxyFile = "validatorTest/gsi2fullproxy.pem";
    
    public static BouncyCastleCertProcessingFactory factory = 
    BouncyCastleCertProcessingFactory.getDefault();

    public BouncyCastleCertProcessingFactoryTest(String name) {
    super(name);
    }
    
    public static void main (String[] args) {
    junit.textui.TestRunner.run (suite());
    }

    public static Test suite() {
    return new TestSuite(BouncyCastleCertProcessingFactoryTest.class);
    }
    
    public void testResctrictedNoProxyCertInfoExt() throws Exception {
    
    ClassLoader loader = BouncyCastleCertProcessingFactoryTest.class.getClassLoader();
    X509Credential cred = new X509Credential(loader.getResource(proxyFile).getPath());
    
    try {
        factory.createCredential(cred.getCertificateChain(),
                     cred.getPrivateKey(),
                     512,
                     60 * 60,
                     CertificateType.GSI_3_RESTRICTED_PROXY,
                     (X509Extensions)null,
                     null);
        fail("Expected to fail");
    } catch (IllegalArgumentException e) {
        // that's what we expected
    }
    }

    public void testResctrictedWithOtherExt() throws Exception {

    ClassLoader loader = BouncyCastleCertProcessingFactoryTest.class.getClassLoader();
    X509Credential cred = new X509Credential(loader.getResource(proxyFile).getPath());

    X509Extension ext = null;
    
    String oid = "1.2.3.4";
    String expectedValue = "foo";
    boolean critical = false;

    String policyOid = "1.2.3.4.5.6.7.8.9";
    String policyValue = "bar";
    
    Hashtable<DERObjectIdentifier,X509Extension> hashExtensions = new Hashtable<DERObjectIdentifier, X509Extension>();
    ext = new X509Extension(critical, new DEROctetString(new DERUTF8String(expectedValue)));
    hashExtensions.put(new ASN1ObjectIdentifier(oid), ext);

    ext = new X509Extension(false,  new DEROctetString(new BasicConstraints(15).getEncoded()));
    hashExtensions.put(X509Extension.basicConstraints, ext);
    
    ProxyPolicy policy = new ProxyPolicy(policyOid, policyValue.getBytes());
    ext = new ProxyCertInfoExtension(new ProxyCertInfo(policy));
    hashExtensions.put(ProxyCertInfo.OID, ext);
    
    
    X509Extensions extSet = new X509Extensions(hashExtensions);
    
    X509Credential newCred = 
        factory.createCredential(cred.getCertificateChain(),
                     cred.getPrivateKey(),
                     512,
                     60 * 60,
                     CertificateType.GSI_3_RESTRICTED_PROXY,
                     extSet,
                     null);
    
    X509Certificate newCert = newCred.getCertificateChain()[0];
    verifyExtension(newCert, oid, expectedValue, critical);
    
    byte [] realValue = newCert.getExtensionValue(ProxyCertInfo.OID.getId());
    assertTrue(realValue != null && realValue.length > 0);

    ProxyCertInfo proxyCertInfo = ProxyCertInfo.getInstance(realValue);
    
    assertTrue(proxyCertInfo != null);
    assertTrue(proxyCertInfo.getProxyPolicy() != null);
    assertEquals(policyOid, 
             proxyCertInfo.getProxyPolicy().getPolicyLanguage().getId());
    assertEquals(policyValue,
             proxyCertInfo.getProxyPolicy().getPolicyAsString());
    }

    public void testExtensions() throws Exception {
    
    ClassLoader loader = BouncyCastleCertProcessingFactoryTest.class.getClassLoader();
    X509Credential cred = new X509Credential(loader.getResource(proxyFile).getFile());
    X509Extension ext = null;
    
    String oid1 = "1.2.3.4";
    String expectedValue1 = "foo";
    boolean critical1 = false;
    
    // COMMENT Used to be 5.6.7.8. Didn't work with newer bouncy castle version
    String oid2 = "1.2.3.5";
    String expectedValue2 = "bar";
    boolean critical2 = true;
    
    Hashtable<DERObjectIdentifier,X509Extension> hashExtensions = new Hashtable<DERObjectIdentifier, X509Extension>();
    ext = new X509Extension(critical1, new DEROctetString(new DERUTF8String(expectedValue1).getEncoded()));
    hashExtensions.put(new ASN1ObjectIdentifier(oid1), ext);
    ext = new X509Extension(critical2, new DEROctetString(new DERUTF8String(expectedValue2).getEncoded()));
    hashExtensions.put(new ASN1ObjectIdentifier(oid2), ext);
    
    X509Extensions extSet = new X509Extensions(hashExtensions);

    X509Credential newCred = 
        factory.createCredential(cred.getCertificateChain(),
                     cred.getPrivateKey(),
                     512,
                     60 * 60,
                     CertificateType.GSI_3_IMPERSONATION_PROXY,
                     extSet,
                     null);

    X509Certificate newCert = newCred.getCertificateChain()[0];

    verifyExtension(newCert, oid1, expectedValue1, critical1);
    verifyExtension(newCert, oid2, expectedValue2, critical2);
    }

    private void verifyExtension(X509Certificate cert, 
                 String oid,
                 String expectedValue,
                 boolean critical) throws Exception {
    byte [] realValue = cert.getExtensionValue(oid);
    
    assertTrue(realValue != null && realValue.length > 0);

    DEROctetString derOctetString = (DEROctetString) toASN1Object(realValue);
    DERUTF8String derutf8String = (DERUTF8String) toASN1Object(derOctetString.getOctets());
	
    assertEquals(expectedValue, derutf8String.getString());

    Set<String> exts = null;
    if (critical) {
        exts = cert.getCriticalExtensionOIDs();
    } else {
        exts = cert.getNonCriticalExtensionOIDs();
    }
    
    assertTrue(exts.contains(oid));
    }
    
    private static DERObject toASN1Object(byte[] data) throws IOException {
        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream DIS = new ASN1InputStream(inStream);
        try{
        	return DIS.readObject();
        }finally{
        	DIS.close();
        }
    }
}

