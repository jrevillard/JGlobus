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
package org.globus.gsi.proxy.ext;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.globus.gsi.util.CertificateUtil;


/**
 * Proxy cert info extension class.
 * 
 * <pre>
 * ProxyCertInfoExtension ::= SEQUENCE { 
 *          pCPathLenConstraint    ProxyCertPathLengthConstraint OPTIONAL, 
 *          proxyPolicy            ProxyPolicy }
 *  
 *     ProxyCertPathLengthConstraint ::= INTEGER
 * </pre>
 * 
 * Inspired from the canl java library
 */
public class ProxyCertInfo extends ASN1Object
{
	/** The oid of the proxy cert info extension, defined in the RFC 3820. */
	public static final ASN1ObjectIdentifier RFC_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.14");

	/** The oid of the rfc draft proxy cert extension. */
	public static final ASN1ObjectIdentifier DRAFT_RFC_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.3536.1.222");

	/**
	 * The sub proxy path length, default is not limited.
	 */
	private int pathLen = Integer.MAX_VALUE;

	/**
	 * The underlying policy object.
	 */
	private ProxyPolicy policy;

	/**
	 * Generate new proxy certificate info extension with length limit len
	 * and policy policy. Use negative value if no limit is desired.
	 * 
	 * @param pathLen
	 *                the maximum number of proxy certificates to follow
	 *                this one. If Integer.MAX_VALUE is used then no limit will be set. 
	 * @param policy
	 *                the proxy policy extension.
	 */
	public ProxyCertInfo(int pathLen, ProxyPolicy policy)
	{
		this.pathLen = pathLen;
		this.policy = policy;
	}

	/**
	 * Generate a proxy that inherits all rights and that has no cert path
	 * length limitations.
	 */
	public ProxyCertInfo()
	{
		policy = new ProxyPolicy(ProxyPolicy.IMPERSONATION);
	}
	
	/**
	 * Generate a proxy that inherits policy rights and that has no cert path
	 * length limitations.
	 */
	public ProxyCertInfo(ProxyPolicy policy)
	{
		this.policy = policy;
	}

	/**
	 * Constructor that generates instance out of byte array.
	 * 
	 * @param bytes
	 *                The byte array to consider as the ASN.1 encoded
	 *                proxyCertInfo extension.
	 * @throws IOException
	 *                 thrown in case the parsing of the byte array fails.
	 */
	public ProxyCertInfo(byte[] bytes) throws IOException
	{
		this((ASN1Sequence) ASN1Primitive.fromByteArray(bytes));
	}

	/**
	 * Read a proxyCertInfoExtension from the ASN1 sequence.
	 * 
	 * @param seq
	 *                The sequence containing the extension.
	 * @throws IOException 
	 */
	public ProxyCertInfo(ASN1Sequence seq) throws IOException
	{
		int index = 0;

		if (seq == null || seq.size() == 0)
			throw new IOException("ProxyCertInfoExtension is empty");

		if (seq.getObjectAt(0) instanceof ASN1Integer)
		{
			pathLen = ((ASN1Integer) seq.getObjectAt(0)).getValue().intValue();
			index = 1;
		}
		if (seq.size() <= index)
			throw new IOException("ProxyCertInfoExtension parser error, expected policy, but it was not found");

		if (seq.getObjectAt(index) instanceof DLSequence)
		{
			policy = new ProxyPolicy((DLSequence)seq.getObjectAt(index));
		} else
		{
			throw new IOException("ProxyCertInfoExtension parser error, expected policy sequence, but got: "
					+ seq.getObjectAt(index).getClass());
		}

		index++;
		if (seq.size() > index)
			throw new IOException("ProxyCertInfoExtension parser error, sequence contains too many items");
	}


	/**
     * Returns an instance of <code>ProxyCertInfo</code> from given object.
     *
     * @param obj the object to create the instance from.
     * @return <code>ProxyCertInfo</code> instance.
     * @throws IllegalArgumentException if unable to convert the object to <code>ProxyCertInfo</code> instance.
     */
	public static ProxyCertInfo getInstance(Object obj) throws IOException
	{
		if (obj instanceof ProxyCertInfo) {
            return (ProxyCertInfo) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new ProxyCertInfo((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
            ASN1Primitive derObj;
            try {
                derObj = CertificateUtil.toASN1Primitive((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            if (derObj instanceof ASN1Sequence) {
                return new ProxyCertInfo((ASN1Sequence) derObj);
            }else if(derObj instanceof DEROctetString) {
            	ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(((DEROctetString)derObj).getOctets());
            	return new ProxyCertInfo(asn1Sequence);
            }
        }else if(obj instanceof X509Certificate) {
        	byte[] bytes = getExtensionBytes((X509Certificate) obj,
    				ProxyCertInfo.RFC_OID);

    		// if not found, check if there is draft extension
    		if (bytes == null)
    			bytes = getExtensionBytes((X509Certificate) obj,
    					ProxyCertInfo.DRAFT_RFC_OID);

    		if (bytes == null)
    			return null;

    		return new ProxyCertInfo(bytes);
		}
        throw new IllegalArgumentException();
    }
	
	public static byte[] getExtensionBytes(X509Certificate cert, ASN1ObjectIdentifier oid)
			throws IOException
	{
		byte[] bytes = cert.getExtensionValue(oid.getId());
		if (bytes == null)
			return null;
		DEROctetString valueOctets = (DEROctetString) ASN1Primitive
				.fromByteArray(bytes);
		return valueOctets.getOctets();
	}

	/**
	 * Get the proxy certificate path length limit of this extension, if
	 * set.
	 * 
	 * @return The number of allowed proxy certificates in the chain allowed
	 *         after this certificate. Integer.MAX_VALUE if not set.
	 */
	public int getPathLenConstraint()
	{
		return pathLen;
	}

	/**
	 * Get the policy object of this extension.
	 * 
	 * @return The ProxyPolicy object.
	 */
	public ProxyPolicy getProxyPolicy()
	{
		return policy;
	}

	@Override
	public ASN1Primitive toASN1Primitive()
	{
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (pathLen != Integer.MAX_VALUE)
			v.add(new ASN1Integer(pathLen));

		if (policy != null)
		{
			v.add(policy.toASN1Primitive());
		} else
		{
			throw new IllegalArgumentException("Can't generate " +
					"ProxyCertInfoExtension without mandatory policy");
		}
		return new DLSequence(v);
	}
}