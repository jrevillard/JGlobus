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

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * A helper class to deal with {@link X500Name X500Name} object.
 */
public class X500NameHelper {

    private ASN1Sequence seq;

    /**
     * Creates an instance using existing {@link X500Name X500Name} 
     * object. 
     * This behaves like a copy constructor.
     *
     * @param name existing <code>X500Name</code> 
     */
    public X500NameHelper(X500Name name) {
    	RDN[] rdns = name.getRDNs();
    	if(GlobusStyle.toRevert(name)){
    		GlobusStyle.swap(rdns);
    	}
    	this.seq = new DERSequence(rdns);
    }

    /**
     * Converts to {@link X500Name X500Name} object.
     *
     * @return the <code>X500Name</code> object.
     */
    public X500Name getAsName() {
        RDN[] rdns = new RDN[seq.size()];
        int index = 0;
        for (Enumeration<?> e = seq.getObjects(); e.hasMoreElements();){
            rdns[index++] = RDN.getInstance(e.nextElement());
        }
        return new X500Name(BCStyle.INSTANCE, rdns);
    }

    /**
     * Appends the specified OID and value pair name component to the end of the
     * current name.
     *
     * @param oid   the name component oid, e.g. {@link X500Name#CN
     *              X500Name.CN}
     * @param value the value (e.g. "proxy")
     */
    public X500NameHelper add(
            ASN1ObjectIdentifier oid,
            String value) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(oid);
        v.add(new DERPrintableString(value));
        add(new DERSet(new DERSequence(v)));
        return this;
    }

    /**
     * Appends the specified name component entry to the current name. This can
     * be used to add handle multiple AVAs in one name component.
     *
     * @param entry the name component to add.
     */
    public X500NameHelper add(ASN1Set entry) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        int size = seq.size();
        for (int i = 0; i < size; i++) {
            v.add(seq.getObjectAt(i));
        }
        v.add(entry);
        seq = new DERSequence(v);
        return this;
    }

    /**
     * Gets the name component at specified position.
     *
     * @return the name component the specified position.
     */
    public ASN1Set getNameEntryAt(int i) {
        return (ASN1Set) seq.getObjectAt(i);
    }

    /**
     * Gets the last name component in the current name.
     *
     * @return the last name component. Null if there is none.
     */
    public ASN1Set getLastNameEntry() {
        int size = seq.size();
        return (size > 0) ? getNameEntryAt(size - 1) : null;
    }

    /**
     * Gets the last name component from the {@link X500Name X500Name} name.
     *
     * @return the last name component. Null if there is none.
     * @throws IOException 
     */
    public static ASN1Set getLastNameEntry(X500Name name) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(name.getEncoded());
        int size = seq.size();
        return (size > 0) ? (ASN1Set) seq.getObjectAt(size - 1) : null;
    }

    /**
     * Returns Globus format representation of the name. It handles names with
     * multiple AVAs.
     *
     * @param name the name to get the Globus format of.
     * @return the Globus format of the name
     */
    public static String toString(X500Name name) {
        if (name == null) {
            return null;
        }
        return GlobusStyle.INSTANCE.toString(name);
    }

    private static String toString(ASN1Sequence seq) {
        if (seq == null) {
            return null;
        }
        RDN[] rdns = new RDN[seq.size()];
        int index = 0;
        for (Enumeration<?> e = seq.getObjects(); e.hasMoreElements();){
            rdns[index++] = RDN.getInstance(e.nextElement());
        }
        return new X500Name(GlobusStyle.INSTANCE, rdns).toString();
    }

    /**
     * Returns Globus format representation of the name.
     */
    public String toString() {
        return toString(this.seq);
    }

}
