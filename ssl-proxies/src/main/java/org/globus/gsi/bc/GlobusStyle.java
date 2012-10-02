package org.globus.gsi.bc;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

public class GlobusStyle extends BCStyle{
	
	public static final X500NameStyle INSTANCE = new GlobusStyle();
    /**
     * see {@link BCStyle} DefaultSymbols variable
     */
    protected static final Hashtable<ASN1ObjectIdentifier, String> DefaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();
    /**
     *  see {@link BCStyle} DefaultLookUp variable
     */
    protected static final Hashtable<String, ASN1ObjectIdentifier> DefaultLookUp = new Hashtable<String, ASN1ObjectIdentifier>();
    
    static
    {
        DefaultSymbols.put(C, "C");
        DefaultSymbols.put(O, "O");
        DefaultSymbols.put(T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "SERIALNUMBER");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");
        
        DefaultLookUp.put("c", C);
        DefaultLookUp.put("o", O);
        DefaultLookUp.put("t", T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
    }
    
    protected GlobusStyle(){
    	super();
    }
    
    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.x500.style.BCStyle#fromString(java.lang.String)
     */
	@Override
    public RDN[] fromString(String dirName)
    {
		StringTokenizer nTok = new StringTokenizer(dirName, "/");
        X500NameBuilder builder = new X500NameBuilder(this);
        ASN1ObjectIdentifier previousOID = null;
        String previousValue = null;
        while (nTok.hasMoreTokens())
        {
            String  token = nTok.nextToken();
            int     index = token.indexOf('=');

            if (index == -1)
            {
            	//This mean that the value contained the "/" char -> append it to previous value
            	if(previousOID == null){
            		throw new IllegalArgumentException("badly formated directory string");
            	}
            	previousValue += "/" + token;
            	continue;
            }else{
            	if(previousOID != null){
            		//insert the previous value
            		builder.addRDN(previousOID, previousValue);
            		previousOID = null;
            		previousValue = null;
            	}
            }

            String               attr = token.substring(0, index);
            String               value = token.substring(index + 1);
            ASN1ObjectIdentifier oid = this.attrNameToOID(attr);

            if (value.indexOf('+') > 0)
            {
            	StringTokenizer   vTok = new StringTokenizer(value, "+");
                String  v = vTok.nextToken();

                ArrayList<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>();
                ArrayList<String> values = new ArrayList<String>();

                oids.add(oid);
                values.add(v);

                while (vTok.hasMoreTokens())
                {
                    String  sv = vTok.nextToken();
                    int     ndx = sv.indexOf('=');
                    
                    if (index == -1)
                    {
                    	//This mean that the value contained the "+" char -> append it to previous value
                    	values.set(values.size()-1, values.get(values.size()-1) + "+" + token);
                    	continue;
                    }
                    String  nm = sv.substring(0, ndx);
                    String  vl = sv.substring(ndx + 1);

                    oids.add(this.attrNameToOID(nm));
                    values.add(vl);
                }
                
                builder.addMultiValuedRDN(oids.toArray(new ASN1ObjectIdentifier[oids.size()]), values.toArray(new String[values.size()]));
            }
            else
            {
            	previousOID = oid;
            	previousValue = value;
            }
        }
        if(previousOID != null){
    		//insert the previous value
    		builder.addRDN(previousOID, previousValue);
    	}

        //Swap the RDNs in order to have them in the standard order.
        RDN[] rdns = builder.build().getRDNs();
        swap(rdns);
        return rdns;
    }
	
	public static void swap(RDN[] rdns){
        RDN temp = null ;
        for(int start=0, end = rdns.length -1 ; start < end; start++, end--){
            //swap rdns
            temp = rdns[start];
            if(temp.isMultiValued()){
            	temp = new RDN(invertAttributeTypeAndValueArray(temp.getTypesAndValues()));
            }
            if(rdns[end].isMultiValued()){
            	rdns[end] = new RDN(invertAttributeTypeAndValueArray(rdns[end].getTypesAndValues()));
            }
            rdns[start] = rdns[end];
            rdns[end] = temp;
        }
        if (rdns.length % 2 != 0) {
        	if(rdns[((rdns.length+1)/2)-1].isMultiValued()){
        		rdns[((rdns.length+1))/2] = new RDN(invertAttributeTypeAndValueArray(rdns[((rdns.length+1))/2].getTypesAndValues()));
        	}
        }
	}
	
	
	private static AttributeTypeAndValue[] invertAttributeTypeAndValueArray(AttributeTypeAndValue[] attributeTypeAndValues){
    	AttributeTypeAndValue temp= null;
    	for(int start=0, end = attributeTypeAndValues.length -1 ; start < end; start++, end--){
    		//swap
            temp = attributeTypeAndValues[start];
            attributeTypeAndValues[start] = attributeTypeAndValues[end];
            attributeTypeAndValues[end] = temp;
    	}
    	return attributeTypeAndValues;
	}
	
	@Override
	public ASN1ObjectIdentifier attrNameToOID(String attrName)
    {
        return IETFUtils.decodeAttrName(attrName, DefaultLookUp);
    }
	
	@Override
	public String toString(X500Name name) {
		StringBuffer buf = new StringBuffer();
        RDN[] rdns = name.getRDNs();
        
        //Check if reverse or not
        boolean revert = false;
        if(rdns.length > 1){
        	RDN rdn1 = rdns[0];
        	RDN rdn2 = rdns[rdns.length-1];
        	Set<ASN1ObjectIdentifier> asn1ObjectIdentifiers = DefaultSymbols.keySet();
        	for (ASN1ObjectIdentifier asn1ObjectIdentifier : asn1ObjectIdentifiers) {
				if(asn1ObjectIdentifier.equals(AttributeTypeAndValue.getInstance(((ASN1Set)rdn1.toASN1Primitive()).getObjectAt(0)).getType())){
					//Revert
					revert = true;
					break;
				}
				if(asn1ObjectIdentifier.equals(AttributeTypeAndValue.getInstance(((ASN1Set)rdn2.toASN1Primitive()).getObjectAt(0)).getType())){
					//Do not revert;
					revert = false;
					break;
				}
			}
        }
        
        if(revert){
        	for (int i = rdns.length-1; i >= 0; i--){
        		appendRDNInfo(buf, rdns[i], "/");
        	}
        }else{
        	for (int i = 0; i < rdns.length; i++){
        		appendRDNInfo(buf, rdns[i], "/");
        	}
        }
        
        return buf.toString();
	}
	
	protected void appendRDNInfo(StringBuffer buf, RDN rdn, String separator){
		buf.append(separator);
        if (rdn.isMultiValued())
        {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
            boolean firstAtv = true;

            for (int j = 0; j != atv.length; j++)
            {
                if (firstAtv)
                {
                    firstAtv = false;
                }
                else
                {
                    buf.append('+');
                }
                
                IETFUtils.appendTypeAndValue(buf, atv[j], DefaultSymbols);
            }
        }
        else
        {
            IETFUtils.appendTypeAndValue(buf, rdn.getFirst(), DefaultSymbols);
        }
	}
}
