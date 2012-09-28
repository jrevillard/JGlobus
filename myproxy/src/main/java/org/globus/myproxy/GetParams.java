package org.globus.myproxy;

import org.ietf.jgss.GSSCredential;
import java.util.List;
import java.util.Iterator;


/**
 * Holds the parameters for the <code>get</code> operation.
 */
public class GetParams
    extends Params {

    private boolean wantTrustroots = false;
    private String credentialName;
    private GSSCredential authzcreds;
    private List<String> voname;
    private List<String> vomses;

    public GetParams() {
	super(MyProxy.GET_PROXY);
    }

    public GetParams(String username, String passphrase) {
	super(MyProxy.GET_PROXY, username, passphrase);
    }

    public void setCredentialName(String credentialName) {
	this.credentialName = credentialName;
    }

    public String getCredentialName() {
	return this.credentialName;
    }

    public void setWantTrustroots(boolean wantTrustroots) {
        this.wantTrustroots = wantTrustroots;
    }

    public boolean getWantTrustroots() {
        return this.wantTrustroots;
    }

    public void setVoname(List<String> voname) {
        this.voname = voname;
    }

    public List<String> getVoname() {
        return this.voname;
    }

    public void setVomses(List<String> vomses) {
        this.vomses = vomses;
    }

    public List<String> getVomses() {
        return this.vomses;
    }

    /**
     * Set credentials for renewal authorization.
     * @param creds
     *        The credentials to renew.
     */
    public void setAuthzCreds(GSSCredential creds) {
        this.authzcreds = creds;
    }

    public GSSCredential getAuthzCreds() {
        return this.authzcreds;
    }

    protected String makeRequest(boolean includePassword) {
	StringBuffer buf = new StringBuffer();
	buf.append(super.makeRequest(includePassword));
	add(buf, CRED_NAME, credentialName);
        add(buf, VONAME, this.voname);
        add(buf, VOMSES, this.vomses);
        if (this.wantTrustroots == true) {
            add(buf, TRUSTROOTS, "1");
        }
	return buf.toString();
    }

    private void add(StringBuffer buf, String prefix, List<String> values) {
        if (values == null) {
            return;
        }
        for (Iterator<String> itr = values.iterator(); itr.hasNext(); ) {
            String value = itr.next();
            add(buf, prefix, value);
        }
    }
    
}
