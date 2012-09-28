package org.globus.myproxy;

/**
 * Holds the parameters for the <code>destroy</code> operation.
 */
public class DestroyParams
    extends Params {

    private String credentialName;

    public DestroyParams() {
        super(MyProxy.DESTROY_PROXY);
    }
    
    public DestroyParams(String username, String passphrase) {
        super(MyProxy.DESTROY_PROXY, username, passphrase);
    }

    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
    }

    public String getCredentialName() {
        return this.credentialName;
    }

    protected String makeRequest(boolean includePassword) {
        StringBuffer buf = new StringBuffer();
        buf.append(super.makeRequest(includePassword));
        add(buf, CRED_NAME, credentialName);
        return buf.toString();
    }
    
}
