package org.globus.myproxy;

/**
 * Holds the parameters for the <code>get-trustroots</code> operation.
 */
public class GetTrustrootsParams
    extends Params {

    public GetTrustrootsParams() {
	super(MyProxy.GET_TRUSTROOTS);
    }

    protected String makeRequest(boolean includePassword) {
	StringBuffer buf = new StringBuffer();
	buf.append(super.makeRequest(includePassword));
        add(buf, TRUSTROOTS, "1");
	return buf.toString();
    }
}
