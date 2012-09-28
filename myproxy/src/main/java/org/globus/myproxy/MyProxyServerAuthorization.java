package org.globus.myproxy;

import org.globus.gsi.gssapi.auth.Authorization;
import org.globus.gsi.gssapi.auth.AuthorizationException;
import org.globus.gsi.gssapi.auth.HostAuthorization;
import org.ietf.jgss.GSSContext;

/**
 * Implements the MyProxy server authorization mechanism.
 */
public class MyProxyServerAuthorization
    extends Authorization {
    
    private HostAuthorization authzHostService, authzMyProxyService;

    public MyProxyServerAuthorization() {
        this.authzMyProxyService = new HostAuthorization("myproxy");
        this.authzHostService = HostAuthorization.getInstance();
    }

    /**
     * Performs MyProxy server authorization checks. The hostname of
     * the server is compared with the hostname specified in the
     * server's (topmost) certificate in the certificate chain. The
     * hostnames must match exactly (in case-insensitive way). The
     * service in the certificate may be "host" or "myproxy".
     * <code>AuthorizationException</code> if the authorization fails.
     * Otherwise, the function completes normally.
     *
     * @param context the security context.
     * @param host host address of the peer.
     * @exception AuthorizationException if the peer is
     *            not authorized to access/use the resource.
     */
    public void authorize(GSSContext context, String host) 
        throws AuthorizationException {
        try {
            this.authzMyProxyService.authorize(context, host);
        } catch (AuthorizationException e) {
            this.authzHostService.authorize(context, host);
        }
    }
}
