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

package org.globus.gsi.stores;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.util.CertificateIOUtil;
import org.globus.gsi.util.CertificateLoadUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;

import org.globus.util.GlobusResource;


/**
 * Created by IntelliJ IDEA.
 * User: turtlebender
 * Date: Dec 29, 2009
 * Time: 11:37:52 AM
 * To change this template use File | Settings | File Templates.
 */
public class ResourceTrustAnchor extends AbstractResourceSecurityWrapper<TrustAnchor> {
	private Log logger = LogFactory.getLog(getClass().getCanonicalName());

    public ResourceTrustAnchor(String fileName) throws ResourceStoreException {
    	super(false);
        init(globusResolver.getResource(fileName));
    }

    public ResourceTrustAnchor(boolean inMemory, GlobusResource globusResource) throws ResourceStoreException {
    	super(inMemory);
        init(globusResource);
    }

    public ResourceTrustAnchor(String fileName, TrustAnchor cachedAnchor) throws ResourceStoreException {
    	super(false);
        init(globusResolver.getResource(fileName), cachedAnchor);
    }

    public ResourceTrustAnchor(boolean inMemory, GlobusResource globusResource, TrustAnchor cachedAnchor) throws ResourceStoreException {
    	super(inMemory);
        init(globusResource, cachedAnchor);
    }

    public TrustAnchor getTrustAnchor() throws ResourceStoreException {
        return super.getSecurityObject();
    }

    @Override
    protected TrustAnchor create(GlobusResource resource) throws ResourceStoreException {
        X509Certificate certificate;
        InputStream inputStream = null;
        try {
        	inputStream = globusResource.getInputStream();
            certificate = CertificateLoadUtil.loadCertificate(inputStream);
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new ResourceStoreException(e);
        }finally{
        	try {
        		if(inputStream != null){
        			inputStream.close();
        		}
			} catch (IOException e) {
				logger.warn("Unable to close stream.");
			}
        }

        return new TrustAnchor(certificate, null);
    }

    public void store() throws ResourceStoreException {
        try {
            CertificateIOUtil.writeCertificate(this.getTrustAnchor().getTrustedCert(), globusResource.getFile());
        } catch (IOException e) {
            throw new ResourceStoreException(e);
        }
    }
}
