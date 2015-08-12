package org.globus.gsi.stores;

import java.security.Security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.globus.gsi.provider.GlobusProvider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

/**
 * @author Jerome Revillard
 *
 */
public class Activator implements BundleActivator {
	private static final Log LOGGER = LogFactory.getLog(Activator.class);
	
	public void start(BundleContext bundleContext) throws Exception {
		LOGGER.info("\n>>>>>> JGlobus SSL-PROXY BUNDLE STARTING");
		
		LOGGER.info("\n>>>>>> JGlobus SSL-PROXY BUNDLE STARTED");
	}

	public void stop(BundleContext arg0) throws Exception {
		LOGGER.info("\n>>>>>> JGlobus SSL-PROXY BUNDLE STOPPING");
		Stores.clearAll();
		Security.removeProvider(GlobusProvider.PROVIDER_NAME);
		LOGGER.info("\n>>>>>> JGlobus SSL-PROXY BUNDLE STOPPED");
	}
}