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
package org.globus.gsi;

import java.security.GeneralSecurityException;


/**
 * This exception signals an error with the Signing Policy.
 *
 * @version ${version}
 * @since 1.0
 */
public class SigningPolicyException extends GeneralSecurityException {
	private static final long serialVersionUID = 1L;

	public SigningPolicyException(String msg) {
        super(msg);
    }

    public SigningPolicyException(String msg, Throwable ex) {
        super(msg, ex);
    }

    public SigningPolicyException(Throwable ex) {
        super(ex);
    }
}
