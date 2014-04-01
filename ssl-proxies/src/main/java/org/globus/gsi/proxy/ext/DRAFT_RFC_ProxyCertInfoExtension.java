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

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Extension;

/**
 * Represents ProxyCertInfo X.509 extension.
 */
public class DRAFT_RFC_ProxyCertInfoExtension extends Extension {

    public DRAFT_RFC_ProxyCertInfoExtension(ProxyCertInfo value) throws IOException {
	    super(ProxyCertInfo.DRAFT_RFC_OID, true, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
	}
}
