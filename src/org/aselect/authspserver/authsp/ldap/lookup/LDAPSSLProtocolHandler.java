/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */

package org.aselect.authspserver.authsp.ldap.lookup;

import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.Context;

/**
 * @author remy
 *
 */
public class LDAPSSLProtocolHandler extends LDAPSimpleProtocolHandler {

	protected static String _sModule = "lookup.LDAPSSLProtocolHandler";

	/**
	 * 
	 */
	public LDAPSSLProtocolHandler() {
		super();
		_sModule = "lookup.LDAPSSLProtocolHandler";
		

	}

	/**
	 * @param htEnvironment
	 */
	public void additionalSettings(Hashtable<String, String> htEnvironment)
	{	
		super.additionalSettings(htEnvironment);
		_systemLogger.log(Level.FINE, _sModule, "additionalSettings", "ssl");
		htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
	}

}
