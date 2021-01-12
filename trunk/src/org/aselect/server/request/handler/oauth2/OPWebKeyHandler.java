/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.oauth2;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

/**
 * OAUTH2 WebKeyHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as an OAuth2 request handler 
 *  It handles OAUTH2 webkey requests
 *  Generates default webkeyset
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>OPWebKeyHandler</code> <br>
 * 
 * @author RH
 */
public class OPWebKeyHandler extends OPBaseHandler
{
	private final static String MODULE = "OPWebKeyHandler";

	/* @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oConfig);
			
			
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Process incoming request.<br>
	 * 
	 * @param servletRequest
	 *            HttpServletRequest.
	 * @param servletResponse
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of  data request fails.
	 */
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{		
		String sMethod = "process";
   		PrintWriter outwriter = null;
		try {
			
			outwriter = Utils.prepareForHtmlOutput(servletRequest , servletResponse, "application/json" );
			//
//			Utils.setDisableCachingHttpHeaders(servletRequest , servletResponse);
//   			String out = toJSONString();
			String out = "{ \"error\": \"Could not retrieve webkey\" }";	// handle this better
			JsonWebKeySet webkeys = generateWebKeySet(generateDefaultWebKey(null));
			if (webkeys != null) {
				 out = webkeys.toJson();
			}
	   		servletResponse.setStatus(HTTP_OK);
	   		// return all JSON
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Writing to client: " + out);
			outwriter.println(out);
			outwriter.flush();
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem writing to client: " + e.getMessage());
		} finally {
			if (outwriter != null) {
				outwriter.close();
			}
		}
		return null;
	}

	private PublicJsonWebKey generateDefaultWebKey(Map<String, Object> conf) {
		String sMethod = "generateWebKey";
		
		RSAPublicKey pub_key = (RSAPublicKey)_configManager.getDefaultCertificate().getPublicKey();
		//RSAKey jwk = new RSAKey.Builder(publicKey).build();
		PublicJsonWebKey keyJwk;
		try {
			keyJwk = PublicJsonWebKey.Factory.newPublicJwk(pub_key);
			keyJwk.setUse("sig");
//			keyJwk.setKeyId(keyJwk.calculateBase64urlEncodedThumbprint(pub_key.getAlgorithm()));	// not working because of "RSA", must be RSA-256
			keyJwk.setKeyId(keyJwk.calculateBase64urlEncodedThumbprint(org.jose4j.lang.HashUtil.SHA_256));
			keyJwk.setKeyId(_configManager.getDefaultCertId());
		} catch (JoseException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem generating webkey from public key: " + e.getMessage());
			keyJwk = null;
		}
		/*
		pub_key.getAlgorithm();
		String modulus = null;
		BigInteger bMod = pub_key.getModulus().
		
		pub_key.getPublicExponent();
		_configManager.getDefaultCertificate().getSigAlgName();	// we might use this for alg parameter
		
		_configManager.getDefaultCertificate().getSerialNumber();	// we might use this (or the thumbprint) for the kid parameter
		*/

		
		return keyJwk;
	}
	
	private JsonWebKeySet generateWebKeySet(PublicJsonWebKey key) {
		String sMethod = "generateWebKeySet(PublicJsonWebKey key)";
		
		JsonWebKeySet keyJwks;
		keyJwks = new JsonWebKeySet();
		keyJwks.addJsonWebKey(key);
		return keyJwks;
	}

	private JsonWebKeySet generateWebKeySet(Set<PublicJsonWebKey> keys) {
		String sMethod = "generateWebKeySet(Set<PublicJsonWebKey> keys)";
		
		JsonWebKeySet keyJwks;
			keyJwks = new JsonWebKeySet();
			for (PublicJsonWebKey key : keys) {
				keyJwks.addJsonWebKey(key);
			}
		return keyJwks;
	}

}
