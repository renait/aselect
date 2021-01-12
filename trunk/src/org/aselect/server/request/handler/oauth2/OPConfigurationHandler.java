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
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

/**
 * OAUTH2 ConfigurationHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as an OAuth2 request handler 
 *  It handles OAUTH2 "well_known" openid-configuration requests
 *  should be configured with "/openid-configuration.*" as target
 * <br>
 * 
 * @author RH
 */
public class OPConfigurationHandler extends OPBaseHandler
{
	private final static String MODULE = "OPBaseHandler";
	


	private Map<String, Object> configuration = null;


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
			
			if (configuration == null) {
				configuration = new HashMap<String, Object>();
			}

			configuration.put("issuer", getIssuer());
			try {
				String authorization_endpoint = _configManager.getParam(oConfig, "authorization_endpoint_target");
				configuration.put("authorization_endpoint", getIssuer() + authorization_endpoint);	//
				
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'authorization_endpoint' config parameter in 'authorization_endpoint_target' config section");
				throw e;
			}

			try {
				String token_endpoint = _configManager.getParam(oConfig, "token_endpoint_target");
				configuration.put("token_endpoint", getIssuer() + token_endpoint);	//
				
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'token_endpoint_target' found, using authorization_endpoint");
				configuration.put("token_endpoint", configuration.get("authorization_endpoint"));
				
			}
			
//			conf.put("userinfo_endpoint", getIssuer() + );	// not supported (yet)
			
			try {
				String jwks_uri = _configManager.getParam(oConfig, "jwks_uri_target");
				configuration.put("jwks_uri", getIssuer() + jwks_uri);	//
				
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'authorization_endpoint' config parameter in 'jwks_uri_target' config section");
				throw e;
			}

//			conf.put("registration_endpoint", getIssuer() + "/");	//
			
			try {
				String scopes_supported = _configManager.getParam(oConfig, "scopes_supported");
				configuration.put("scopes_supported", scopes_supported.split(","));	// for now split on comma
				
			}
			catch (ASelectConfigException e) {
				configuration.put("scopes_supported", "openid".split(","));	// MUST support openid
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'scopes_supported' found, using default: " + configuration.get("scopes_supported"));
				
			}

			try {
				String response_types_supported = _configManager.getParam(oConfig, "response_types_supported");
				configuration.put("response_types_supported", response_types_supported.split(","));	// for now split on comma
				
			}
			catch (ASelectConfigException e) {
				configuration.put("response_types_supported", "code".split(","));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'response_types_supported' found, using default: " + configuration.get("response_types_supported"));
				
			}

//			conf.put("response_modes_supported", "");	//	defaults to ["query", "fragment"]
			
			try {
				String grant_types_supported = _configManager.getParam(oConfig, "grant_types_supported");
				configuration.put("grant_types_supported", grant_types_supported.split(","));	// for now split on comma
				
			}
			catch (ASelectConfigException e) {
				configuration.put("grant_types_supported", "authorization_code".split(","));	// defaults to ["authorization_code", "implicit"] but we prefer authorization_code
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'grant_types_supported' found, using default: " + configuration.get("grant_types_supported"));
				
			}

			configuration.put("subject_types_supported", "public".split(","));	//	Valid types include pairwise and public, defaults to public
			configuration.put("id_token_signing_alg_values_supported", "RS256".split(","));	//	alg values,  RS256 MUST be included

			configuration.put("token_endpoint_auth_methods_supported", "client_secret_basic".split(","));	//	OPTIONAL but we support just one

			try {
				String claims_supported = _configManager.getParam(oConfig, "claims_supported");
				configuration.put("claims_supported", claims_supported.split(","));	// for now split on comma
				
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'claims_supported' found, ignoring");
				
			}

			configuration.put("request_uri_parameter_supported", false);	//	OPTIONAL defaults to true
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
//			configuration = generateConfig(null);	// for testing
   			String out = toJSONString();
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

	/*
	private Map<String, Object> generateConfig(Map<String, Object> conf) {
		String sMethod = "generateConfig";

		if (conf == null) {
			conf = new HashMap<String, Object>();
		}

		conf.put("authorization_endpoint", getIssuer() + "/");	//
		conf.put("token_endpoint", getIssuer() + "/");	//
//		conf.put("userinfo_endpoint", getIssuer() + "/");	//
		conf.put("jwks_uri", getIssuer() + "/");	//
//		conf.put("registration_endpoint", getIssuer() + "/");	//
//		conf.put("scopes_supported", "");	// 
		conf.put("response_types_supported", "");	//
//		conf.put("response_modes_supported", "");	//	defaults to ["query", "fragment"]
		conf.put("response_types_supported", "");	//
//		conf.put("grant_types_supported", "");	//	defaults to ["authorization_code", "implicit"]
		conf.put("subject_types_supported", "public");	//	Valid types include pairwise and public, defaults to public
		conf.put("id_token_signing_alg_values_supported", "RS256");	//	alg values,  RS256 MUST be included

		conf.put("token_endpoint_auth_methods_supported", "client_secret_basic");	//	OPTIONAL but we support just one

//		conf.put("claims_supported", "");	//	RECOMMENDED but we should include some of our claims

//		conf.put("request_uri_parameter_supported", "");	//	OPTIONAL defaults to true

		
		return conf;
	}
	*/
	
	private String toJSONString() {
		return ((JSONObject) JSONSerializer.toJSON( getConfiguration() )).toString(0); 
	}

	/**
	 * @return the configuration
	 */
	public synchronized Map<String, Object> getConfiguration() {
		return configuration;
	}

	/**
	 * @param configuration the configuration to set
	 */
	public synchronized void setConfiguration(Map<String, Object> configuration) {
		this.configuration = configuration;
	}


}
