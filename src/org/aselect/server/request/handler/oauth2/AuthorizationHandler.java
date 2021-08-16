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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * OAUTH2 Authorization RequestHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as an OAuth2 request handler 
 *  It handles OAUTH2 authentication and token requests
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AuthorizationHandler</code> implementation for a single client_id. <br>
 * 
 * @author RH
 */
public class AuthorizationHandler extends ProtoRequestHandler
{
	private final static String MODULE = "AuthorizationHandler";
	private final static String AUTH_CODE_PREFIX = "AUTH_CODE";
	private static final String DEFAULT_EXPIRES_IN = "900";	// defaults to 15 minutes
	private static final String DEFAULT_PW_HASH_METHOD = "SHA-256";
	
	private String oauthEndpointUrl =  null;

	private String _sMyServerID = null;
	private String appID = null;
	private String sharedSecret = null;
	private String defaultUID = null;
	private String aselectServerURL = null;
	private String oauth2_redirect_uri = null;
	private String oauth2_client_id = null;
	private String oauth2_client_credentials_user = null;
	private String oauth2_client_credentials_pwhash = null;
	private String oauth2_client_credentials_pwhash_alg = null;
	private boolean verifyRedirectURI = true;
	private boolean verifyClientID = true;

	// we might use this in future for alternative redirect
	private String _sPostTemplate = null;
	// we might use this in future for client_secret when implementing auth_type "implicit"
	private String secretKey = null;
	private	String loginrequest = null;


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
			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find 'aselect' config section in config file", e);
				throw e;
			}

			try {
				_sMyServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'aselect' config section", e);
				throw e;
			}
			try {
				aselectServerURL = _configManager.getParam(oASelect, "redirect_url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'redirect_url' config section", e);
				throw e;
			}

			try {
				oauthEndpointUrl = _configManager.getParam(oConfig, "oauthendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'ists' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				appID = _configManager.getParam(oConfig, "application");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'application' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
						
			try {
				sharedSecret = _configManager.getParam(oConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'shared_secret' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				defaultUID = _configManager.getParam(oConfig, "uid");
			}
			catch (ASelectConfigException e) {
				defaultUID = "siam_user";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'uid' found, using default: " + defaultUID);
			}

			try {
				oauth2_redirect_uri = _configManager.getParam(oConfig, "oauth2_redirect_uri");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_redirect_uri' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				String sVerifyRedirectURI = _configManager.getParam(oConfig, "oauth2_verify_redirect_uri");
				verifyRedirectURI = Boolean.parseBoolean(sVerifyRedirectURI);
			}
			catch (ASelectConfigException e) {
				verifyRedirectURI = true;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_verify_redirect_uri' found");
			}

			try {
				oauth2_client_id = _configManager.getParam(oConfig, "oauth2_client_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'applicationendpointurl' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oauth2_client_credentials_user = _configManager.getParam(oConfig, "oauth2_client_credentials_user");
			}
			catch (ASelectConfigException e) {
				oauth2_client_credentials_user = null;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_client_credentials_user' found, client_authentication disabled");
			}

			try {
				oauth2_client_credentials_pwhash = _configManager.getParam(oConfig, "oauth2_client_credentials_pwhash");
			}
			catch (ASelectConfigException e) {
				oauth2_client_credentials_pwhash = null;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_client_credentials_pwhash' found, client_authentication disabled");
			}

			oauth2_client_credentials_pwhash_alg = _configManager.getParamFromSection(oConfig, oauth2_client_credentials_pwhash, "algorithm", false);
			if (oauth2_client_credentials_pwhash_alg == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'method' found for 'oauth2_client_credentials_pwhash', using default: " + DEFAULT_PW_HASH_METHOD);
				oauth2_client_credentials_pwhash_alg = DEFAULT_PW_HASH_METHOD;
			}

			try {
				String sVerifyClientID = _configManager.getParam(oConfig, "oauth2_verify_client_id");
				verifyClientID = Boolean.parseBoolean(sVerifyClientID);
			}
			catch (ASelectConfigException e) {
				verifyClientID = true;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_verify_client_id' found");
			}

			try {
				setPostTemplate(_configManager.getParam(oConfig, "post_template"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'post_template' found, disabled");
			}
			try {
				setSecretKey(_configManager.getParam(oConfig, "secretkey"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'secretkey' found, disabled");
			}

			try {
				setLoginrequest(_configManager.getParam(oConfig, "loginrequest"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'loginrequest' found, using default");
				setLoginrequest( "login1");	// default
			}
			
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
		String uid = defaultUID;
		String extractedAselect_credentials = null;
	    
		
		// verify this is a authorization request here. e.g. url end with _authorize and/or if it is's a GET
		// rfc6749 says authorization endpoint must support GET, may support POST
		//	token endpoint must use POST
		// so to see if it's a token request, we see if it is a POST and if it contains all the needed parameters, if not it's another request

		String client_id =  servletRequest.getParameter("client_id");	// maybe use this as app_id as well, need some security though
   		String redirect_uri =  servletRequest.getParameter("redirect_uri");

		if ("POST".equalsIgnoreCase(servletRequest.getMethod())) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handling access token POST request");
			// grant_type only "authorization_code" supported, code, redirect_uri, client_id
			String grant_type =  servletRequest.getParameter("grant_type");
	   		String code =  servletRequest.getParameter("code");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received client_id/redirect_uri/grant_type/code: " + 
					client_id + "/" + redirect_uri + "/" + grant_type + "/" + Auxiliary.obfuscate(code));
			// we should verify the redirect_uri against the saved_redirect_uri here, if there is a saved_redirect_uri
			
			String auth_header = servletRequest.getHeader("Authorization");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found HTTP 'Authorization' header: " + Auxiliary.obfuscate(auth_header));

	   		PrintWriter outwriter = null;
			try {
				outwriter = Utils.prepareForHtmlOutput(servletRequest , servletResponse, "application/json" );
	   			int  return_status = 400; // default

				HashMap<String, String> return_parameters = new HashMap<String, String>();
				boolean client_may_pass = false;
				if (getOauth2_client_credentials_user() != null && getOauth2_client_credentials_pwhash() != null) { // verify auth_header
					client_may_pass = verify_auth_header(auth_header);
				}
				else { // don't verify auth_header

					if (auth_header == null) { // we must verify client_id
						if (client_id_valid(client_id)) {
							client_may_pass = true;
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "No client auth header but client_id valid");
						}
						else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod,
									"No auth header and client_id not valid");
							return_parameters.put("error", "invalid_client");
							return_status = 400; // default
						}
					}
					else {
						client_may_pass = true;
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Client auth header present but not validated");
					}
				}
	   			
		   		if (client_may_pass && code != null && code.length() > 0) {	// retrieve access_token
		   			// access_token, token_type only "Bearer" supported, expires_in recommended, scope optional
		   			// we do not implement refresh token yet
		   			// retrieve code from HistoryManager and delete from history
					SamlHistoryManager history = SamlHistoryManager.getHandle();
					try {
						String access_token = (String)history.get(AUTH_CODE_PREFIX + code);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved access token: " + Auxiliary.obfuscate(access_token));

			   			return_parameters.put("access_token", access_token );
			   			return_parameters.put("token_type", "bearer" );
			   			return_parameters.put("expires_in", DEFAULT_EXPIRES_IN );
			   			return_status = 200; // all well
			   			try {
			   				history.remove(AUTH_CODE_PREFIX + code);	// we'll have to handle if there would be a problem with remove
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Removed access token from local storage using auth code: " + Auxiliary.obfuscate(code));
			   			} catch (ASelectStorageException ase2) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Ignoring problem removing authentication code from temp storage: " + ase2.getMessage());
			   			}
					} catch (ASelectStorageException ase){
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not retrieve authentication code from temp storage: " + ase.getMessage());
			   			return_parameters.put("error", "invalid_request" );
			   			return_status = 400; // default
						
					}
	
		   		} else {	// handle error situation
		   				// return error 
		   			if (!client_may_pass) {
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Client authentication failed");
			   			return_parameters.put("error", "client_authentication_failed" );
			   			return_status = 401;
						servletResponse.setHeader("WWW-Authenticate", "Bearer realm=\"" + _sMyServerID + "\"" + " , " + "error=" + "\"" + return_parameters.get("error") + "\"");
		   			} else {
						_systemLogger.log(Level.FINE, MODULE, sMethod, "No or empty code parameter received");
			   			return_parameters.put("error", "invalid_grant" );
			   			return_status = 400; // default
		   			}
		   		}
		   		servletResponse.setStatus(return_status);
		   		// return all JSON
	   			String out = ((JSONObject) JSONSerializer.toJSON( return_parameters )).toString(0); 
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Writing to client: " + out);
				outwriter.println(out);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem writing to client: " + e.getMessage());
			} finally {
				if (outwriter != null) {
					outwriter.close();
				}
			}
			
			
		} else {	// not a POST
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handling GET request");
		
		// and we don't have credentials yet
    	extractedAselect_credentials = servletRequest.getParameter("aselect_credentials");

    	if (extractedAselect_credentials == null) {		// For now we don't care about previous authentication, let aselect handle that
	    	
    		
	    	// authenticate to the aselect server
    		String ridReqURL = aselectServerURL;
    		String ridSharedSecret = sharedSecret;
    		String ridAselectServer = _sMyServerID;
    		String ridrequest= "authenticate";
    		String ridAppURL =  getIdpfEndpointUrl();
    		
    		String ridResponse = "";
    		
    		// First get request parameters
    		String response_type = servletRequest.getParameter("response_type");
       		String scope	 =  servletRequest.getParameter("scope");
       		String state	 =  servletRequest.getParameter("state");
    		if ( response_type != null &&  !"code".equals(response_type) ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Only response_type=code allowed, received response_type: " + response_type);
				String error_redirect = null;
				try {
				        	String error = "unsupported_response_type";
					error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error 
							+ ( ( state != null ) ? ("&state=" + state) : "");
					servletResponse.sendRedirect(error_redirect);
					return null;
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}
    		} else {
       			response_type = "code"; 	// default because of Facebook but rfc says REQUIRED
    		}

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received client_id/redirect_uri/scope/state: " + 
					client_id + "/" + redirect_uri + "/" + scope + "/" + state);
			if (!client_id_valid(client_id) /* || !redirect_uri_valid(redirect_uri) */ ) {	// we do not verify redirect_uri yet
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "client_id or  redirect_uri invalid");
				String error_redirect = null;
				try {
				        	String error = "unauthorized_client";
				        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error 
							+ ( ( state != null ) ? ("&state=" + state) : "");
					servletResponse.sendRedirect(error_redirect);
					return null;
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}
			}
       		
    		// Send data 
    		BufferedReader in = null;
    		try { 
	    		//Construct request data 
	    		String ridURL = ridReqURL + "?" + "shared_secret=" + URLEncoder.encode(ridSharedSecret, "UTF-8") +
	    				"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
	    				"&request=" + URLEncoder.encode(ridrequest, "UTF-8") +
	    				"&uid=" + URLEncoder.encode(uid, "UTF-8") +
	    				 // RM_30_01
	    				"&app_url=" + URLEncoder.encode(ridAppURL, "UTF-8") +
//			    				"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
	    				"&app_id=" + URLEncoder.encode(appID, "UTF-8");
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting rid from: " + ridReqURL + " , with app_url: " + ridAppURL + " , and app_id: " + appID);

    			URL url = new URL(ridURL); 
    			
    			in = new BufferedReader(new InputStreamReader(url.openStream()));

    			String inputLine = null;
    			while ((inputLine = in.readLine()) != null) {
    				ridResponse += inputLine;
    			}
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting rid response: " + ridResponse);
    		}
    		catch (Exception e) { 	
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve rid from aselectserver: " + ridAselectServer);
				String error_redirect = null;
				try {
				        	String error = "server_error";
				        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error 
							+ ( ( state != null ) ? ("&state=" + state) : "");
					servletResponse.sendRedirect(error_redirect);
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}

				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
    		}
    		finally {
    			if (in != null)
					try {
						in.close();
					}
					catch (IOException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
					}
    		}

    		String extractedRid = ridResponse.replaceFirst(".*rid=([^&]*).*$", "$1");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "rid retrieved: " + extractedRid);

//			_htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, o
			HashMap _htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, n
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + extractedRid);
				String error_redirect = null;
				try {
				        	String error = "server_error";
				        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error 
							+ ( ( state != null ) ? ("&state=" + state) : "");
					servletResponse.sendRedirect(error_redirect);
					return null;
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}
			}
			_htSessionContext = setupSessionContext(_htSessionContext);

			String javaxSessionid = servletRequest.getSession().getId();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "oauthsessionid: " +javaxSessionid);

			_htSessionContext.put("oauthsessionid", javaxSessionid);
			if (state != null) {
				_htSessionContext.put("oauthsessionstate", state);
			}
			if (redirect_uri != null) {
//				_htSessionContext.put("oauthsessionredirect_uri", state);	// RH, 20170606, o
				_htSessionContext.put("oauthsessionredirect_uri", redirect_uri);	// RH, 20170606, n
			}
			
			_oSessionManager.updateSession(extractedRid, _htSessionContext);
			
 
    		//Construct request data 
    		String redirectURL = null;
			try {
				redirectURL = ridReqURL + "?" + 
						"request=" + URLEncoder.encode(loginrequest, "UTF-8") +
						"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
						"&rid=" + extractedRid;
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting login through redirect with redirectURL: " + redirectURL);
				
	    		servletResponse.sendRedirect(redirectURL);
			}
			catch (UnsupportedEncodingException e1) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e1);
			}
			catch (IOException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not redirect to: " + redirectURL);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
	    }
    	else {	// This should be a return from the aselect server
    		// This should be the aselectserver response
    		
    		// check the session for validity
			String javaxSessionid = servletRequest.getSession().getId();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "javaxSessionid: " +javaxSessionid);

			String org_javaxSessionid = null;
			String sTgt = decryptCredentials(extractedAselect_credentials);
			HashMap htTGTContext = getContextFromTgt(sTgt, false);
			if (htTGTContext != null) {
				org_javaxSessionid = (String)htTGTContext.get("oauthsessionid");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "original javaxSessionid: " +org_javaxSessionid);
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve tgt for aselect_credentials:  " +extractedAselect_credentials);
			}
			
			if (!javaxSessionid.equals(org_javaxSessionid)) { 
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid sessionid found");
				String error_redirect = null;
				try {
				        	String error = "invalid_request";
				        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error ;
					servletResponse.sendRedirect(error_redirect);
					return null;
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}
			}
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Handle the aselectserver response");
			
			String finalResult  = verify_credentials(servletRequest, extractedAselect_credentials);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "finalResult after verify_credentials: " + finalResult);
			
//    		String extractedAttributes = finalResult.replaceFirst(".*attributes=([^&]*).*$", "$1");
    		String extractedResultCode = finalResult.replaceFirst(".*result_code=([^&]*).*$", "$1");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "extractedResultCode after verify_credentials: " + extractedResultCode);

	        Boolean authenticatedAndApproved = false;
	        try {
	        	authenticatedAndApproved = Boolean.valueOf(Integer.parseInt(extractedResultCode) == 0);
	        } catch (NumberFormatException nfe ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Resultcode from aselectserver was non-numeric: " + extractedResultCode);
				String error_redirect = null;
				try {
				        	String error = "server_error";
				        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error ;
					servletResponse.sendRedirect(error_redirect);
					return null;
				} catch (IOException iox){
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
				}
	        }
	        String return_url = null;
			String saved_state = (String)htTGTContext.get("oauthsessionstate");
			// we force the redirect_uri so don't use it yet for redirection, if used, must be verified against(list of) valid uri
//			String saved_redirect_uri = (String)htTGTContext.get("oauthsessionredirect_uri");
	        if (authenticatedAndApproved) {
				// If authenticatedAndApproved then send off the user with redirect
	        	
	        	// generate authorization_code
	    		byte[] baRandomBytes = new byte[32];

	    		CryptoEngine.nextRandomBytes(baRandomBytes);
	    		String generated_authorization_code = Utils.byteArrayToHexString(baRandomBytes);

	    		// for now store in HistoryManager
	    		HashMap<String, String> authorization_code = new HashMap<String, String>();
	    		authorization_code.put("aselect_credentials", extractedAselect_credentials);
				// Store it in the history for later retrieval by token request
	    		// Unfortunately access_token should not contain "*", see rfc6750, par. 2.1 Bearer token
	    		// our extractedAselect_credentials may contain one or more "*"
	    		// We should fix that, so we do
	    		BASE64Encoder b64enc = new BASE64Encoder();
	    		String access_token = null;
	    		try {
					access_token = b64enc.encode(extractedAselect_credentials.getBytes("UTF-8"));
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
					String error_redirect = null;
					try {
					        	String error = "server_error";
					        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error ;
						servletResponse.sendRedirect(error_redirect);
						return null;
					} catch (IOException iox){
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
					}
				}
				SamlHistoryManager history = SamlHistoryManager.getHandle();
				history.put(AUTH_CODE_PREFIX+ generated_authorization_code, access_token);
	        	
				return_url = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "code=" + generated_authorization_code 
						+ ( ( saved_state != null ) ? ("&state=" + saved_state) : "") ;
	        } else {	// only happy flow implemented
	        	String error = "access_denied";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not authenticate user, authentication failed with resultcode: " + extractedResultCode);
				return_url = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error 
						+ ( ( saved_state != null ) ? ("&state=" + saved_state) : "");
	        }
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirecting to:  " + return_url);
        	try {
				servletResponse.sendRedirect(return_url);
			}
			catch (IOException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
	        
	    }
		} //  else of POST
		return null;
	}

	private boolean verify_auth_header(String auth_header)
	{
		String sMethod = "verify_auth_header";

		boolean result = false;
		if (auth_header != null) {
			StringTokenizer tkn = new StringTokenizer(auth_header, " \t");
			ArrayList<String> auth_tokens = new ArrayList<String>();
			while (tkn.hasMoreTokens()) {
				auth_tokens.add(tkn.nextToken());
			}
			if ( auth_tokens.size() >=2 && ("Basic".equalsIgnoreCase(auth_tokens.get(0))) && auth_tokens.get(1) != null ) {	// only Basic allowed
				BASE64Decoder b64dec = new BASE64Decoder();
				byte[] baUserpass = b64dec.decodeBuffer(auth_tokens.get(1));
				try {
					String userpass = new String(baUserpass, "UTF-8");
					String[] cred = userpass.split(":", 2); // split in two
					if (cred.length == 2) {	// should be two tokens
						String credashexstring =  Utils.byteArrayToHexString(mdDigest(cred[1], getOauth2_client_credentials_pwhash_method()));
						if ( getOauth2_client_credentials_user().equals(cred[0]) && getOauth2_client_credentials_pwhash().equalsIgnoreCase(credashexstring) ) {
							result = true;
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Authentication header invalid");
						}
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Authentication header not two tokens separated by ':'");
					}
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "UnsupportedEncodingException");
				}
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Authentication header syntax invalid");
			}
		} else {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Authentication header empty");
		}
		return result;
	}

	// Should go to some utilities class
	/**
	 * 
	 * @param plaintext the text to be digested
	 * @param algorithm one of MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512
	 * should work like echo -n <plaintext> | sha<alg>sum
	 * @return the digested value as hex string
	 */
	private static byte[] mdDigest(String plaintext, String algorithm) {
		MessageDigest md;
		 byte byteData[] = null;
		try {
			md = MessageDigest.getInstance(algorithm);
	        md.update(plaintext.getBytes("UTF-8"));
	        byteData = md.digest();
		}
		catch (NoSuchAlgorithmException e) {
			byteData = null;
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			byteData = null;
			e.printStackTrace();
		}
		return byteData;
	}
	
	
	
	private boolean redirect_uri_valid(String redirect_uri) {
		if (isVerifyRedirectURI()) {
			return getOauth2_redirect_uri().equals(redirect_uri);
		}
			else return true;
	}

	private boolean client_id_valid(String client_id)
	{
		if (isVerifyClientID()) {
			return getOauth2_client_id().equals(client_id);
		} else return true;
	}


	/**
	 * @param sMethod
	 */
	protected HashMap setupSessionContext(HashMap htSessionContext)
	{
		String sMethod = "setupSessionContext";

		
		return htSessionContext;
	}

	/**
	 * @param request
	 * @param extracted_credentials
	 * @param sMethod
	 * @param extractedAselect_credentials
	 * @return 
	 * @throws ASelectCommunicationException
	 */
	private String verify_credentials(HttpServletRequest request, String extracted_credentials)
	throws ASelectCommunicationException
	{
		String sMethod = "verify_credentials";
		// This could be done by getting request parametermap
		String queryData = request.getQueryString();
		String extractedRid = queryData.replaceFirst(".*rid=([^&]*).*$", "$1");
		String finalReqURL = aselectServerURL;
		String finalReqSharedSecret = sharedSecret;
		String finalReqAselectServer = _sMyServerID;
		String finalReqrequest= "verify_credentials";
		
		//Construct request data
		String finalRequestURL = null;
		try {
			finalRequestURL = finalReqURL + "?" + "shared_secret=" + URLEncoder.encode(finalReqSharedSecret, "UTF-8") +
					"&a-select-server=" + URLEncoder.encode(finalReqAselectServer, "UTF-8") +
					"&request=" + URLEncoder.encode(finalReqrequest, "UTF-8") +
					"&aselect_credentials=" + extracted_credentials +
//								"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
					"&rid=" + extractedRid;
		}
		catch (UnsupportedEncodingException e3) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e3);
		}
		String finalResult = "";

		//Send data
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving attributes through: " + finalRequestURL);

		BufferedReader in = null;
		try { 
			URL url = new URL(finalRequestURL); 
			
			in = new BufferedReader(
					new InputStreamReader(
							url.openStream()));

			String inputLine = null;
			while ((inputLine = in.readLine()) != null) {
				finalResult += inputLine;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Retrieved attributes in: " + finalResult);

		} catch (Exception e) { 	
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve attributes from aselectserver: " + finalReqAselectServer);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
		} finally {
			if (in != null)
				try {
					in.close();
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + finalReqAselectServer);
				}
		}
		return finalResult;
	}


	public void destroy()
	{
	}

	public synchronized String getIdpfEndpointUrl()
	{
		return oauthEndpointUrl;
	}

	public synchronized void setIdpfEndpointUrl(String idpfEndpointUrl)
	{
		this.oauthEndpointUrl = idpfEndpointUrl;
	}

	
	public synchronized String getPostTemplate()
	{
		return _sPostTemplate;
	}
	public synchronized void setPostTemplate(String sPostTemplate)
	{
		_sPostTemplate = sPostTemplate;
	}


	public String getSecretKey()
	{
		return secretKey;
	}

	public void setSecretKey(String secretKey)
	{
		this.secretKey = secretKey;
	}

	public synchronized String getLoginrequest()
	{
		return loginrequest;
	}

	public synchronized void setLoginrequest(String loginrequest)
	{
		this.loginrequest = loginrequest;
	}

	public synchronized String getOauth2_redirect_uri()
	{
		return oauth2_redirect_uri;
	}

	public synchronized void setOauth2_redirect_uri(String oauth2_redirect_uri)
	{
		this.oauth2_redirect_uri = oauth2_redirect_uri;
	}

	public synchronized String getOauth2_client_id()
	{
		return oauth2_client_id;
	}

	public synchronized void setOauth2_client_id(String oauth2_client_id)
	{
		this.oauth2_client_id = oauth2_client_id;
	}

	public synchronized boolean isVerifyRedirectURI()
	{
		return verifyRedirectURI;
	}

	public synchronized void setVerifyRedirectURI(boolean verifyRedirectURI)
	{
		this.verifyRedirectURI = verifyRedirectURI;
	}

	public synchronized boolean isVerifyClientID()
	{
		return verifyClientID;
	}

	public synchronized void setVerifyClientID(boolean verifyClientID)
	{
		this.verifyClientID = verifyClientID;
	}

	public synchronized String getOauth2_client_credentials_user()
	{
		return oauth2_client_credentials_user;
	}

	public synchronized void setOauth2_client_credentials_user(String oauth2_client_credentials_user)
	{
		this.oauth2_client_credentials_user = oauth2_client_credentials_user;
	}

	public synchronized String getOauth2_client_credentials_pwhash()
	{
		return oauth2_client_credentials_pwhash;
	}

	public synchronized void setOauth2_client_credentials_pwhash(String oauth2_client_credentials_pwhash)
	{
		this.oauth2_client_credentials_pwhash = oauth2_client_credentials_pwhash;
	}

	public synchronized String getOauth2_client_credentials_pwhash_method()
	{
		return oauth2_client_credentials_pwhash_alg;
	}

	public synchronized void setOauth2_client_credentials_pwhash_method(String oauth2_client_credentials_pwhash_method)
	{
		this.oauth2_client_credentials_pwhash_alg = oauth2_client_credentials_pwhash_method;
	}

}
