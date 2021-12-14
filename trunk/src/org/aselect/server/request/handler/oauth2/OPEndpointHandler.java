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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.attributes.requestors.IAttributeRequestor;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.server.session.PersistentStorageManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.jose4j.lang.JoseException;

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
//	public class OPEndpointHandler extends ProtoRequestHandler	// RH, 20200210, o
public class OPEndpointHandler extends OPBaseHandler	// RH, 20200210, n

{
	private static final String RESPONSE_MODE_FRAGMENT = "fragment";
	private static final String RESPONSE_MODE_QUERY = "query";
	private static final String RESPONSE_MODE_FORM_POST = "form_post";
	private final static String MODULE = "OPEndpointHandler";
	protected final static String AUTH_CODE_PREFIX = "AUTH_CODE";
	protected final static String ID_TOKEN_PREFIX = "ID_TOKEN";
	protected final static String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN";
	
	
	protected static final String DEFAULT_EXPIRES_IN = "900";	// defaults to 15 minutes
//	private static final String DEFAULT_PW_HASH_METHOD = "SHA-256";
	protected static final boolean DEFAULT_PROMPT_SUPPORTED = false;	// RH, 20191206, n
	protected static final boolean DEFAULT_ALLOW_REFRESH_TOKEN = false;
	protected static final boolean DEFAULT_ALLOW_PASSWORD_CREDENTIALS = false;
	
	private HashMap<String, String> _client_ids = null;
	
	private String oauthEndpointUrl =  null;
	private String allowedResponseTypes = null; // BW, 20211125, n
	private List<String> allowed_repons_type = null; // BW, 20211206, n

	private String defaultUID = null;
	private boolean verifyRedirectURI = true;
	private boolean verifyClientID = true;

	// we might use this in future for alternative redirect
	private String _sPostTemplate = null;
	// we might use this in future for client_secret when implementing auth_type "implicit"
	private String secretKey = null;
	private	String loginrequest = null;

	private HashMap<String, String> _forced_app_ids = null;	// RH 20181129, n
	private	String _forced_app_parameter = null;

	private	boolean prompt_supported = DEFAULT_PROMPT_SUPPORTED;
	private String sConsentTemplate = null;
	private	boolean allow_refresh_token = DEFAULT_ALLOW_REFRESH_TOKEN;
	private String sRefresh_token_storage_manager = null;

	private	boolean allow_password_credentials = DEFAULT_ALLOW_PASSWORD_CREDENTIALS;
	private String sPassword_credentials_verify_requestorid = null;
	private String sPassword_credentials_client_id = null;
	

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
			
			try {
				oauthEndpointUrl = _configManager.getParam(oConfig, "oauthendpointurl");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauthendpointurl' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			
			// BW, 20211125, sn
			try {
				allowedResponseTypes = _configManager.getParam(oConfig, "allowed_response_types");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No config item 'allowed_response_types' found");
			} 
  			
			if(allowedResponseTypes == null || allowedResponseTypes.isEmpty()) {  // default to code and id_token
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No or empty allowed response type configured, default to code & id_token");
				allowed_repons_type.add("code");
				allowed_repons_type.add("id_token");
			} else {
				allowed_repons_type = Arrays.asList(allowedResponseTypes.toLowerCase().trim().split(" "));
			} 
			// BW, 2021206, en

			// RH, 20180828, sn
			HashMap<String, String> _htClientIds = new HashMap<String, String>(); // contains level -> urn
			_htClientIds = ASelectConfigManager.getTableFromConfig(oConfig,  _htClientIds, "applications",
					"application", "client_id",/*->*/"app_id", false/* mandatory */, false/* unique values */);
			if (_htClientIds != null) {
				setClientIds(_htClientIds);
			}
			// RH, 20180828, en

			try {
				defaultUID = _configManager.getParam(oConfig, "uid");
			}
			catch (ASelectConfigException e) {
				defaultUID = "siam_user";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'uid' found, using default: " + defaultUID);
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
				String sVerifyClientID = _configManager.getParam(oConfig, "oauth2_verify_client_id");
				verifyClientID = Boolean.parseBoolean(sVerifyClientID);
			}
			catch (ASelectConfigException e) {
				verifyClientID = true;
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'oauth2_verify_client_id' found");
			}

			try {
				if (_configManager.getParam(oConfig, "post_template") != null) {
					// RH, 20191205, so
//					_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");
//					setPostTemplate(_sPostTemplate);
					// RH, 20191205, eo
					// RH, 20191205, sn
					String sPostTemplate = readTemplateFromConfig(oConfig, "post_template");
					setPostTemplate(sPostTemplate);
					// RH, 20191205, en
				}
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

			// RH, 20181203, sn
			try {
				set_forced_app_parameter(_configManager.getParam(oConfig, "forced_app_parameter"));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'forced_app_parameter' found, using default none");
			}

			HashMap<String, String> _htForced_app_ids = new HashMap<String, String>(); // contains mapping to app_id
			_htForced_app_ids = ASelectConfigManager.getTableFromConfig(oConfig,  _htForced_app_ids, "forced_applications",
					"application", "forced_app_id",/*->*/"app_id", false/* mandatory */, false/* unique values */);
			if (_htForced_app_ids != null) {
				set_forced_app_ids(_htForced_app_ids);
			}
			// RH, 20181203, en

			// RH, 20191206, sn
			try {
				String sPrompt_supprted = _configManager.getParam(oConfig, "prompt_supported");
				setPrompt_supported(Boolean.parseBoolean(sPrompt_supprted));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'prompt_supported' found, defaults to:" + DEFAULT_PROMPT_SUPPORTED);
			}
			try {
				if (_configManager.getParam(oConfig, "consent_template") != null) {
					String sConsentTemplate = readTemplateFromConfig(oConfig, "consent_template");
					setConsentTemplate(sConsentTemplate);

				}
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'consent_template' found, disabled");
			}
			// RH, 20191206, en
			try {
				String sAllow_refresh_token = _configManager.getParam(oConfig, "allow_refresh_token");
				setAllow_refresh_token(Boolean.parseBoolean(sAllow_refresh_token));

			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'allow_refresh_token' found, defaults to:" + DEFAULT_ALLOW_REFRESH_TOKEN);
			}
			if (isAllow_refresh_token()) {
				try {
					setRefresh_token_storage_manager(_configManager.getParam(oConfig, "refresh_token_storage_manager"));
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'refresh_token_storage_manager' found");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				try {
					persistentStorage = new PersistentStorageManager(getRefresh_token_storage_manager());
					persistentStorage.init();
				} catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize refresh_token storagemanager");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
			
			try {
				String sAllow_password_credentials = _configManager.getParam(oConfig, "allow_password_credentials");
				setAllow_password_credentials(Boolean.parseBoolean(sAllow_password_credentials));
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'allow_password_credentials' found, defaults to:" + DEFAULT_ALLOW_PASSWORD_CREDENTIALS);
			}
			if (isAllow_password_credentials()) {
				try {
				setPassword_credentials_verify_requestorid(_configManager.getParam(oConfig, "password_credentials_verify_requestorid"));
				} catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'password_credentials_verify_requestorid'");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				try {
				setPassword_credentials_client_id(_configManager.getParam(oConfig, "password_credentials_client_id"));
				} catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'password_credentials_client_id'");
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
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
	    
		ITokenMachine tokenMachine = createTokenMachine();
		
		// verify this is a authorization request here. e.g. url end with _authorize and/or if it is's a GET
		// rfc6749 says authorization endpoint must support GET, may support POST
		// token endpoint must use POST
		

		String client_id =  servletRequest.getParameter("client_id");	// maybe use this as app_id as well, need some security though
   		String redirect_uri =  servletRequest.getParameter("redirect_uri");

		String grant_type =  servletRequest.getParameter("grant_type");
   		String code =  servletRequest.getParameter("code");
   		String refresh_token =  servletRequest.getParameter("refresh_token");
   		// Used for Resource Owner Password Credentials Grant
   		String username =  servletRequest.getParameter("username");
   		String password =  servletRequest.getParameter("password");
   		//
   		String nonce =  servletRequest.getParameter("nonce");	// if present, should be passed back in the id_token
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received client_id/redirect_uri/grant_type/code: " + 
				client_id + "/" + redirect_uri + "/" + grant_type + "/" + Auxiliary.obfuscate(code));
		// we should verify the redirect_uri against the saved_redirect_uri here, if there is a saved_redirect_uri

		String appidacr = "0"; // We have not authenticated the client yet 
		if (grant_type != null && (code != null || refresh_token != null || (username != null && password!= null))) {	// (Refresh) Token request
			
			// Token request, should be POST
			if ( "POST".equalsIgnoreCase(servletRequest.getMethod()) ) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handling access_token/refresh_token POST request");
				// grant_type only "authorization_code" supported, code, redirect_uri, client_id
				
				String auth_header = servletRequest.getHeader("Authorization");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found HTTP 'Authorization' header: " + Auxiliary.obfuscate(auth_header));
	
		   		PrintWriter outwriter = null;
				try {
					outwriter = Utils.prepareForHtmlOutput(servletRequest , servletResponse, "application/json" );
					Utils.setDisableCachingHttpHeaders(servletRequest , servletResponse);	// RH, 20190606
//		   			int  return_status = 400; // default, already set by TokenMachine contructor
	
					boolean client_may_pass = false;
				   	if ("authorization_code".equals(grant_type) && code != null && code.length() > 0) {	// retrieve access_token
			   			// retrieve code from HistoryManager and delete from history
						SamlHistoryManager history = SamlHistoryManager.getHandle();
						try {
							String encoded_access_token = (String)history.get(AUTH_CODE_PREFIX + code);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved access token: " + Auxiliary.obfuscate(encoded_access_token));
	
							String access_token = extractAccessToken(encoded_access_token);
				   		
						BASE64Decoder b64dec = new BASE64Decoder();
						byte[] bytes_access_token = b64dec.decodeBuffer(access_token);
						String string_access_token = new String(bytes_access_token, "UTF-8");
						String sTGT = org.aselect.server.utils.Utils.decodeCredentials(string_access_token,
								_systemLogger);
						HashMap tgt = TGTManager.getHandle().getTGT(sTGT);
						String sAppId = (String)tgt.get("app_id");
						String saved_redirect_uri = (String)tgt.get("oauthsessionredirect_uri");
						// RH, 20210409, so
//						if (saved_redirect_uri == null) {	// we did not receive a redirect_url upon authentication so use registered one
//							saved_redirect_uri = ApplicationManager.getHandle().getApplication(sAppId).getOauth_redirect_uri().keySet().iterator().next().toString();
//						}
						// RH, 20210409, eo
						
//						if (saved_redirect_uri != null && !saved_redirect_uri.equals(redirect_uri)) {	// RH, 20210409, o
						if (saved_redirect_uri == null || saved_redirect_uri.equals(redirect_uri)) {	// RH, 20210409, n
							// RH, 20210409, so
		//						_systemLogger.log(Level.WARNING, MODULE, sMethod, "redirect_uri does not match, MUST NOT automatically redirect user to: " + redirect_uri);
//								throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
								// RH, 20210409, eo
	
						if (ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_user() != null 
								&& ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_pwhash() != null) { // verify auth_header
							client_may_pass = verify_auth_header(auth_header, ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_user(),
									ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_pwhash(),
									ApplicationManager.getHandle().getApplication(sAppId).getOauth2_client_credentials_pwhash_alg());
	
							appidacr = "1"; 	// client secret was used for authentication
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
									tokenMachine.setParameter("error", "invalid_client");
									tokenMachine.setStatus(400);
								}
							}
							else {
								client_may_pass = true;
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client auth header present but not validated");
							}
						}
	
				   		if (client_may_pass) {	// All well
							String saved_scope = (String)tgt.get("oauthsessionscope");
							String saved_client_id = (String)tgt.get("oauthsessionclient_id");

							// RH, 20200428, so
//				   			tokenMachine.setParameter("scope", tgt.get(saved_scope));
//				   			tokenMachine.setParameter("client_id", tgt.get(saved_client_id));
							// RH, 20200428, eo
							// RH, 20200428, sn
				   			tokenMachine.setParameter("scope", saved_scope);
				   			tokenMachine.setParameter("client_id", saved_client_id);
							// RH, 20200428, en

				   			tokenMachine.setParameter("issuer", getIssuer());
				   			tokenMachine.setParameter("appidacr", appidacr);
				   			
							int status = supplyReturnParameters(code, tokenMachine, history, encoded_access_token, tgt, appidacr);
							tokenMachine.setStatus(status);
				   			try {
				   				history.remove(AUTH_CODE_PREFIX + code);	// we'll have to handle if there would be a problem with remove
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "Removed auth code from local storage using auth code: " + Auxiliary.obfuscate(code));
				   			} catch (ASelectStorageException ase2) {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Ignoring problem removing authentication code from temp storage: " + ase2.getMessage());
				   			}
					   			
				   		} else {
				   			tokenMachine.setParameter("error", "client_authentication_failed" );
				   			tokenMachine.setStatus(401);
							servletResponse.setHeader("WWW-Authenticate", "Bearer realm=\"" + getMyServerID() + "\"" + " , " + "error=" + "\"" + tokenMachine.getParameter("error") + "\"");
				   			
				   		}
						// RH, 20210409, sn
					   	} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "redirect_uri: " + redirect_uri +  ", does not match: " + saved_redirect_uri);
							tokenMachine.setParameter("error", "invalid_request");
							//	return_status = 400; // default
							tokenMachine.setStatus(400);
					   	}
						// RH, 20210409, en
						} catch (ASelectStorageException ase){
							_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not retrieve authentication code from temp storage: " + ase.getMessage());
				   			tokenMachine.setParameter("error", "invalid_request" );
				   			//	return_status = 400; // default
				   			tokenMachine.setStatus(400);
						}
				   	} else if ("refresh_token".equals(grant_type) &&  refresh_token != null && refresh_token.length() > 0) {
				   		// supply refresh_token
				   		if (isAllow_refresh_token()) { // && refresh_token ok
				   			refresh_token = extractAccessToken(refresh_token);	// should be extract refresh_token but we can use the same
							BASE64Decoder b64dec = new BASE64Decoder();
							byte[] bytes_refresh_token = b64dec.decodeBuffer(refresh_token);
							String string_refresh_token = new String(bytes_refresh_token, "UTF-8");
							String sTGT = org.aselect.server.utils.Utils.decodeCredentials(string_refresh_token,
									_systemLogger);
							

				   			HashMap previous_token = (HashMap)persistentStorage.get(REFRESH_TOKEN_PREFIX + sTGT);	// returns previous tgt
				   			if (previous_token != null) {
				   				// we should compare original scope to new scope
				   				// if original scope contained offline_access and new scope doesn't we might opt for not deleting
				   				// the refresh_token and not issuing a new refresh_token so refresh_token stays valid
				   				// for now we delete refresh_toekn and issue a new one based on the original scope
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "Removing previous token from persistent storage: " + REFRESH_TOKEN_PREFIX + sTGT);
				   				persistentStorage.remove(REFRESH_TOKEN_PREFIX + sTGT);

				   				// we should get requested scope from request and verify against saved_scope
				   				// scope requested might be less than saved_scope
								String saved_scope = (String)previous_token.get("oauthsessionscope");
								String saved_client_id = (String)previous_token.get("oauthsessionclient_id");
					        	String extractedRid = (String)previous_token.get("rid");
					        	
					        	String app_id = (String)previous_token.get("app_id");
					        	client_may_pass = false;
								// get app_id and client_may_pass = verify_auth_header(....) here
								if (ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_user() != null 
										&& ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_pwhash() != null) { // verify auth_header
									client_may_pass = verify_auth_header(auth_header, ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_user(),
											ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_pwhash(),
											ApplicationManager.getHandle().getApplication(app_id).getOauth2_client_credentials_pwhash_alg());
			
									appidacr = "1"; 	// client secret was used for authentication
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
											tokenMachine.setParameter("error", "invalid_client");
											//	return_status = 400; // default
											tokenMachine.setStatus(400);
										}
									}
									else {
										client_may_pass = true;
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client auth header present but not validated");
									}
								}
					        	
						   		if (client_may_pass) {	// All well
					   				///// create refreshed tgt
					   				String newsTgt = createRefreshTgt(previous_token);	// create new tgt from old refresh_token and updates (tgt) context
									_systemLogger.log(Level.FINEST, MODULE, sMethod, "newsTgt: " + newsTgt);
					   				// create new refresh_token
					   				String new_extractedAselect_credentials = (newsTgt == null) ? "" : CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(newsTgt));
									_systemLogger.log(Level.FINEST, MODULE, sMethod, "new_extractedAselect_credentials: " + new_extractedAselect_credentials);
						        	
									String verify_result = verify_credentials(null, new_extractedAselect_credentials, app_id, extractedRid);
						    		String extractedAttributes = verify_result.replaceFirst(".*attributes=([^&]*).*$", "$1");
									try {
										extractedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
									} catch (UnsupportedEncodingException e1) {
										// should not happen
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not URLDecode attributes: " + e1.getMessage());
										extractedAttributes = "";
									}	
//						    		HashMap hmExtractedAttributes = Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, o
						    		HashMap hmExtractedAttributes = org.aselect.server.utils.Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, n 
									_systemLogger.log(Level.FINEST, MODULE, sMethod, "hmExtractedAttributes after verify_credentials: " + Auxiliary.obfuscate(hmExtractedAttributes));
									
						    		String extractedResultCode = verify_result.replaceFirst(".*result_code=([^&]*).*$", "$1");
									_systemLogger.log(Level.FINEST, MODULE, sMethod, "extractedResultCode after verify_credentials: " + extractedResultCode);
						      
							        Boolean authenticatedAndApproved = false;
							        try {
							        	authenticatedAndApproved = Boolean.valueOf(Integer.parseInt(extractedResultCode) == 0);
							        } catch (NumberFormatException nfe ) {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Resultcode from aselectserver was non-numeric: " + extractedResultCode);
							   			tokenMachine.setParameter("error", "Internal error: " + nfe.getMessage() );
							   			//	return_status = 400; // default
							   			tokenMachine.setStatus(400);
							        }
					   				
							        if (authenticatedAndApproved) {
							    		String access_token = null;
							    		try {
							    			tokenMachine.setParameter("scope", saved_scope);
							    			tokenMachine.setParameter("issuer", getIssuer());
							    			tokenMachine.setParameter("client_id", saved_client_id);
								   			tokenMachine.setParameter("appidacr", appidacr);
	
								   			tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
								   			
								    		access_token = tokenMachine.createAccessToken(new_extractedAselect_credentials, hmExtractedAttributes, ASelectConfigManager.getHandle().getDefaultPrivateKey());
							    		}
										catch (UnsupportedEncodingException e) {
											_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported charset UTF-8, this should not happen!");	// RH, 20181126, n
								   			tokenMachine.setParameter("error", "Internal error: " + e.getMessage() );
								   			//	return_status = 400; // default
								   			tokenMachine.setStatus(400);
										} catch (JoseException e) {
											_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to serialize json, this should not happen!");	// RH, 20181126, n
								   			tokenMachine.setParameter("error", "Inreadable token error: " + e.getMessage() );
								   			//	return_status = 400; // default
								   			tokenMachine.setStatus(400);
										}
										SamlHistoryManager history = SamlHistoryManager.getHandle();
							        	String temp_authorization_code = tokenMachine.generateAuthorizationCode();
	
										if (saved_scope != null && saved_scope.contains("openid")) {
											//	generate the id_token using extractedAttributes
											String saved_nonce = (String)previous_token.get("oauthsessionnonce");
	
											try {
												tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
												String id_token = tokenMachine.createIDToken(hmExtractedAttributes, (String)(hmExtractedAttributes.get("uid")), getIssuer(), 
																							saved_client_id, saved_nonce, appidacr, ASelectConfigManager.getHandle().getDefaultPrivateKey(), 
														null );	// no code for refresh_token
	
												history.put(ID_TOKEN_PREFIX+ temp_authorization_code, id_token);	// maybe make this more efficient
											} catch (UnsupportedEncodingException e) {
												_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported charset UTF-8, this should not happen!");	// RH, 20181126, n
									   			tokenMachine.setParameter("error", "Internal error: " + e.getMessage() );
									   			tokenMachine.setStatus(400);
											} catch (JoseException e) {
												_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to serialize json, this should not happen!");	// RH, 20181126, n
									   			tokenMachine.setParameter("error", "Inreadable token error: " + e.getMessage() );
									   			tokenMachine.setStatus(400);
											}
										}
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "access_token: " + access_token);
										int status = supplyReturnParameters(temp_authorization_code, tokenMachine, history, access_token, previous_token, appidacr);
										tokenMachine.setStatus(status);
	
							        } else {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Verify credentials returned error code");
							   			tokenMachine.setParameter("error", "Token not or no longer valid" );
							   			//	return_status = 400; // default
							   			tokenMachine.setStatus(400);
							        }
						   		} else {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client auth header not validated");

						   			tokenMachine.setParameter("error", "invalid_client" );
						   			//	return_status = 401;
						   			tokenMachine.setStatus(401);
									servletResponse.setHeader("WWW-Authenticate", "Bearer realm=\"" + getMyServerID() + "\"" + " , " + "error=" + "\"" + tokenMachine.getParameter("error") + "\"");
						   			
						   		}

				   			} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Previus token not found in peristent storage");
					   			tokenMachine.setParameter("error", "invalid_request" );
					   			//	return_status = 400; // default
					   			tokenMachine.setStatus(400);
				   				
				   			}
				   		} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Refresh Token requested but not allowed");
				   			tokenMachine.setParameter("error", "invalid_request" );
				   			//	return_status = 400; // default
				   			tokenMachine.setStatus(400);
				   		}
			   		} else if ("password".equals(grant_type)) { //	Resource Owner Password Credentials Grant
				   		if (isAllow_password_credentials()) {

			        	client_may_pass = false;
						// get app_id and client_may_pass = verify_auth_header(....) here
			       		String forced_app_id_hint = findForcedAppidHint(servletRequest);
			       		// scope might be in the request

						if (client_id == null) {
							//
							client_id = getBasicAuthUser(auth_header);
							if ( client_id != null ) {
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Using client_id from BasicAuth:" + client_id);
							} else {
								//
								client_id = getPassword_credentials_client_id();
								_systemLogger.log(Level.INFO, MODULE, sMethod, "Using client_id from config:" + client_id);
							//
							}
						}
						String app_id = findAppid(client_id , forced_app_id_hint);
		        		// Handle unconfigured app_id
		    	   		if (app_id == null) {	//	unconfigured app_id
		    				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No app_id for client_id: " + client_id);
		    				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
		    	   		}
			       		String requestedScope = servletRequest.getParameter("scope");
			       		Set<String> requestedScopes = deserializeScopes(requestedScope);	// may return null
			       		Set<String> purifiedScopes = purifyScopes(requestedScopes, app_id);	// this handles default scopes as well
			       		String scope = serializeScopes(purifiedScopes);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using _forced_app_parameter/client_id/redirect_uri/scope/forced_app_id_hint" +
								(_forced_app_parameter != null ? ("/" + _forced_app_parameter) : "") + ": " + 
								client_id + "/" + redirect_uri + "/" + scope + (forced_app_id_hint != null ? ("/" + forced_app_id_hint) : ""));

						if (ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_user() != null 
								&& ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_pwhash() != null) { // verify auth_header
							client_may_pass = verify_auth_header(auth_header, ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_user(),
									ApplicationManager.getHandle().getApplication(app_id).getOauth_client_credentials_pwhash(),
									ApplicationManager.getHandle().getApplication(app_id).getOauth2_client_credentials_pwhash_alg());
	
							appidacr = "1"; 	// client secret was used for authentication
						}
						else { // don't verify auth_header, ONLY FOR TESTING
		
							if (auth_header == null) { // we must verify client_id
								if (client_id_valid(client_id)) {
									client_may_pass = true;
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "No client auth header but client_id valid, ONLY FOR TESTING");
								}
								else {
									_systemLogger.log(Level.WARNING, MODULE, sMethod,
											"No auth header and client_id not valid");
									tokenMachine.setParameter("error", "invalid_client");
									//	return_status = 400; // default
									tokenMachine.setStatus(400);
								}
							}
							else {
								client_may_pass = true;
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client auth header present but not validated, ONLY FOR TESTING");
							}
						}
				   		if (client_may_pass) {	// All well so far
				   		// call to requester
							HashMap password_verify_result = null;
							IAttributeRequestor passwordVerifyAttrRequestor = null;
							boolean response_client_may_pass = false;
							if (getPassword_credentials_verify_requestorid() != null) {
								// if the requestor is present it should have been initialized by the startup process by now.
								passwordVerifyAttrRequestor = (IAttributeRequestor)AttributeGatherer.getHandle().get_htRequestors().get(getPassword_credentials_verify_requestorid());
								Object attrSection = _configManager.getSection(null, "requestor", "id=" + getPassword_credentials_verify_requestorid());
								try {
									passwordVerifyAttrRequestor.init(attrSection);
									HashMap pwverifyContext = new HashMap();
									pwverifyContext.put("security_principal_dn", username);
									pwverifyContext.put("security_principal_password", password);
									Vector pwverifyAttr = new Vector();
									password_verify_result = passwordVerifyAttrRequestor.getAttributes(pwverifyContext, pwverifyAttr, pwverifyContext);
								} catch (ASelectAttributesException e) {
									_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not authenticate user/service: " + e.getMessage());
								} catch (Exception e) {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configuration error in requestor init: " + e.getMessage());
								}
								response_client_may_pass = (password_verify_result != null && password_verify_result.get("full_dn") != null && ((String)(password_verify_result.get("full_dn"))).length()>0);	// should be parameter
							} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Configuration error, no 'password_credentials_verify_requestorid' defined");
							}
							if (response_client_may_pass) {
					    		String ridReqURL = getAselectServerURL();
					    		String ridAselectServer = getMyServerID();
					    		String ridrequest= "authenticate";
					    		String ridAppURL =  getIdpfEndpointUrl();
								String ridResponse = "";
								// get a rid
					    		BufferedReader in = null;
					    		String extractedRid = null;
					    		try { 
						    		//Construct request data 
					        		String ridURL = assembleRidUrl(ridReqURL, ridAselectServer, ridrequest, ridAppURL,
											forced_app_id_hint, app_id);
					
					    			URL url = new URL(ridURL); 
					    			
					    			in = new BufferedReader(new InputStreamReader(url.openStream()));
					
					    			ridResponse = extractResponse(ridAselectServer, ridResponse, in);
						    		extractedRid = extractRid(ridResponse);
						    		
//									_htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, o
									HashMap _htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, n
									if (_htSessionContext != null) {
										// fill minimum set of tgt values
										_htSessionContext.put("oauthsessionscope", scope);
										_htSessionContext.put("oauthsessionclient_id", client_id);
										_htSessionContext.put("oauthsessionnonce", nonce);
										_htSessionContext.put("uid", password_verify_result.get("full_dn"));	// should be parameter
										_htSessionContext.put("authsp", getPassword_credentials_verify_requestorid());
										String level = "" + ApplicationManager.getHandle().getApplication(app_id).getMinLevel();	// make string
										_htSessionContext.put("app_level", level);
										_htSessionContext.put("sel_level", level);

										// create tgt
						   				String newsTgt = createRefreshTgt(_htSessionContext);	// create new tgt from _htSessionContext and updates (tgt) context
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "newsTgt: " + newsTgt);
						   				// create new refresh_token
						   				String new_extractedAselect_credentials = (newsTgt == null) ? "" : CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(newsTgt));
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "new_extractedAselect_credentials: " + new_extractedAselect_credentials);

										// do verify credentials
										String verify_result = verify_credentials(null, new_extractedAselect_credentials, app_id, extractedRid);
							    		String extractedAttributes = verify_result.replaceFirst(".*attributes=([^&]*).*$", "$1");
										try {
											extractedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
										} catch (UnsupportedEncodingException e1) {
											// should not happen
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not URLDecode attributes: " + e1.getMessage());
											extractedAttributes = "";
										}	
//							    		HashMap hmExtractedAttributes = Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, o
							    		HashMap hmExtractedAttributes = org.aselect.server.utils.Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, n
							    		
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "hmExtractedAttributes after verify_credentials: " + Auxiliary.obfuscate(hmExtractedAttributes));
										
							    		String extractedResultCode = verify_result.replaceFirst(".*result_code=([^&]*).*$", "$1");
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "extractedResultCode after verify_credentials: " + extractedResultCode);
							      
								        Boolean authenticatedAndApproved = false;
								        try {
								        	authenticatedAndApproved = Boolean.valueOf(Integer.parseInt(extractedResultCode) == 0);
								        } catch (NumberFormatException nfe ) {
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Resultcode from aselectserver was non-numeric: " + extractedResultCode);
								   			tokenMachine.setParameter("error", "Internal error: " + nfe.getMessage() );
								   			//	return_status = 400; // default
								   			tokenMachine.setStatus(400);
								        }

										// create token(s)
								        if (authenticatedAndApproved) {
								    		String access_token = null;
								    		try {
								    			if (scope != null) {
									    			tokenMachine.setParameter("scope", scope);
								    			}
								    			tokenMachine.setParameter("issuer", getIssuer());
								    			tokenMachine.setParameter("client_id", client_id);
									   			tokenMachine.setParameter("appidacr", appidacr);
		
									   			tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
									   			
									    		access_token = tokenMachine.createAccessToken(new_extractedAselect_credentials, hmExtractedAttributes, ASelectConfigManager.getHandle().getDefaultPrivateKey());
								    		}
											catch (UnsupportedEncodingException e) {
												_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported charset UTF-8, this should not happen!");	// RH, 20181126, n
									   			tokenMachine.setParameter("error", "Internal error: " + e.getMessage() );
									   			//	return_status = 400; // default
									   			tokenMachine.setStatus(400);
											} catch (JoseException e) {
												_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to serialize json, this should not happen!");	// RH, 20181126, n
									   			tokenMachine.setParameter("error", "Inreadable token error: " + e.getMessage() );
									   			//	return_status = 400; // default
									   			tokenMachine.setStatus(400);
											}
		
											SamlHistoryManager history = SamlHistoryManager.getHandle();
								        	String temp_authorization_code = tokenMachine.generateAuthorizationCode();

											if (scope != null && scope.contains("openid")) {
												try {
													tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
													
													String id_token = tokenMachine.createIDToken(hmExtractedAttributes, (String)(hmExtractedAttributes.get("uid")), getIssuer(), 
																								client_id, nonce, appidacr, ASelectConfigManager.getHandle().getDefaultPrivateKey(), 
															null );	// no code for refresh_token
													history.put(ID_TOKEN_PREFIX+ temp_authorization_code, id_token);	// maybe make this more efficient
		
												} catch (UnsupportedEncodingException e) {
													_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported charset UTF-8, this should not happen!");	// RH, 20181126, n
										   			tokenMachine.setParameter("error", "Internal error: " + e.getMessage() );
										   			tokenMachine.setStatus(400);
												} catch (JoseException e) {
													_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to serialize json, this should not happen!");	// RH, 20181126, n
										   			tokenMachine.setParameter("error", "Inreadable token error: " + e.getMessage() );
										   			tokenMachine.setStatus(400);
												}
											}
											_systemLogger.log(Level.FINEST, MODULE, sMethod, "access_token: " + access_token);
											int status = supplyReturnParameters(temp_authorization_code, tokenMachine, history, access_token, _htSessionContext, appidacr);
											tokenMachine.setStatus(status);
		
								        } else {
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Verify credentials returned error code");
								   			tokenMachine.setParameter("error", "invalid_grant" );
								   			//	return_status = 400; // default
								   			tokenMachine.setStatus(400);
								        }
										
									} else {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + extractedRid);
							   			tokenMachine.setParameter("error", "Internal error: " + "No session found for RID: " + extractedRid );
							   			//	return_status = 400; // default
							   			tokenMachine.setStatus(400);
										
									}
					    		}
					    		catch (Exception e) { 	
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve rid from aselectserver: " + ridAselectServer);
						   			tokenMachine.setParameter("error", "Internal error: " + e.getMessage() );
						   			//	return_status = 400; // default
						   			tokenMachine.setStatus(400);

					    		} finally {
//					    			_oSessionManager.deleteSession(extractedRid, _htSessionContext);	// RH, 20210413, o
					    			_oSessionManager.deleteSession(extractedRid, null);	// RH, 20210413, n
					    			if (in != null)
										try {
											in.close();
										}
										catch (IOException ioe) {
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
										}
					    		}
								
							} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Password Credentials Grant invalid credentials supplied");
					   			tokenMachine.setParameter("error", "invalid_grant" );
					   			//	return_status = 400; // default
					   			tokenMachine.setStatus(400);
							}
				   			
				   		} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Client auth header not validated");

				   			tokenMachine.setParameter("error", "invalid_client" );
				   			//	return_status = 401;
				   			tokenMachine.setStatus(401);
							servletResponse.setHeader("WWW-Authenticate", "Bearer realm=\"" + getMyServerID() + "\"" + " , " + "error=" + "\"" + tokenMachine.getParameter("error") + "\"");
				   			
				   		}
				   			
				   		} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Password Credentials Grant requested but not allowed");
				   			tokenMachine.setParameter("error", "invalid_request" );
				   			//	return_status = 400; // default
				   			tokenMachine.setStatus(400);
				   		}

			   		}
				   	
				   	else {	// handle empty code
		   				// return error 
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Empty code or invalid grant_type received");
			   			tokenMachine.setParameter("error", "invalid_grant" );
			   			//	return_status = 400; // default
			   			tokenMachine.setStatus(400);
			   		}
			   		servletResponse.setStatus(tokenMachine.getStatus());
			   		// return all JSON
		   			String out = tokenMachine.toJSONString();
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
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Token request should be POST");
				throw new ASelectException("Token request should be POST");
			}
		} else {	// Not a token request
			// and we might don't have credentials yet
	    	extractedAselect_credentials = servletRequest.getParameter("aselect_credentials");

	    	// RH, 20191205, sn
       		String prompt	 =  servletRequest.getParameter("prompt");
			ArrayList<String> prompts = new ArrayList<String>();

       		if (isPrompt_supported() && prompt != null) {
    			StringTokenizer tkn = new StringTokenizer(prompt);	// allow various separators, not only space
    			while (tkn.hasMoreTokens()) {
    				prompts.add(tkn.nextToken());
    			}
    			if ( prompts.contains("none") && prompts.size() > 1 ) {
    				// Specs not clear on type of error
    				_systemLogger.log(Level.WARNING, MODULE, sMethod, "prompt contains 'none' and some other value");
    				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
    			}
       			// prompt can have only distinct values
       			// none : id we have extractedAselect_credentials we should validate them (and maybe also validate consent) and pass the user
       			// else we should return an error
       			// not implemented yet
       			// login : prompt for reauthentication and pass user or return error if authentication fails
       			// not implemented yet, we should probably remove the tgt and set extractedAselect_credentials = null
       			// consent : prompt consent screen before continuing, error if no consent given
       			// not implemented yet
       			// select_account : prompt user to select an account, error if no account selected
       			// not implemented yet
       		}
	    	// RH, 20191205, en

	    	if (extractedAselect_credentials == null) {		// For now we don't care about previous authentication, let aselect handle that
		    	// authenticate to the aselect server
	    		String ridReqURL = getAselectServerURL();
	    		String ridAselectServer = getMyServerID();
	    		String ridrequest= "authenticate";
	    		String ridAppURL =  getIdpfEndpointUrl();
	    		
	    		String ridResponse = "";
	    		// First get request parameters
	    		String response_type = servletRequest.getParameter("response_type");
	       			    		   		
	    		String scopesRequested =  servletRequest.getParameter("scope");
    	   		// deserialize scope to Set
	       		Set<String> scopes	 =  deserializeScopes(scopesRequested);
	       		
	       		String state	 =  servletRequest.getParameter("state");
	       		String aud	 =  servletRequest.getParameter("aud");	// RH, 20191205, n	// additional audience(s) in claim
	       		
	       		// RH, 20190905, sn
	       		String response_mode	 =  servletRequest.getParameter("response_mode");
	       		if ( response_mode != null && !(RESPONSE_MODE_FORM_POST.equals(response_mode) || RESPONSE_MODE_QUERY.equals(response_mode)|| RESPONSE_MODE_FRAGMENT.equals(response_mode)) ) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid response_mode received:" + response_mode + " , continuing with default");
					// maybe we should return error, specs are not exclusive
	       			response_mode = null;
	       		}
	       		// RH, 20190905, en
				ArrayList<String> resp_types = new ArrayList<String>();

	       		String forced_app_id = findForcedAppidHint(servletRequest);

				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received client_id/redirect_uri/scope/state" +
						(_forced_app_parameter != null ? ("/" + _forced_app_parameter) : "") + ": " + 
						client_id + "/" + redirect_uri + "/" + scopesRequested + "/" + state + (forced_app_id != null ? ("/" + forced_app_id) : ""));

				String sAppId = findAppid(client_id, forced_app_id);
        		// Handle unconfigured app_id
    	   		if (sAppId == null) {	//	unconfigured app_id
    				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No app_id for client_id: " + client_id);
    				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
    	   		}
    	   		
    	   		// RH, 20200430, sn
	       		// handle scopes
    	   		Set<String> purifiedScopes = purifyScopes(scopes, sAppId);
    	   		// RH, 20200430, en
    	   		
    	   		HashMap<URI, String> validURIs = ApplicationManager.getHandle().getApplication(sAppId).getOauth_redirect_uri();
    	   		boolean validateClientID = ApplicationManager.getHandle().getApplication(sAppId).isOauth_verify_client_id();
    	   		boolean validateRedirectURI = ApplicationManager.getHandle().getApplication(sAppId).isOauth_verify_redirect_uri();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "validURIs: " + validURIs);
				URI redirectURI = null;
				if (Utils.hasValue(redirect_uri)) {
					try {
						redirectURI = new URI(redirect_uri);
					} catch (URISyntaxException e) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Requested redirect_uri not a valid uri: " + redirect_uri);
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				} else {
					// we supply default
					redirectURI = validURIs.keySet().iterator().next();	// just get the first, list should contain only one value if no redirect_uri specified 
				}

				// RH, 20191206, sn
    			if ( prompts.contains("none") ) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not logged in and prompt==none");
					String error_redirect = null;
					try {
			        	String error = "login_required";
						error_redirect = redirectURI.toString() + (redirectURI.toString().contains("?") ? "&" : "?") + "error=" + error 
//								+ ( ( state != null ) ? ("&state=" + state) : "");
								+ ( ( state != null ) ? ("&state=" + URLEncoder.encode(state, "UTF-8")) : "");
						servletResponse.sendRedirect(error_redirect);
						return null;
					} catch (IOException iox){
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
					}
    			}
    			
				// RH, 20191206, sn  // BW, 20211128, sn	 			  			
    			if (response_type == null || response_type.isEmpty()) { // default to code 
    				_systemLogger.log(Level.FINER, MODULE, sMethod, "No or empty response type received, default to code");
					resp_types.add("code"); // default because of Facebook but rfc says REQUIRED
    			} else  {
	           		StringTokenizer tkn = new StringTokenizer(response_type);	// allow various separators, not only space
	    			while (tkn.hasMoreTokens()) {
	    				resp_types.add(tkn.nextToken());
	    			}
	    			
	    			if (!(resp_types.contains("code") || resp_types.contains("id_token")) || !compareAllowedResponseTypes(resp_types, allowed_repons_type)) {
						
	    				if(!(resp_types.contains("code") || resp_types.contains("id_token"))) {
	    					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing valid response_type, allowed are code and/or id_token but received response_type: " + response_type);
	    				}
	    				
	    				if(!compareAllowedResponseTypes(resp_types, allowed_repons_type)){
		    				_systemLogger.log(Level.WARNING, MODULE, sMethod, allowedResponseTypesMessage(resp_types, allowed_repons_type) + " - Allowed response types: code and/or id_token ");
	    				}
	    										
	    				String error_redirect = null;
						
	    				try {
				        	String error = "unsupported_response_type";
							error_redirect = redirectURI.toString() + (redirectURI.toString().contains("?") ? "&" : "?") + "error=" + error 
//									+ ( ( state != null ) ? ("&state=" + state) : "");
									+ ( ( state != null ) ? ("&state=" + URLEncoder.encode(state, "UTF-8")) : "");
							servletResponse.sendRedirect(error_redirect);
							return null;
						} catch (IOException iox){
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
						}
	    			}
	    		}  
	   					
				if ( (validateClientID && !client_id_valid(client_id)) || (validateRedirectURI && !is_redirect_uri_valid(redirectURI, validURIs)) ) {	// we do not verify redirect_uri yet, but we should
					// 3.1.2.4.  Invalid Endpoint and 4.1.2.1.  Error Response
					// MUST NOT automatically redirect
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "client_id or redirect_uri invalid, MUST NOT automatically redirect user to: " + redirect_uri);
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
	       		
	    		// Send data 
	    		BufferedReader in = null;
	    		try { 
		    		//Construct request data 
	        		String ridURL = assembleRidUrl(ridReqURL, ridAselectServer, ridrequest, ridAppURL,
							forced_app_id, sAppId);
	
	    			URL url = new URL(ridURL); 
	    			
	    			in = new BufferedReader(new InputStreamReader(url.openStream()));
	
	    			ridResponse = extractResponse(ridAselectServer, ridResponse, in);
	    		}
	    		catch (Exception e) { 	
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve rid from aselectserver: " + ridAselectServer);
					String error_redirect = null;
					try {
					        	String error = "server_error";
			        			error_redirect = redirectURI.toString() + (redirectURI.toString().contains("?") ? "&" : "?") + "error=" + error 
							+ ( ( state != null ) ? ("&state=" + URLEncoder.encode(state, "UTF-8")) : "");
						servletResponse.sendRedirect(error_redirect);
		    			if (in != null)
							try {
								in.close();
							}
							catch (IOException ioe) {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
							}
						return null;
					} catch (IOException iox){
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
					}
	
	    		}
	
	    		String extractedRid = extractRid(ridResponse);
	
//				_htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, o
				HashMap _htSessionContext = _oSessionManager.getSessionContext(extractedRid);	// RH, 20210413, n
				if (_htSessionContext == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + extractedRid);
					String error_redirect = null;
					try {
					        	String error = "server_error";
			        			error_redirect = redirectURI.toString() + (redirectURI.toString().contains("?") ? "&" : "?") + "error=" + error 
//						+ ( ( state != null ) ? ("&state=" + state) : "");
							+ ( ( state != null ) ? ("&state=" + URLEncoder.encode(state, "UTF-8")) : "");
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
				_htSessionContext.put("oauthsessionresp_types", resp_types);
				if (purifiedScopes != null) {
					_htSessionContext.put("oauthsessionscope", serializeScopes(purifiedScopes));
				}
			
				if (state != null) {
					_htSessionContext.put("oauthsessionstate", state);
				}
				if (redirect_uri != null) {
	//				_htSessionContext.put("oauthsessionredirect_uri", state);	// RH, 20170606, o
					_htSessionContext.put("oauthsessionredirect_uri", redirect_uri);	// RH, 20170606, n
				}
				if (nonce != null) {
					_htSessionContext.put("oauthsessionnonce", nonce);
				}
				if (client_id != null) {	// should not be null here
					_htSessionContext.put("oauthsessionclient_id", client_id);
				}
				// RH, 20190905, sn
				if (response_mode != null) {
					_htSessionContext.put("oauthsessionresponse_mode", response_mode);
				}
				// RH, 20190905, en
				
				// RH, 20191206, sn
				if (aud != null) {
					_htSessionContext.put("oauthsessionaud", aud);
				}
				if (prompts.size() > 0) {
					_htSessionContext.put("oauthsessionprompts", prompts);
				}
				// RH, 20191206, en
				
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
				String saved_redirect_uri = null;
				String saved_response_mode = null;	// RH, 20190905, n

				if (htTGTContext != null) {
					org_javaxSessionid = (String)htTGTContext.get("oauthsessionid");
					saved_redirect_uri = (String)htTGTContext.get("oauthsessionredirect_uri");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "original javaxSessionid: " +org_javaxSessionid);
					saved_response_mode = (String)htTGTContext.get("oauthsessionresponse_mode");	// RH, 20190905, n
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "original response_mode: " +saved_response_mode);	// RH, 20190905, n
				} else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve tgt for aselect_credentials:  " +extractedAselect_credentials);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
				}
				if (!javaxSessionid.equals(org_javaxSessionid)) { 
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid sessionid found");
					String error_redirect = null;
					try {
					        	String error = "invalid_request";
					        	
//					        			error_redirect = saved_redirect_uri + (saved_redirect_uri.contains("?") ? "&" : "?") + "error=" + error ;	// RH, 20190906, o
					        			error_redirect =  "error=" + error ;	// RH, 20190906, n
//						servletResponse.sendRedirect(error_redirect);	// RH, 20190905, o
						transferToClient(servletRequest, servletResponse, saved_redirect_uri, error_redirect, saved_response_mode);	// RH, 20190905, n
						return null;
					} catch (IOException iox){
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
					}
				}
				
				// RH, 20191206, sn
				// Request user consent
				String oauthsessionconsent = (String)htTGTContext.get("oauthsessionconsent");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "oauthsessionconsent: " + oauthsessionconsent);
//				if (oauthsessionconsent == null) {	// maybe check for which claims here	// RH, 20200207, o
				// fix, Only request consent if consent form has been configured
				if (getConsentTemplate() != null && oauthsessionconsent == null) {	// maybe check for which claims here	// RH, 20200207, n
		    		String formToken = servletRequest.getParameter("form_token");
		    		String userconsent = servletRequest.getParameter("consent");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "form_token: " + formToken + ", consent: " + userconsent);

		    		if (formToken == null || userconsent == null) {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "No form_token or consent, start requesting consent");
						extractedAselect_credentials = servletRequest.getParameter("aselect_credentials");
						HashMap<String, String> parms = new HashMap<>();
						parms.put("aselect_credentials", extractedAselect_credentials);
						byte[] baFormToken = new byte[32];
						CryptoEngine.nextRandomBytes(baFormToken);
						formToken = Utils.byteArrayToHexString(baFormToken);
						htTGTContext.put("oauthsessionform_token", formToken);
						_tgtManager.updateTGT(sTgt, htTGTContext);
						parms.put("form_token", formToken);
//						parms.put("a-select-server", _sMyServerID);
						parms.put("a-select-server", getMyServerID());
						parms.put("consent", "OK");	// maybe put requested claims in consent
						String rid = (String)htTGTContext.get("rid");
						parms.put("rid", rid);
						//	parms.put("cancel", "");		// not sure yet what to do with cancel
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Requesting consent from user");
						
						requestConsent(servletRequest, servletResponse, getIdpfEndpointUrl(), parms);
						// maybe do some cleanup here
						return null;
		    		} else {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received form_token and consent, continuing");
		    			String savedFormToken = (String)htTGTContext.get("oauthsessionform_token");
		    			
//		    			if (!savedFormToken.equals(savedFormToken)) {	// RH, 20200207, o
		    			if (!formToken.equals(savedFormToken)) {	// RH, 20200207, n
		    				// form has been tempered with or not our request
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Form has been tempered with or not our request");
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
		    			} else {
		    				if (!"OK".equals(userconsent)) {
		    					// return error
		    					// transferToClient with error
		    				} else {
		    					// all well, continue
		    					oauthsessionconsent = "OK";	// maybe put requested claims instead of OK
								htTGTContext.put("oauthsessionconsent", oauthsessionconsent);
								_tgtManager.updateTGT(sTgt, htTGTContext);
		    				}
		    			}
		    		}
				}
				// RH, 20191206, sn
				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Handle the aselectserver response");
				String sAppId = (String)htTGTContext.get("app_id");
				String extractedRid = servletRequest.getParameter("rid");	// RH, 20200306, n

//				String finalResult  = verify_credentials(servletRequest, extractedAselect_credentials, sAppId);	// RH, 20200306, o
				String finalResult  = verify_credentials(servletRequest, extractedAselect_credentials, sAppId, extractedRid);	// RH, 20200306, n
				
	    		String extractedAttributes = finalResult.replaceFirst(".*attributes=([^&]*).*$", "$1");
	    		// RH, 20181108, sn
				try {
					extractedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
				} catch (UnsupportedEncodingException e1) {
					// should not happen
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not URLDecode attributes: " + e1.getMessage());
					extractedAttributes = "";
				}	
	    		// RH, 20181108, en
//	    		HashMap hmExtractedAttributes = Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, o
	    		HashMap hmExtractedAttributes = org.aselect.server.utils.Utils.deserializeAttributes(extractedAttributes);	// RH, 20200612, n
	    		
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "hmExtractedAttributes after verify_credentials: " + Auxiliary.obfuscate(hmExtractedAttributes));
	    		
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
//					        			error_redirect = saved_redirect_uri + (saved_redirect_uri.contains("?") ? "&" : "?") + "error=" + error ;	// RH, 20190906, o
					        			error_redirect = "error=" + error ;	// RH, 20190906, n
//						servletResponse.sendRedirect(error_redirect);	// RH, 20190905, o
						transferToClient(servletRequest, servletResponse, saved_redirect_uri, error_redirect, saved_response_mode);	// RH, 20190905, n
						return null;
					} catch (IOException iox){
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);
						throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
					}
		        }
//		        String return_url = null;	// RH, 20181126, o
				String saved_state = (String)htTGTContext.get("oauthsessionstate");
				String saved_client_id = (String)htTGTContext.get("oauthsessionclient_id");
				String saved_nonce = (String)htTGTContext.get("oauthsessionnonce");
				
				// saved_uri already verified
				if (saved_redirect_uri == null) {	// we did receive a redirect_url upon authentication so use registered one
					saved_redirect_uri = ApplicationManager.getHandle().getApplication(sAppId).getOauth_redirect_uri().keySet().iterator().next().toString();
				}
//				String sep = saved_redirect_uri.contains("?") ? "&" : "?";	// RH, 20181126, n	// RH, 20190906, o
				String sep = "";// RH, 20190906, n
//		        StringBuffer return_url = new StringBuffer(saved_redirect_uri);	// RH, 20181126, n	// RH, 20190906, o
		        StringBuffer return_url = new StringBuffer();	// RH, 20181126, n	// RH, 20190906, o
		        
		        if (authenticatedAndApproved) {
					// If authenticatedAndApproved then send off the user with redirect

					String saved_scope = (String)htTGTContext.get("oauthsessionscope");
					ArrayList<String> saved_resp_types = (ArrayList<String>)htTGTContext.get("oauthsessionresp_types");	// not sure if we support this
		        	String generated_authorization_code = tokenMachine.generateAuthorizationCode();
	
		        	// RH, 201191210, so
		        	// For now store in HistoryManager
//		    		HashMap<String, String> authorization_code = new HashMap<String, String>();
//		    		authorization_code.put("aselect_credentials", extractedAselect_credentials);
		        	// RH, 201191210, eo
					// Store it in the history for later retrieval by token request
		    		String access_token = null;
		    		try {
		    			tokenMachine.setParameter("scope", saved_scope);
		    			tokenMachine.setParameter("issuer", getIssuer());
		    			tokenMachine.setParameter("client_id", saved_client_id);
		    			tokenMachine.setParameter("appidacr", appidacr);

		    			tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
		    			
			    		access_token = tokenMachine.createAccessToken(extractedAselect_credentials, hmExtractedAttributes, ASelectConfigManager.getHandle().getDefaultPrivateKey());
					}
					catch (UnsupportedEncodingException e) {
//						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");	// RH, 20181126, o
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported charset UTF-8, this should not happen!");	// RH, 20181126, n
//						String error_redirect = null;	// RH, 20181126, o
						try {
							// RH, 20181126, so
//						        	String error = "server_error";
////						        			error_redirect = getOauth2_redirect_uri() + (getOauth2_redirect_uri().contains("?") ? "&" : "?") + "error=" + error ;
//						        	error_redirect = saved_redirect_uri + (saved_redirect_uri.contains("?") ? "&" : "?") + "error=" + error ;
//							servletResponse.sendRedirect(error_redirect);
							// RH, 20181126, eo
							// RH, 20181126, sn
				        	String error = "server_error_" + "Unsupported_charset_UTF-8" ;
				        	return_url.append(sep).append("error=" + error);
				        	sep = "&";
				        	if (saved_state != null) {
				        		return_url.append(sep).append("state=" + URLEncoder.encode(saved_state, "UTF-8"));
				        	}
//							servletResponse.sendRedirect(return_url.toString());	// RH, 20190905, o
							transferToClient(servletRequest, servletResponse, saved_redirect_uri, return_url.toString(), saved_response_mode);	// RH, 20190905, n
							// RH, 20181126, en
							return null;
						} catch (IOException iox){
//							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + error_redirect);	// RH, 20181126, o
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + return_url);	// RH, 20181126, n
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
						}
					} catch (JoseException e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to serialize json, this should not happen!");	// RH, 20181126, n
						try {
				        	String error = "server_error_" + "Unsupported_charset_UTF-8" ;
				        	return_url.append(sep).append("error=" + error);
				        	sep = "&";
				        	if (saved_state != null) {
				        		return_url.append(sep).append("state=" + URLEncoder.encode(saved_state, "UTF-8"));
				        	}
	//						servletResponse.sendRedirect(return_url.toString());	// RH, 20190905, o
							transferToClient(servletRequest, servletResponse, saved_redirect_uri, return_url.toString(), saved_response_mode);
						} catch (IOException e1) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect user to: " + return_url);	// RH, 20181126, n
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
						}	// RH, 20190905, n
						// RH, 20181126, en
						return null;
					}
		    		// store in HistoryManager	// RH, 201191210, n
					SamlHistoryManager history = SamlHistoryManager.getHandle();
					history.put(AUTH_CODE_PREFIX+ generated_authorization_code, access_token);
					// if scope contains openid, also generate the id_token
					String id_token = null;
					if (saved_scope != null && saved_scope.contains("openid")) {
						//	generate the id_token using extractedAttributes
						try {
//							id_token = createIDToken(hmExtractedAttributes, (String)(hmExtractedAttributes.get("uid")), _sMyServerID, saved_client_id, saved_nonce, appidacr );	// RH, 20181114, o
							tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
							id_token = tokenMachine.createIDToken(hmExtractedAttributes, (String)(hmExtractedAttributes.get("uid")), getIssuer(), 
																		saved_client_id, saved_nonce, appidacr, ASelectConfigManager.getHandle().getDefaultPrivateKey(), 
//									saved_resp_types.contains("id_token") ? generated_authorization_code : null );	// RH, 20181114, n	// RH, 20181129, o
									saved_resp_types.contains("code") ? generated_authorization_code : null );	// RH, 20181114, n	// RH, 20181129, n
//							history.put(ID_TOKEN_PREFIX+ generated_authorization_code, id_token);	// RH, 20181129, n
							// RH, 20181129, sn
							if (saved_resp_types.contains("code")) {	// only store the id_token for later retrieval if code requested
								history.put(ID_TOKEN_PREFIX+ generated_authorization_code, id_token);
							}
							// RH, 20181129, en
//						} catch (UnsupportedEncodingException | JoseException e) {	// RH, 20181001, o, 1.6 compliance
						} catch (UnsupportedEncodingException e) {
							// should redirect to caller with error
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create id_token, UnsupportedEncodinG");
							throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
						} catch (JoseException e) {
							// should redirect to caller with error
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create id_token, Jose PROBLEM");
							throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
						}
					}
		        	
					// if response_type included id_token, also return the token as id_token parameter
					// RH, 20181126, so
//					return_url = saved_redirect_uri + (saved_redirect_uri.contains("?") ? "&" : "?") + "code=" + generated_authorization_code 
//							+ ( ( saved_state != null ) ? ("&state=" + saved_state) : "") ;
//					if (saved_resp_types.contains("id_token")) {
//						// include id_token in response
//						return_url += "&id_token=" + id_token;
//					}
					// RH, 20181126, eo
					// RH, 20181126, sn
					if (saved_resp_types.contains("code")) {
						return_url.append(sep).append("code=" + generated_authorization_code);
						sep = "&";
					}
					if (saved_resp_types.contains("id_token")) {
						// include id_token in response
						return_url.append(sep).append("id_token=" + id_token);
						sep = "&";
					}
					if (saved_state != null) {
//						return_url.append(sep).append("state=" + saved_state);
						try {
							return_url.append(sep).append("state=" + URLEncoder.encode(saved_state, "UTF-8"));
						} catch (UnsupportedEncodingException e) {
							// should not happen
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode state, UnsupportedEncodinG");
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
						}
					}
					// RH, 20181126, en
		        } else {	// only happy flow implemented
		        	String error = "access_denied";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not authenticate user, authentication failed with resultcode: " + extractedResultCode);
					// RH, 20181126, so
//					return_url = saved_redirect_uri + (saved_redirect_uri.contains("?") ? "&" : "?") + "error=" + error 
//							+ ( ( saved_state != null ) ? ("&state=" + saved_state) : "");
					// RH, 20181126, eo
					// RH, 20181126, sn
					return_url.append(sep).append("error=" + error );
					sep = "&";
					if (saved_state != null) {
						try {
							return_url.append(sep).append("state=" + URLEncoder.encode(saved_state, "UTF-8"));
						} catch (UnsupportedEncodingException e) {
							// should not happen
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode state, UnsupportedEncodinG");
							throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
						}
					}
					// RH, 20181126, en
		        }
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirecting to:  " + return_url);	// RH, 20190906, o
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Transfering to:  " + return_url);	// RH, 20190906, n
	        	try {
//					servletResponse.sendRedirect(return_url);	// RH, 20181126, o
//					servletResponse.sendRedirect(return_url.toString());	// RH, 20181126, n		// RH, 20190905, o
					transferToClient(servletRequest, servletResponse, saved_redirect_uri, return_url.toString(), saved_response_mode);	// RH, 20190905, n
				}
				catch (IOException e) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}
		        
		    }
		} // Not a token request
		return null;
	}

	/**
	 * @param sMethod
	 * @param ridResponse
	 * @return
	 */
	protected String extractRid(String ridResponse) {
		
		String sMethod = "extractRid";

		String extractedRid = ridResponse.replaceFirst(".*rid=([^&]*).*$", "$1");
		_systemLogger.log(Level.FINER, MODULE, sMethod, "rid retrieved: " + extractedRid);
		return extractedRid;
	}

	/**
	 * @param sMethod
	 * @param ridAselectServer
	 * @param ridResponse
	 * @param in
	 * @return
	 * @throws IOException
	 */
	protected String extractResponse(String ridAselectServer, String ridResponse, BufferedReader in)
			throws IOException {

		String sMethod = "extractResponse";

		String inputLine = null;
		while ((inputLine = in.readLine()) != null) {
			ridResponse += inputLine;
		}
		_systemLogger.log(Level.FINER, MODULE, sMethod, "Requested rid response: " + ridResponse);
		if (in != null)
			try {
				in.close();
			}
			catch (IOException ioe) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + ridAselectServer);
			}
		return ridResponse;
	}

	/**
	 * @param sMethod
	 * @param ridReqURL
	 * @param ridAselectServer
	 * @param ridrequest
	 * @param ridAppURL
	 * @param forced_app_id
	 * @param sAppId
	 * @return
	 * @throws ASelectException
	 * @throws UnsupportedEncodingException
	 */
	protected String assembleRidUrl(String ridReqURL, String ridAselectServer, String ridrequest,
			String ridAppURL, String forced_app_id, String sAppId)
			throws ASelectException, UnsupportedEncodingException {
		
		String sMethod = "assembleRidUrl";

		String uid;
		String ridSharedSecret = ApplicationManager.getHandle().getApplication(sAppId).getSharedSecret();;
		if (ridSharedSecret == null) {	// this is a configuration error, there should be a sharedsecret
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No sharedsecret for app_id: " + sAppId);
			throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
		}
		// RH, 20181001, sn
		uid = ApplicationManager.getHandle().getApplication(sAppId).getForcedUid();
		if (uid == null) {
			uid = defaultUID;
		}
		// RH, 20181001, sn
		
		// RH, 20190514, sn
		// Add to appurl for later retrieval by parameters2forward
		if (_forced_app_parameter != null && forced_app_id != null) {
			if (ridAppURL.contains("?")) {
				ridAppURL += "&";
			} else {
				if (!ridAppURL.endsWith("/")) {
					ridAppURL += "/";
				}
				ridAppURL += "?";
			}
//	        			ridAppURL += _forced_app_parameter + "=" + forced_app_id;	// RH, 20190604, o
			ridAppURL += _forced_app_parameter + "=" + URLEncoder.encode(forced_app_id, "UTF-8") ;	// RH, 20190604, n	// we need to double urlencode
		}
		// RH, 20190514, en
		
		// Still to add signature to RID request
		String ridURL = ridReqURL + "?" + "shared_secret=" + URLEncoder.encode(ridSharedSecret, "UTF-8") +
				"&a-select-server=" + URLEncoder.encode(ridAselectServer, "UTF-8") +
				"&request=" + URLEncoder.encode(ridrequest, "UTF-8") +
				"&uid=" + URLEncoder.encode(uid, "UTF-8") +
				 // RM_30_01
				"&app_url=" + URLEncoder.encode(ridAppURL, "UTF-8") +		    				
//			    				"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
				"&app_id=" + URLEncoder.encode(sAppId, "UTF-8");
		_systemLogger.log(Level.FINER, MODULE, sMethod, "Requesting rid from: " + ridReqURL + " , with app_url: " + ridAppURL + " , and app_id: " + sAppId);
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "ridURL: " + Auxiliary.obfuscate(ridURL));
		return ridURL;
	}

	/**
	 * @param client_id
	 * @param forced_app_id_hint
	 * @return
	 */
	protected String findAppid(String client_id, String forced_app_id_hint) {
		String sAppId = getClientIds().get(client_id);
		if (forced_app_id_hint != null) {
			// RH, 20190523, sn
			if (get_forced_app_ids() != null && get_forced_app_ids().size() > 0 ) {
				sAppId = get_forced_app_ids().get(forced_app_id_hint);
			} else {
				// no forced_app_ids configured, use appid from client_id table
			}
			// RH, 20190523, en
		}
		return sAppId;
	}

	/**
	 * @param servletRequest
	 * @return
	 */
	protected String findForcedAppidHint(HttpServletRequest servletRequest) {
		String forced_app_id_hint = null;
		if (_forced_app_parameter != null && _forced_app_parameter.length() > 0) {
			forced_app_id_hint	 =  servletRequest.getParameter(_forced_app_parameter);	// can contain sort of login_hint
		}
		return forced_app_id_hint;
	}

	/**
	 * @param servletRequest
	 * @return
	 */
	protected String findScope(HttpServletRequest servletRequest, String defaultScope) {
		String scope = servletRequest.getParameter("scope");
		if (scope == null && defaultScope != null) {
			scope =  defaultScope;
		}
		return scope;
	}

	protected String createRefreshTgt(HashMap htTGTContext) {
		String sMethod = "createRefreshTgt";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Creating new tgt");
			// maybe set some new values in the context here
			String tgt = null;
			try {
				tgt = TGTManager.getHandle().createTGT(htTGTContext);
			} catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem creating tgt: " + e.getMessage());
			}

		return tgt;
	}

	protected String extractAccessToken(String access_token) {
		// for standard oauth we do nothing here
		return access_token;
	}

	/**
	 * @param sMethod
	 * @param code
	 * @param return_parameters
	 * @param history
	 * @param access_token
	 * @param tgt
	 * @return HTTP return code
	 * @throws ASelectStorageException
	 */
	protected int supplyReturnParameters(String code, ITokenMachine tokenMachine,
			SamlHistoryManager history, String access_token, HashMap tgt, String appidacr) throws ASelectStorageException {
		
		String sMethod = "supplyReturnParameters";

		// Also retrieve the id_token if there is one (Must have been requested with scope parameter in earlier Auth request
		String saved_scope = (String)tgt.get("oauthsessionscope");

		if (saved_scope != null && saved_scope.contains("openid")) {
			if (history != null) {	// get info from historymanager
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Creating new id_token from history");
				String id_token = (String)history.get(ID_TOKEN_PREFIX + code);
				if (id_token != null) {
					// we should generate new id_token with proper appidacr
					//	return_parameters.put("id_token", id_token );
					tokenMachine.setParameter("id_token", id_token );
					try {
						history.remove(ID_TOKEN_PREFIX + code);	// we'll have to handle if there would be a problem with remove
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Removed id token from local storage using auth code: " + Auxiliary.obfuscate(code));
					} catch (ASelectStorageException ase2) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Ignoring problem removing id token from temp storage: " + ase2.getMessage());
					}
				}
			} else {	// create new id_token, 	// we should check the currently requested scope, it might not contain "openid"
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to retrieve id_token from history manager");
			}
		}
		if (isAllow_refresh_token() && (saved_scope != null) && (saved_scope.contains("offline_access"))) {
			try {
				// generate random
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Creating new refresh_token");
				byte[] baRandomBytes = new byte[120];	// just like a tgt
		
				CryptoEngine.nextRandomBytes(baRandomBytes);
				String storeToken = Utils.byteArrayToHexString(baRandomBytes);	// mimic the sTgt
				boolean createOK = persistentStorage.create(REFRESH_TOKEN_PREFIX + storeToken, tgt); // save original tgt
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "persistentStorage.create: " + createOK);
				
				if (createOK) {
					String extractedrefresh_credentials = CryptoEngine.getHandle().encryptTGT(baRandomBytes);
					tokenMachine.setKid(generateKeyID());	// RH, 20211014, n
			 		String refresh_token = tokenMachine.createRefreshToken(extractedrefresh_credentials, tgt, ASelectConfigManager.getHandle().getDefaultPrivateKey());	// still to generate refresh token
					//	return_parameters.put("refresh_token", refresh_token);
					tokenMachine.setParameter("refresh_token", refresh_token);
				} else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem with persistent storage while storing refresh_token");
					// not sure about setting status if problem only with refresh_token, specs not conclusive 
				}
			} catch (UnsupportedEncodingException | JoseException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem creating refresh_token" + e.getMessage());
			} catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem encrypting refresh_token" + e.getMessage());
			}
		}
		
		tokenMachine.setParameter("access_token", access_token );
		tokenMachine.setParameter("token_type", "bearer" );
		tokenMachine.setParameter("expires_in", DEFAULT_EXPIRES_IN );
//		return_status = 200; // all well
		tokenMachine.setStatus(200); // all well
		return tokenMachine.getStatus();
	}

	private boolean verify_auth_header(String auth_header, String user, String pwhash, String alg)
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
						String credashexstring =  Utils.byteArrayToHexString(mdDigest(cred[1], alg));
						if ( user.equals(cred[0]) && pwhash.equalsIgnoreCase(credashexstring) ) {
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

	
	private String getBasicAuthUser(String auth_header)
	{
		String sMethod = "getBasicAuthUser";

		String result = null;
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
						result = cred[0];
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
	
	

	private boolean is_redirect_uri_valid(URI redirect_uri, HashMap<URI, String> validuris) {
		String sMethod = "redirect_uri_valid";
			for (URI uri: validuris.keySet()) {
				if (uri.equals(redirect_uri)) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Requested redirect_uri valid: " + redirect_uri);
					return true;
				}
			}
		return false;
	}

	private boolean client_id_valid(String client_id)
	{
		if (isVerifyClientID()) {
			return getClientIds().keySet().contains(client_id);
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
//	private String verify_credentials(HttpServletRequest request, String extracted_credentials, String app_id)
	private String verify_credentials(HttpServletRequest request, String extracted_credentials, String app_id, String extractedRid)
	throws ASelectCommunicationException
	{
		String sMethod = "verify_credentials";
		String finalReqURL = getAselectServerURL();
		String finalReqAselectServer = getMyServerID();
		String finalReqrequest= "verify_credentials";
		
		//Construct request data
		String finalRequestURL = null;
		try {
    		String finalReqSharedSecret = ApplicationManager.getHandle().getApplication(app_id).getSharedSecret();;

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
		} catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Invalid client_id or no app_id for client_id");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, e);
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

	public synchronized HashMap<String, String> getClientIds() {
		return _client_ids;
	}

	public synchronized HashMap<String, String> get_forced_app_ids() {
		return _forced_app_ids;
	}

	public synchronized String get_forced_app_parameter() {
		return _forced_app_parameter;
	}

	public synchronized void set_forced_app_parameter(String _forced_app_parameter) {
		this._forced_app_parameter = _forced_app_parameter;
	}

	public synchronized void set_forced_app_ids(HashMap<String, String> _forced_app_ids) {
		this._forced_app_ids = _forced_app_ids;
	}

	public synchronized void setClientIds(HashMap<String, String> _client_ids) {
		this._client_ids = _client_ids;
	}


	public synchronized boolean isPrompt_supported() {
		return prompt_supported;
	}

	public synchronized void setPrompt_supported(boolean prompt_supported) {
		this.prompt_supported = prompt_supported;
	}

	public synchronized String getConsentTemplate() {
		return sConsentTemplate;
	}

	public synchronized void setConsentTemplate(String sConsentTemplate) {
		this.sConsentTemplate = sConsentTemplate;
	}
	
	/**
	 * @return the allow_refresh_token
	 */
	public synchronized boolean isAllow_refresh_token() {
		return allow_refresh_token;
	}

	/**
	 * @param allow_refresh_token the allow_refresh_token to set
	 */
	public synchronized void setAllow_refresh_token(boolean allow_refresh_token) {
		this.allow_refresh_token = allow_refresh_token;
	}

	/**
	 * @return the allow_password_credentials
	 */
	public synchronized boolean isAllow_password_credentials() {
		return allow_password_credentials;
	}

	/**
	 * @param allow_password_credentials the allow_password_credentials to set
	 */
	public synchronized void setAllow_password_credentials(boolean allow_password_credentials) {
		this.allow_password_credentials = allow_password_credentials;
	}

	/**
	 * @return the sRefresh_token_storage_manager
	 */
	public synchronized String getRefresh_token_storage_manager() {
		return sRefresh_token_storage_manager;
	}

	/**
	 * @param sRefresh_token_storage_manager the sRefresh_token_storage_manager to set
	 */
	public synchronized void setRefresh_token_storage_manager(String sRefresh_token_storage_manager) {
		this.sRefresh_token_storage_manager = sRefresh_token_storage_manager;
	}

	/**
	 * @return the sPassword_credentials_verify_requester
	 */
	public synchronized String getPassword_credentials_verify_requestorid() {
		return sPassword_credentials_verify_requestorid;
	}

	/**
	 * @param sPassword_credentials_verify_requester the sPassword_credentials_verify_requester to set
	 */
	public synchronized void setPassword_credentials_verify_requestorid(String sPassword_credentials_verify_requester) {
		this.sPassword_credentials_verify_requestorid = sPassword_credentials_verify_requester;
	}

	/**
	 * @return the sPassword_credentials_client_id
	 */
	public synchronized String getPassword_credentials_client_id() {
		return sPassword_credentials_client_id;
	}

	/**
	 * @param sPassword_credentials_client_id the sPassword_credentials_client_id to set
	 */
	public synchronized void setPassword_credentials_client_id(String sPassword_credentials_client_id) {
		this.sPassword_credentials_client_id = sPassword_credentials_client_id;
	}

	protected ITokenMachine createTokenMachine() {
		return  new TokenMachine();
	}

	
	// RH, 20191206, sn
	public void requestConsent(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String action_url, HashMap<String, String> parms) throws ASelectException {

		String sMethod = "requestConsent";
		String sTemplate = getConsentTemplate();
		if (sTemplate != null) {
			String sInputLines = ""; 
			for (String s : parms.keySet()) {
				sInputLines += buildHtmlInput(Tools.htmlEncode(s), Tools.htmlEncode(parms.get(s)));
			}
			handlePostForm(sTemplate, action_url, sInputLines,
					servletRequest, servletResponse);
		}
		return;
	}
		
	// RH, 20191206, sn

		
	// RH, 20190905, sn
	/**
	 * 
	 * @param servletResponse
	 * @param return_url
	 * @param response_mode	one of query, fragment or form_post
	 * @throws IOException
	 * @throws ASelectException 
	 */
	public void transferToClient(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String action_url, String querystring, String response_mode) throws IOException, ASelectException {

		String sMethod = "transferToClient";

		if (RESPONSE_MODE_FORM_POST.equals(response_mode)) {
			String sTemplate = getPostTemplate();
			if (sTemplate != null) {
				HashMap<String, String> queryparameters = Utils.convertCGIMessage(querystring, false);
				Set<String> parmnames = queryparameters.keySet();
				String sInputLines = ""; 
				for (String s : parmnames) {
					sInputLines += buildHtmlInput(Tools.htmlEncode(s), Tools.htmlEncode(queryparameters.get(s)));
				}
				handlePostForm(sTemplate, action_url, sInputLines,
						servletRequest, servletResponse);
				return;
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "response_mode:" + response_mode + " not allowed, doing default");
			}
		} else if (RESPONSE_MODE_FRAGMENT.equals(response_mode)) {
			String return_url = action_url + (action_url.contains("#") ? "&" : "#") + querystring;
			servletResponse.sendRedirect(return_url);
			return;
		}
		// default
		String return_url = action_url + (action_url.contains("?") ? "&" : "?") + querystring;
		servletResponse.sendRedirect(return_url);
		return;
	}
	// RH, 20190905, en
	
	// BW, 20211117, sn
	private static boolean compareAllowedResponseTypes(List<String> response_type, List<String> allowed_reponse_type) {
		for (String str : response_type) {
			if (!allowed_reponse_type.contains(str)) {
				return false;
			}
		}
		return true;
	}	
	
	private String allowedResponseTypesMessage(List<String> response_type, List<String> allowed_reponse_type) {
		StringBuilder message = new StringBuilder();
		for (String str : response_type) {
			if (!allowed_reponse_type.contains(str)) {
				message.append(str + " ");
			}
		}
		if (message.length() != 0) {
			message.insert(0, "Response type(s) not allowed: ");
			return message.toString();
		} else {
			return "Response type(s) allowed";
		}	
	} // BW, 20211128, en
}
