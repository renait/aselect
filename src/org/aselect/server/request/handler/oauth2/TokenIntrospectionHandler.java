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
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

import net.sf.json.JSON;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

/**
 * OAUTH2 TokenIntrospectionHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as an OAuth2 request handler 
 *  It handles OAUTH2 Token Introspection (Validation) requests
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>TokenIntrospectionHandler</code><br>
 * 
 * @author RH
 */
public class TokenIntrospectionHandler extends OPBaseHandler

{
	private final static String MODULE = "TokenIntrospectionHandler";
	
	private String oauthClientCredentialsUser = null;
	private String oauthClientCredentialsPwHash = null;
	private String oauth2ClientCredentialsPwhashAlg = null;

	
	
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
				oauthClientCredentialsUser = _configManager.getParam(oConfig, "client_credentials_user");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'client_credentials_user' found, authentication disabled");
			}

			try {
				oauthClientCredentialsPwHash = _configManager.getParam(oConfig, "client_credentials_pwhash");
				oauth2ClientCredentialsPwhashAlg = _configManager.getParamFromSection(oConfig, "client_credentials_pwhash", "algorithm", false);
				if (oauth2ClientCredentialsPwhashAlg == null) {
					oauth2ClientCredentialsPwhashAlg = DEFAULT_PW_HASH_METHOD;
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'algorithm' found for 'oauth2_client_credentials_pwhash', using default: " + oauth2ClientCredentialsPwhashAlg);
				}
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'client_credentials_pwhash' found, authentication disabled");
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
		
		// rfc7662 says MUST be POST
		Map<String, Object> return_parameters = new HashMap<String, Object>();
		String token =  servletRequest.getParameter("token");	// maybe use this as app_id as well, need some security though
   		String token_type_hint =  servletRequest.getParameter("token_type_hint");	// we'll ignore token_type_hint for now

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received token/token_type_hint: " + 
				Auxiliary.obfuscate(token) + " / " + token_type_hint);

		// Request, should be POST
		if ( "POST".equalsIgnoreCase(servletRequest.getMethod()) ) {
	   		PrintWriter outwriter = null;
			int status = 400;	// default
			try {
				outwriter = Utils.prepareForHtmlOutput(servletRequest , servletResponse, "application/json" );
				Utils.setDisableCachingHttpHeaders(servletRequest , servletResponse);
				
				if (token != null && token.length() > 0) {	// Token verification requested
					
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handling token verification POST request");
					
					String auth_header = servletRequest.getHeader("Authorization");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found HTTP 'Authorization' header: " + Auxiliary.obfuscate(auth_header));
	
					boolean client_may_pass = false;
						// maybe we want application specific authorization later but we don't have an appid now
//						if (ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_user() != null 
//								&& ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_pwhash() != null) { // verify auth_header
//							client_may_pass = verify_auth_header(auth_header, ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_user(),
//									ApplicationManager.getHandle().getApplication(sAppId).getOauth_client_credentials_pwhash(),
//									ApplicationManager.getHandle().getApplication(sAppId).getOauth2_client_credentials_pwhash_alg());
//	
//						}
					if (getOauthClientCredentialsUser() != null 
							&& getOauthClientCredentialsPwHash() != null) { // verify auth_header
						client_may_pass = verify_auth_header(auth_header, getOauthClientCredentialsUser(),
								 getOauthClientCredentialsPwHash(),
								getOauth2ClientCredentialsPwhashAlg());

					}
					else { // don't verify auth_header
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "No client auth header verification! Client may pass");
						client_may_pass = true;
					}

			   		if (client_may_pass) {	// All well
						status = 200;
			   			if (isTokenValid(token)) {
			   				return_parameters.put("active", true );
			   			} else {
				   			return_parameters.put("active", false );
			   			}
			   		} else {
			   			return_parameters.put("error", "client_authentication_failed" );
			   			status = 401;
//						servletResponse.setHeader("WWW-Authenticate", "Basic realm=\"" + getMyServerID() + "\"" + " , " + "error=" + "\"" + "client_authentication_failed" + "\"");
			   		}
				} else {	// No token received
					return_parameters.put("error", "invalid_request");
				} // Not a valid token request
		   		servletResponse.setStatus(status);
		   		// return all JSON
	   			String out = ((JSONObject) JSONSerializer.toJSON( return_parameters )).toString(0); 
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
		} else {	// not a POST
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request must be POST");
			// Maybe change throw to responding with error
//   			return_parameters.put("error", "invalid method" );
//   			return_status = 400; // default
//			if (outwriter != null) {
//				outwriter.close();
//			}
			throw new ASelectException("Token request should be POST");
		}
		return null;
	}

	private boolean isTokenValid(String token) {
		// verify token here
		String sMethod = "isTokenValid";
		
		boolean tokenValid = false;
		String string_access_token = null;;

		// we MUST support all types of tokens here
		// if jwt token, first extract the tgt
		if (token.indexOf('{') >= 0) {	// first check
			try {
	            JSON jsonResponse = JSONSerializer.toJSON(token);
	            if (jsonResponse instanceof JSONObject) {
	                JSONObject object = (JSONObject) jsonResponse;
	                if (object.containsKey("aselect_credentials")) {
	                	string_access_token = object.getString("aselect_credentials");
	                }
	            }
	        } catch (JSONException ex) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Object received invalid JSON object: " + ex.getMessage());
	        }
		} else {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] bytes_access_token = b64dec.decodeBuffer(token);
			try {
				string_access_token = new String(bytes_access_token, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UnsupportedEncodingException: " + e.getMessage());
			}
		}
		
		String sTGT = null;
		try {
			sTGT = org.aselect.server.utils.Utils.decodeCredentials(string_access_token,
					_systemLogger);
			HashMap tgt = TGTManager.getHandle().getTGT(sTGT);
			String sAppId = (String)tgt.get("app_id");
			if (sAppId != null) {	// maybe use other verification method(s)
				tokenValid = true;
			}
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "ASelectException: " + e.getMessage());
		}
		return tokenValid;
	}

	// should go to OPBaseHandler
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
	
	

	/**
	 * @return the oauthClientCredentialsUser
	 */
	public synchronized String getOauthClientCredentialsUser() {
		return oauthClientCredentialsUser;
	}

	/**
	 * @param oauthClientCredentialsUser the oauthClientCredentialsUser to set
	 */
	public synchronized void setOauthClientCredentialsUser(String oauthClientCredentialsUser) {
		this.oauthClientCredentialsUser = oauthClientCredentialsUser;
	}

	/**
	 * @return the oauthClientCredentialsPwHash
	 */
	public synchronized String getOauthClientCredentialsPwHash() {
		return oauthClientCredentialsPwHash;
	}

	/**
	 * @param oauthClientCredentialsPwHash the oauthClientCredentialsPwHash to set
	 */
	public synchronized void setOauthClientCredentialsPwHash(String oauthClientCredentialsPwHash) {
		this.oauthClientCredentialsPwHash = oauthClientCredentialsPwHash;
	}

	/**
	 * @return the oauth2ClientCredentialsPwhashAlg
	 */
	public synchronized String getOauth2ClientCredentialsPwhashAlg() {
		return oauth2ClientCredentialsPwhashAlg;
	}

	/**
	 * @param oauth2ClientCredentialsPwhashAlg the oauth2ClientCredentialsPwhashAlg to set
	 */
	public synchronized void setOauth2ClientCredentialsPwhashAlg(String oauth2ClientCredentialsPwhashAlg) {
		this.oauth2ClientCredentialsPwhashAlg = oauth2ClientCredentialsPwhashAlg;
	}

}
