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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.session.PersistentStorageManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;

/**
 * OAUTH2 Authorization BaseHandler. <br>
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
public class OPBaseHandler extends ProtoRequestHandler
{
	private final static String MODULE = "OPBaseHandler";
	private final static String HTTPS_SCHEME = "https://";
	
	protected final static int HTTP_OK = 200;
	protected final static int HTTP_NoContent = 204;
	protected final static int HTTP_MovedPermanently = 301;
	protected final static int HTTP_Found = 302;
	protected final static int HTTP_SeeOther = 303;
	protected final static int HTTP_TemporaryRedirect = 307;
	protected final static int HTTP_BadRequest = 400;
	protected final static int HTTP_Unauthorized = 401;
	protected final static int HTTP_Forbidden = 403;
	protected final static int HTTP_NotFound = 404;
	protected final static int HTTP_MethodNotAllowed = 405;
	protected final static int HTTP_InternalServerError = 500;
	protected final static int HTTP_NotImplemented = 501;
	protected final static int HTTP_BadGateway = 502;
	protected final static int HTTP_ServiceUnavailable = 503;
	protected final static int HTTP_GatewayTimeout = 504;
	
	protected final static String DEFAULT_PW_HASH_METHOD = "SHA-256";

	private String _sMyServerID = null;
	private String aselectServerURL = null;
	private String issuer = null;

	protected PersistentStorageManager persistentStorage = null;
	protected Pattern scopePattern = Pattern.compile("[\\x21\\x23-\\x5B\\x5D-\\x7E]+");
	protected final static String[] HANDLERDEFAULTSCOPES = {"openid", "offline_access"};   
	protected Set<String> handlerDefaultScopes =  new HashSet<String>();


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
				String sIssuer = _configManager.getParam(oConfig, "issuer");
				issuer = sIssuer;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No config item 'issuer' found, using defaults");
				if (!_sMyServerID.startsWith(HTTPS_SCHEME)) {
					issuer = HTTPS_SCHEME + getMyServerID();
				} else {
					issuer = getMyServerID();
				}
			}
			
			handlerDefaultScopes.addAll(Arrays.asList(HANDLERDEFAULTSCOPES));
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
		_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"This method should have been be overriden");
		return null;
	}

	/**
	 * @return the _sMyServerID
	 */
	public synchronized String getMyServerID() {
		return _sMyServerID;
	}

	/**
	 * @param _sMyServerID the _sMyServerID to set
	 */
	public synchronized void setMyServerID(String _sMyServerID) {
		this._sMyServerID = _sMyServerID;
	}

	/**
	 * @return the aselectServerURL
	 */
	public synchronized String getAselectServerURL() {
		return aselectServerURL;
	}

	/**
	 * @param aselectServerURL the aselectServerURL to set
	 */
	public synchronized void setAselectServerURL(String aselectServerURL) {
		this.aselectServerURL = aselectServerURL;
	}

	/**
	 * @return the issuer
	 */
	public synchronized String getIssuer() {
		return issuer;
	}

	/**
	 * @param issuer the issuer to set
	 */
	public synchronized void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	/**
	 * 
	 * Splits scopes in Set and validates scope-tokens
	 * @param scopeRequested
	 * @return Set containing validated scopes
	 */
	protected Set<String> deserializeScopes(String scopeRequested) {
		String sMethod = "deserializeScopes";
		HashSet<String> scopes = null;
		if (scopeRequested != null) {
			scopes = new HashSet<String>();
			StringTokenizer tkn = new StringTokenizer(scopeRequested, " ");	// scopes must be seperated by spaces
			while (tkn.hasMoreTokens()) {
				String token = tkn.nextToken();
				if ( scopePattern.matcher(token).matches() ) {
					scopes.add(token);
				} else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Skipping invalid scope:" + token);
				}
			}
		}
		return scopes;
	}

	protected String serializeScopes(Set<String> scopes) {
		String sScopes = null;
		if (scopes != null) {
			StringBuffer serializedScopes = new StringBuffer();
			for (String s : scopes) {
				serializedScopes.append(s).append(' ');
			}
			sScopes = serializedScopes.toString().trim();	// remove trailing space
		}
		return sScopes;
	}

	protected Set<String> purifyScopes(Set<String> scopes, String sAppId) throws ASelectException {
		String sMethod = "purifyScopes";
		Set<String> purifiedScopes = null;
		if (scopes != null) {
			purifiedScopes = new HashSet<String>();
			// compare scopes and reject invalid
			if (ApplicationManager.getHandle().getApplication(sAppId).getOauth2AllowedScopesPatterns() != null) {
				Set<Pattern> validScopePatterns = ApplicationManager.getHandle().getApplication(sAppId).getOauth2AllowedScopesPatterns().keySet();
				_systemLogger.log(Level.FINEST, MODULE, sMethod,
						"Verifying requestedscopes against AllowedScopes:" + validScopePatterns);
				for (String s : scopes) {
					boolean added = false;
					for (Pattern p : validScopePatterns) {
						if (p.matcher(s).matches()) {
							purifiedScopes.add(s);
							added = true;
							break;
						}
					}
					if (!added) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Scope rejected:" + s);
					}
				}
			} else {
				// verify against handler default scopes
				_systemLogger.log(Level.FINEST, MODULE, sMethod,
						"Verifying requestedscopes against System Defaultscopes:" + handlerDefaultScopes);
				for (String s : scopes) {
					boolean added = false;
					for (String defaultScope : handlerDefaultScopes) {
						if (defaultScope.equals(s)) {
							purifiedScopes.add(s);
							added = true;
							break;
						}
					}
					if (!added) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Scope rejected:" + s);
					}
				}
			}
		} else {
			if (ApplicationManager.getHandle().getApplication(sAppId).getOauth2DefaultScopes() != null) {
				// if no scope supplied and we have defaults defined
				_systemLogger.log(Level.FINEST, MODULE, sMethod,
						"Using application Defaultscopes");
				purifiedScopes = new HashSet<String>();
				purifiedScopes.addAll(ApplicationManager.getHandle().getApplication(sAppId).getOauth2DefaultScopes().keySet());
			}
		}
		return purifiedScopes;
	}


}
