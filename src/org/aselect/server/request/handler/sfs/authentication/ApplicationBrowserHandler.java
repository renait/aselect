/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: ApplicationBrowserHandler.java,v 1.1.2.1 2007/03/05 11:35:04 maarten Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationBrowserHandler.java,v $
 * Revision 1.1.2.1  2007/03/05 11:35:04  maarten
 * SFS Request Handlers
 *
 * Revision 1.1.2.12  2006/12/14 14:13:34  maarten
 * Updated ARP
 *
 * Revision 1.1.2.11  2006/11/27 13:52:53  leon
 * Fixed no UDB configured and attribute release
 *
 * Revision 1.1.2.10  2006/11/24 14:19:52  leon
 * some null and empty checks added
 *
 * Revision 1.1.2.9  2006/11/23 09:41:47  leon
 * fixed bug: Because sessions were not always updated when something changed, strange errors occurs when the session are stored in a DB.
 *
 * Revision 1.1.2.8  2006/11/22 09:27:20  maarten
 * Updated version
 * Updated home_organization functionality
 * Fixed signing bug
 *
 * Revision 1.1.2.7  2006/09/22 12:11:48  maarten
 * Updated version
 *
 * Revision 1.1.2.6  2006/09/05 14:30:32  maarten
 * Updated version
 *
 * Revision 1.1.2.5  2006/09/05 08:43:47  maarten
 * Updated version
 *
 * Revision 1.1.2.4  2006/09/04 14:05:24  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.3  2006/09/04 13:55:52  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.2  2006/09/04 13:44:23  leon
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2006/09/04 08:52:26  leon
 * SFS Handlers
 *
 * Revision 1.19  2006/05/03 10:10:45  tom
 * Removed Javadoc version
 *
 * Revision 1.18  2006/04/26 09:17:32  leon
 * fixed bug #202
 *
 * Revision 1.17  2006/04/07 07:35:36  leon
 * javadoc added and small bugfix
 *
 * Revision 1.16  2006/04/06 08:43:18  leon
 * removed function
 *
 * Revision 1.15  2006/04/05 12:56:43  leon
 * *** empty log message ***
 *
 * Revision 1.14  2006/03/21 07:35:03  leon
 * Code cleaning
 *
 * Revision 1.13  2006/03/20 12:27:01  martijn
 * level is stored in session as an Integer object
 *
 * Revision 1.12  2006/03/20 11:27:57  martijn
 * updateTemplate() has been moved to ConfigManager
 *
 * Revision 1.11  2006/03/20 10:12:21  leon
 * function renamed
 *
 * Revision 1.10  2006/03/20 10:09:12  leon
 * moved direct login to handler
 *
 * Revision 1.9  2006/03/16 14:47:41  martijn
 * fixed bug in calling updateTemplate in handleLogout
 *
 * Revision 1.8  2006/03/16 10:46:29  martijn
 * added support for showing optional application info in user info page
 *
 * Revision 1.7  2006/03/16 10:34:24  martijn
 * added support for showwing optional application info in html templates
 *
 * Revision 1.6  2006/03/16 08:18:18  leon
 * extra functions for direct login handling
 *
 * Revision 1.5  2006/03/14 11:24:44  martijn
 * fixed support for optional application info tags in login1 and login2
 *
 * Revision 1.4  2006/03/09 12:37:33  jeroen
 * Adaptations for NiceName (partly implemented)
 *
 * Revision 1.3  2006/03/07 14:30:33  leon
 * some redundant code removed.
 *
 * Revision 1.2  2006/03/07 14:18:04  leon
 * If user not is found in the local UDB it is now possible to swich to cross mode
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.4  2006/02/08 08:07:34  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.3  2006/02/02 10:26:56  martijn
 * changes after refactor
 *
 * Revision 1.2  2006/01/25 14:40:05  martijn
 * TGTManager and SessionManager changed
 */
package org.aselect.server.request.handler.sfs.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.handler.sfs.authentication.ASelectBrowserHandler;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * This class handles login requests coming from applications through a users browser. <br>
 * <br>
 * <b>Description:</b> <br>
 * This Class handles the following requests:
 * <ul>
 * <li><code>logout</code></li>
 * <li><code>login1</code></li>
 * <li><code>login2</code></li>
 * <li><code>login3</code></li>
 * <li><code>ip_login</code></li>
 * <li><code>direct_loginx</code></li>
 * <li><code>cross_login</code></li>
 * <li><code>create_tgt</code></li>
 * </ul>
 * <br>
 * If no request is sent the user info (if available) page is shown
 * 
 * @author Alfa & Ariss
 */
public class ApplicationBrowserHandler extends AbstractBrowserRequestHandler
{
	private HashMap _htSessionContext;

	private ApplicationManager _applicationManager;

	private CrossASelectManager _crossASelectManager;

	private AuthSPHandlerManager _authspHandlerManager;

	private CryptoEngine _cryptoEngine;

	private ASelectConfigManager _configManager;

	/**
	 * Constructor for ApplicationBrowserHandler. <br>
	 * 
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param sMyServerId
	 *            The A-Select Server ID.
	 * @param sMyOrg
	 *            The A-Select Server organisation.
	 */
	public ApplicationBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "ApplicationBrowserHandler";
		_applicationManager = ApplicationManager.getHandle();
		_authspHandlerManager = AuthSPHandlerManager.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
		_configManager = ASelectConfigManager.getHandle();
	}

	/**
	 * process application browser requests <br>
	 * <br>
	 * .
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.sfs.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRequest;
		String sRid;
		String sMethod = "processBrowserRequest";

		sRequest = (String) htServiceRequest.get("request");
		if (sRequest == null) {
			// show info page if nothing to do
			if (htServiceRequest.containsKey("aselect_credentials_uid"))
				showUserInfo(htServiceRequest, _servletResponse, pwOut);
			else {
				String sServerInfoForm = _configManager.getHTMLForm("serverinfo", "", "");
				sServerInfoForm = Utils.replaceString(sServerInfoForm, "[message]", " ");
				pwOut.println(sServerInfoForm);
			}
		}
		else if (sRequest.equals("logout") || (sRequest.equals("cross_logout"))) {
			handleLogout(htServiceRequest, _servletResponse, pwOut);
		}
		else {
			// Precondition
			sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Precondition
			// If a valid session is found, it will be valid during the whole
			// servlet request handling.
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			String sDirectAuthSP = (String) _htSessionContext.get("direct_authsp");
			if (sDirectAuthSP != null && !(sRequest.indexOf("direct_login") >= 0)) {
				_systemLogger
						.log(Level.WARNING, _sModule, sMethod, "Probably tampered request with rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// Not a direct_authsp chosen OR it's a direct_login request

			if (sRequest.equals("login1")) {
				handleLogin1(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login2")) {
				handleLogin2(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login3")) {
				handleLogin3(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("cross_login")) {
				handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("ip_login")) {
				handleIPLogin1(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.indexOf("direct_login") >= 0) {
				handleDirectLogin(htServiceRequest, _servletRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("create_tgt")) {
				handleCreateTGT(htServiceRequest, _servletResponse);
			}
			else {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
	}

	/**
	 * Handles the <code>request=direct_login</code> requests. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * All the requests which contains direct_login (e.g. direct_login1, direct_login2) will be handled by this function
	 * and send to the direct authsp handler. <code>request=cross_login</code> instead. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * A session with a <code>rid</code> should be created first using:
	 * <ul>
	 * <li><code>ApplicationRequestHandler.handleAuthenticateRequest()</code>
	 * </ul>
	 * <code>htLoginRequest</code> should contain this <code>rid</code> parameter. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleDirectLogin(HashMap htServiceRequest, HttpServletRequest servletRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleDirectLogin";
		String sRid = null;
		try {
			sRid = (String) htServiceRequest.get("rid");
			String sAuthSPId = (String) _htSessionContext.get("direct_authsp");
			if (sAuthSPId == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing 'direct_authsp' in session, rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			IAuthSPDirectLoginProtocolHandler oProtocolHandler = _authspHandlerManager.getAuthSPDirectLoginProtocolHandler(sAuthSPId);

			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// check if a request was done for an other user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				String sForcedOrganization = (String) _htSessionContext.get("forced_organization");
				if ((sForcedUid != null && !sUid.equals(sForcedUid)) // user_id
						|| (sForcedOrganization != null)) {
					_tgtManager.remove(sTgt);
				}
				else {
					if (checkCredentials(sTgt, sUid, sServerId)) // valid credentials/level/SSO group
					{
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (boolForced == null)
							boolForced = false;
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							// redirect to application as user has already a valid tgt
							String sRedirectUrl;
							if (_htSessionContext.get("remote_session") == null) {
								sRedirectUrl = (String) _htSessionContext.get("app_url");
							}
							else {
								sRedirectUrl = (String) _htSessionContext.get("local_as_url");
							}
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							HashMap htTGTContext = _tgtManager.getTGT(sTgt);

							String sAppId = (String) _htSessionContext.get("app_id");
							if (sAppId != null)
								htTGTContext.put("app_id", sAppId);

							String sLocalOrg = (String) _htSessionContext.get("local_organization");
							if (sLocalOrg != null)
								htTGTContext.put("local_organization", sLocalOrg);

							htTGTContext.put("rid", sRid);
							_tgtManager.updateTGT(sTgt, htTGTContext);

							String sLogAsAppId = (String) htTGTContext.get("local_organization");
							if (sLogAsAppId == null) {
								sLogAsAppId = (String) htTGTContext.get("app_id");
							}
							ASelectAuthenticationLogger.getHandle().log(
									new Object[] {
										"SSO", Auxiliary.obfuscate(sUid), (String) htServiceRequest.get("client_ip"),
										htTGTContext.get("organization"), sLogAsAppId, "updated"
									});

							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
							String sLang = (String)htTGTContext.get("language");
							oTGTIssuer.sendTgtRedirect(sRedirectUrl, sTgt, sRid, servletResponse, sLang);
							_sessionManager.deleteSession(sRid, _htSessionContext);
							return;
						}
					}
					// TGT found but not sufficient.
					// Authenicate with same user-id that was stored in TGT
					HashMap htTGTContext = _tgtManager.getTGT(sTgt);

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg)) {
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						handleCrossLogin(htServiceRequest, servletResponse, pwOut);
						return;
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					// showDirectLoginForm(htServiceRequest,pwOut);
					oProtocolHandler.handleDirectLoginRequest(htServiceRequest, servletRequest, servletResponse, _htSessionContext, null, pwOut, _sMyServerId, "", "");
					return;
				}
			}
			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			if (sForcedUid != null) {
				htServiceRequest.put("user_id", sForcedUid);
				// showDirectLoginForm(htServiceRequest,pwOut);
				oProtocolHandler.handleDirectLoginRequest(htServiceRequest, servletRequest, servletResponse, _htSessionContext, null, pwOut, _sMyServerId, "", "");
				return;
			}
			oProtocolHandler.handleDirectLoginRequest(htServiceRequest, servletRequest, servletResponse, _htSessionContext, null, pwOut, _sMyServerId, "", "");

			// Store changed session, for JDBC Storage Handler
			if (!_sessionManager.updateSession(sRid, _htSessionContext)) {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Handles the <code>request=login1</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * First user request. If the user already has a valid TGT, the user is redirected back to the application (or the
	 * local A-Select Server in case of cross A-Select).<br>
	 * If no valid TGT is found, the user is presented an HTML page asking for a user name. The HTML page implements a
	 * HTML-form that will POST a <code>request=login2</code>. If the user is not from this organizatio, the HTML-form
	 * might POST a <code>request=cross_login</code> instead. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * A session with a <code>rid</code> should be created first using:
	 * <ul>
	 * <li><code>ApplicationRequestHandler.handleAuthenticateRequest()</code>
	 * <li><code>ApplicationRequestHandler.handleCrossAuthenticateRequest()</code>
	 * </ul>
	 * <code>htLoginRequest</code> should contain this <code>rid</code> parameter. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin1(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleLogin1";
		String sRid = null;
		StringBuffer sbUrl;

		try {
			sRid = (String) htServiceRequest.get("rid");

			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// check if a request was done for an other user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				String sForcedOrganization = (String) _htSessionContext.get("forced_organization");
				if ((sForcedUid != null && !sUid.equals(sForcedUid)) // user_id
						|| (sForcedOrganization != null)) {
					_tgtManager.remove(sTgt);
				}
				else {
					if (checkCredentials(sTgt, sUid, sServerId)) // valid credentials/level/SSO group
					{
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (boolForced == null)
							boolForced = false;
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							// redirect to application as user has already a valid tgt
							String sRedirectUrl;
							if (_htSessionContext.get("remote_session") == null) {
								sRedirectUrl = (String) _htSessionContext.get("app_url");
							}
							else {
								sRedirectUrl = (String) _htSessionContext.get("local_as_url");
							}
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							HashMap htTGTContext = _tgtManager.getTGT(sTgt);

							String sAppId = (String) _htSessionContext.get("app_id");
							if (sAppId != null)
								htTGTContext.put("app_id", sAppId);

							String sLocalOrg = (String) _htSessionContext.get("local_organization");
							if (sLocalOrg != null)
								htTGTContext.put("local_organization", sLocalOrg);

							htTGTContext.put("rid", sRid);
							_tgtManager.updateTGT(sTgt, htTGTContext);

							String sLogAsAppId = (String) htTGTContext.get("local_organization");
							if (sLogAsAppId == null) {
								sLogAsAppId = (String) htTGTContext.get("app_id");
							}
							ASelectAuthenticationLogger.getHandle().log(
									new Object[] {
										"SSO", Auxiliary.obfuscate(sUid), (String) htServiceRequest.get("client_ip"),
										htTGTContext.get("organization"), sLogAsAppId, "updated"
									});

							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
							String sLang = (String)htTGTContext.get("language");
							oTGTIssuer.sendTgtRedirect(sRedirectUrl, sTgt, sRid, servletResponse, sLang);
							_sessionManager.deleteSession(sRid, _htSessionContext);
							return;
						}
					}
					// TGT found but not sufficient.
					// Authenicate with same user-id that was stored in TGT
					HashMap htTGTContext = _tgtManager.getTGT(sTgt);

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg)) {
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						// It isn't necessary to update the session here, because it will be done in handleCrossLogin.
						handleCrossLogin(htServiceRequest, servletResponse, pwOut);
						return;
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					handleLogin2(htServiceRequest, servletResponse, pwOut);
					return;
				}
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			if (sForcedUid != null) {
				htServiceRequest.put("user_id", sForcedUid);
			}

			String sLoginUrl = (String) _htSessionContext.get("login_url");
			if (sLoginUrl != null) {
				sbUrl = new StringBuffer(sLoginUrl);
				sbUrl.append("&rid=").append(sRid);
				sbUrl.append("&a-select-server=").append(_sMyServerId);
				servletResponse.sendRedirect(sbUrl.toString());
				return;
			}

			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return;
			}

			if (sForcedUid != null) {
				handleLogin2(htServiceRequest, servletResponse, pwOut);
				return;
			}

			// show login (user_id) form
			String sLoginForm = _configManager.getHTMLForm("login", "", "");
			sLoginForm = Utils.replaceString(sLoginForm, "[rid]", sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sLoginForm = Utils.replaceString(sLoginForm, "[a-select-server]", _sMyServerId);
			sLoginForm = Utils.replaceString(sLoginForm, "[request]", "login2");
			sLoginForm = Utils.replaceString(sLoginForm, "[cross_request]", "cross_login");

			sbUrl = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error").append(
					"&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(
					_sMyServerId).append("&rid=").append(sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[cancel]", sbUrl.toString());

			sLoginForm = _configManager.updateTemplate(sLoginForm, _htSessionContext, _servletRequest);
			pwOut.println(sLoginForm);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Handles the <code>request=login2</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request created by the HTML page presented by the <code>handleLogin1</code> function, is verified here.<br>
	 * For the entered user-id a lookup is done in the user database to determine all enabled AuthSP's for this user.
	 * For every AuthSP a verification is done if it matches the required level.<br>
	 * All valid AuthSP's are presnted to the user by means of a 'drop-down' list in a HTML page. This HTML page will
	 * POST a <code>request=login3</code>.<br>
	 * Depending on the A-Select configuration <code>always_show_select_form</code> the request can be parsed to
	 * <code>handleLogin3()</code> immediately if only one valid AuthSP is found. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin2(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRid = null;
		String sUid = null;
		String sMethod = "handleLogin2";

		StringBuffer sb;
		try {
			sRid = (String) htServiceRequest.get("rid");

			sUid = (String) htServiceRequest.get("user_id");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'user_id'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// If uid contains any spaces, they where transformed to '+'
			// Now first set it back to spaces
			try {
				sUid = URLDecoder.decode(sUid, "UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to decode user id.", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}

			try {
				getAuthsps(sRid, sUid);
			}
			catch (ASelectException e) {
				if (_crossASelectManager.isCrossSelectorEnabled() && _configManager.isCrossFallBackEnabled()) {
					handleCrossLogin(htServiceRequest, servletResponse, pwOut);
					return;
				}
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve AuthSPs of user " + sUid);
				throw e;
			}

			// we have now the list of authsps that the user may use
			// show the selectform

			HashMap htAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
			// should the user be bothered with the selection form
			// if it is only able to choose from 1 method?
			if (htAuthsps.size() == 1) {
				try {
					String sFormShow = _configManager.getParam(_configManager.getSection(null, "authsps"),
							"always_show_select_form");
					if (sFormShow.equalsIgnoreCase("false")) {
						// continue with login3
						Set keys = htAuthsps.keySet();
						for (Object s : keys) {
							htServiceRequest.put("authsp", (String) s);
							break;
						}
						handleLogin3(htServiceRequest, servletResponse, pwOut);
						return;
					}
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Failed to retrieve config 'always_show_select_form'. Using default (yes).", e);
				}
			}
			// end only 1 valid authsp

			String sSelectForm = _configManager.getHTMLForm("select", "", "");
			sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
			sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
			sSelectForm = Utils.replaceString(sSelectForm, "[user_id]", sUid);
			sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sSelectForm = Utils.replaceString(sSelectForm, "[request]", "login3");

			String sFriendlyName = "";
			sb = new StringBuffer();
			Set keys = htAuthsps.keySet();
			for (Object s : keys) {
				String sAuthspName = (String) s;
				// Enumeration enumAuthspEnum = htAuthsps.keys();
				// while (enumAuthspEnum.hasMoreElements()) {
				try {
					// sAuthspName = (String) enumAuthspEnum.nextElement();
					Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
							"authsp", "id=" + sAuthspName);
					sFriendlyName = _configManager.getParam(authSPsection, "friendly_name");

					sb.append("<OPTION VALUE=");
					sb.append(sAuthspName);
					sb.append(">");
					sb.append(sFriendlyName);
					sb.append("</OPTION>");
				}
				catch (ASelectConfigException ace) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.", ace);
					throw ace;
				}
			}
			sSelectForm = Utils.replaceString(sSelectForm, "[allowed_user_authsps]", sb.toString());

			sb = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error").append(
					"&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(
					_sMyServerId).append("&rid=").append(sRid);

			sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sb.toString());

			sSelectForm = _configManager.updateTemplate(sSelectForm, _htSessionContext, _servletRequest);
			pwOut.println(sSelectForm);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This methods handles the <code>request=login3</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The user has now chosen a method for authentication and is ready to be redirected to the AuthSP's authentication
	 * page. <br>
	 * The protocol handler for the AuthSP is instantiated and that object will compute the request for authentication
	 * (e.g., it will also sign the request). The actual method that does this is <code>startAuthentication</code>.<br>
	 * If everything is ok, the user is redirected through the <code>servletResponse.sendRedirect()</code> method with a
	 * signed request for the AuthSP. <br>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogin3(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{

		String sRid = null;
		String sAuthsp = null;
		String sMethod = "handleLogin3";
		String sRedirectUrl = null;
		String sPopup = null;

		try {
			sRid = (String) htServiceRequest.get("rid");
			sAuthsp = (String) htServiceRequest.get("authsp");
			if (sAuthsp == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'authsp'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			sRedirectUrl = startAuthentication(sRid, htServiceRequest);
			try {
				Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
						"id=" + sAuthsp);
				try {
					sPopup = _configManager.getParam(authSPsection, "popup");
				}
				catch (ASelectConfigException e) {
					// No popup configured -> sPopup is null allready
				}

				if (sPopup == null || sPopup.equalsIgnoreCase("false")) {
					servletResponse.sendRedirect(sRedirectUrl);
					return;
				}

				// must use popup so show the popup page
				String sPopupForm = _configManager.getHTMLForm("popup", "", "");
				sPopupForm = Utils.replaceString(sPopupForm, "[authsp_url]", sRedirectUrl);

				String strFriendlyName = _configManager.getParam(authSPsection, "friendly_name");

				sPopupForm = Utils.replaceString(sPopupForm, "[authsp]", strFriendlyName);

				sPopupForm = _configManager.updateTemplate(sPopupForm, _htSessionContext, _servletRequest);
				pwOut.println(sPopupForm);
				return;

			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.", e);
				throw new ASelectException(e.getMessage());
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.", e);
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=cross_login</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * If the user already has a tgt and it is valid for the current application, then the user does not need be
	 * authenticated again. The user is redirected back to the application. If the user's tgt is not valid, then the
	 * remote A-Select Server is contacted by sending a <code>request=cross_authenticate_aselect</code> request. If the
	 * remote A-Select Server is contacted successfully, the user is redirected to him so that the user can be
	 * authenticated there. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            PrintWriter that might be needed by the <code>ISelectorHandler</code>
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleCrossLogin(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRemoteOrg = null;
		String sUid = null;
		String sHomeIdp = null;
		String sMethod = "handleCrossLogin";

		try {
			// is cross enabled? (configuration)
			if (!_crossASelectManager.remoteServersEnabled()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Cross A-Select is disabled since it is not (properly) configured.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
			}

			String sLocalRid = (String) htServiceRequest.get("rid");
			Integer intAppLevel = (Integer) _htSessionContext.get("level");
			if (intAppLevel == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not fetch level from session context.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			sRemoteOrg = (String) _htSessionContext.get("forced_organization");

			sHomeIdp = (String) htServiceRequest.get("home_organization");
			if (sHomeIdp != null) {
				sHomeIdp = URLDecoder.decode(sHomeIdp, "UTF-8");
			}

			String sCompareUid = (String) htServiceRequest.get("user_id");

			if (sCompareUid != null && !sCompareUid.trim().equals("")) {
				sUid = (String) htServiceRequest.get("user_id");
			}

			if (sRemoteOrg == null) {
				if (!_crossASelectManager.isCrossSelectorEnabled()) {
					_systemLogger
							.log(Level.WARNING, _sModule, sMethod,
									"Dynamic 'cross_selector' is disabled, parameter 'remote_organization' is required but not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}

				// No optional parameter 'remote_organization found
				// Determine the remote organization
				HashMap htIdentification;

				// some selector handlers may need the user_id if it is known already
				if (sUid != null) {
					htServiceRequest.put("user_id", sUid);
				}

				Cookie[] aCookies = _servletRequest.getCookies();

				String sHomeIdpCookie = null;

				if (aCookies != null) {
					for (int i = 0; i < aCookies.length; i++) {
						if (aCookies[i].getName().equals("aselect_home_idp")) {
							sHomeIdpCookie = aCookies[i].getValue();
							// remove '"' surrounding cookie if applicable
							int iLength = sHomeIdpCookie.length();
							if (sHomeIdpCookie.charAt(0) == '"' && sHomeIdpCookie.charAt(iLength - 1) == '"') {
								sHomeIdpCookie = sHomeIdpCookie.substring(1, iLength - 1);
							}
						}
					}
				}

				if (sHomeIdpCookie != null) {
					htServiceRequest.put("aselect_home_idp", sHomeIdpCookie);
				}

				try {
					// CrossASelectManager oIdentificationFactory = CrossASelectManager.getHandle();
					htIdentification = _crossASelectManager.getSelectorHandler().getRemoteServerId(htServiceRequest,
							servletResponse, pwOut);
				}
				catch (ASelectException ace) {
					_systemLogger
							.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve the remote server id.", ace);

					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG, ace);
				}
				if (htIdentification == null) {
					// The handler was not ready yet and presented a HTML form
					// to the end user to gather more information
					// this form will POST 'request=cross_authenticate' again.
					return;
				}
				sRemoteOrg = (String) htIdentification.get("organization_id");
				String sTemp = (String) htIdentification.get("user_id");
				sHomeIdp = (String) htIdentification.get("home_idp");

				// Selector handler might have translated the user_id
				if (sTemp != null)
					sUid = (String) htIdentification.get("user_id");

			}
			_htSessionContext.put("remote_organization", sRemoteOrg);
			if (!_sessionManager.updateSession(sLocalRid, _htSessionContext)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not update session context");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			Object oRemoteServer;
			String sRemoteAsUrl;
			String sRemoteServer;

			try {
				// continue cross a-select login processing
				String sResourcegroup = _crossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
				if (sResourcegroup == null) {
					String sRelay = ASelectBrowserHandler.getSFSRelay(sRemoteOrg);
					if (sRelay != null) {
						sResourcegroup = _crossASelectManager.getRemoteParam(sRelay, "resourcegroup");
						sHomeIdp = sRemoteOrg;
						sRemoteOrg = sRelay;
					}
					else {
						_systemLogger.log(Level.SEVERE, _sModule, sMethod, "No remote server and no relay found for: "
								+ sRemoteOrg);
					}
				}
				SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
				oRemoteServer = oSAMResource.getAttributes();
				sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
				sRemoteServer = _crossASelectManager.getRemoteParam(sRemoteOrg, "server");
			}
			catch (ASelectSAMException ase) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ase);

				throw ase;
			}
			catch (ASelectConfigException ace) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read config.", ace);

				throw ace;
			}

			StringBuffer sbMyAppUrl = new StringBuffer();
			sbMyAppUrl.append((String) htServiceRequest.get("my_url"));
			sbMyAppUrl.append("?local_rid=").append(sLocalRid);

			RawCommunicator oCommunicator = new RawCommunicator(_systemLogger); // Default = API communciation

			HashMap htRequestTable = new HashMap();
			HashMap htResponseTable = new HashMap();
			htRequestTable.put("request", "authenticate");

			Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
			if (boolForced == null)
				boolForced = false;
			htRequestTable.put("forced_logon", boolForced.toString());
			htRequestTable.put("local_as_url", sbMyAppUrl.toString());

			Object oASelectConfig = _configManager.getSection(null, "aselect");
			String sMyOrgId = _configManager.getParam(oASelectConfig, "organization");
			htRequestTable.put("local_organization", sMyOrgId);

			Integer intLevel = (Integer) _htSessionContext.get("level");
			htRequestTable.put("required_level", intLevel.toString());
			htRequestTable.put("level", intLevel); // 20090111, Bauke added
			htRequestTable.put("a-select-server", sRemoteServer);

			if (sUid != null && !sUid.trim().equals("")) {
				htRequestTable.put("uid", sUid);
			}
			String sCountry = (String) _htSessionContext.get("country");
			if (sCountry != null) {
				htRequestTable.put("country", sCountry);
			}
			String sLanguage = (String) _htSessionContext.get("language");
			if (sLanguage != null) {
				htRequestTable.put("language", sLanguage);
			}
			if (sHomeIdp != null && !sHomeIdp.equals(sRemoteOrg)) {
				htRequestTable.put("remote_organization", sHomeIdp);
			}
			if ((String) _htSessionContext.get("arp_target") != null) {
				htRequestTable.put("arp_target", (String) _htSessionContext.get("arp_target"));
			}
			/*
			 * else { String sAppId = (String)_htSessionContext.get("app_id"); if (sAppId!=null) { String sArpTarget =
			 * URLEncoder.encode(sAppId, "UTF-8")+ "@" + URLEncoder.encode(sMyOrgId, "UTF-8");
			 * htRequestTable.put("arp_target", sArpTarget); } else { _systemLogger.log(Level.CONFIG,_sModule,sMethod,
			 * "No arp_target yet defined at the local IDP"); String sArpTarget = URLEncoder.encode(_sMyOrg, "UTF-8")+
			 * "@" + URLEncoder.encode(sMyOrgId, "UTF-8"); htRequestTable.put("arp_target", sArpTarget); } }
			 */

			// Store changed session, for JDBC Storage Handler
			if (!_sessionManager.updateSession(sLocalRid, _htSessionContext)) {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// check if request should be signed
			if (_crossASelectManager.useRemoteSigning()) {
				_cryptoEngine.signRequest(htRequestTable);
			}

			htResponseTable = oCommunicator.sendMessage(htRequestTable, sRemoteAsUrl);

			if (htResponseTable.isEmpty()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not reach remote A-Select Server: "
						+ sRemoteAsUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			String sResultCode = (String) htResponseTable.get("result_code");
			if (sResultCode == null) {
				StringBuffer sbWarning = new StringBuffer("Invalid response from remote A-Select Server '");
				sbWarning.append(sRemoteServer);
				sbWarning.append("' (missing: 'result_code')");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				StringBuffer sbWarning = new StringBuffer("A-Select Server '");
				sbWarning.append(sRemoteServer);
				sbWarning.append("' returned error: '");
				sbWarning.append(sResultCode);
				sbWarning.append("'.");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectException(sResultCode);
			}

			// check the response of the A-Select Server
			String sRemoteRid = (String) htResponseTable.get("rid");
			String sRemoteLoginUrl = (String) htResponseTable.get("as_url");
			if ((sRemoteRid == null) || (sRemoteLoginUrl == null)) {
				StringBuffer sbWarning = new StringBuffer("Invalid response from remote A-Select Server: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			try {
				StringBuffer sbUrl = new StringBuffer(sRemoteLoginUrl);
				sbUrl.append("&rid=").append(sRemoteRid);
				sbUrl.append("&a-select-server=").append(sRemoteServer);
				/*
				 * if(sHomeIdp != null) sbUrl.append("&forced_organization=").append(sHomeIdp);
				 */
				servletResponse.sendRedirect(sbUrl.toString());

			}
			catch (IOException e) {
				StringBuffer sbWarning = new StringBuffer("Failed to redirect user to: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString(), e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=ip_login</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request can be used to authenticate user by means of the IP AuthSP without the need to know a user-id. If the
	 * user already has a tgt and it is valid for the current application, then the user does not need be authenticated
	 * again. The user is redirected back to the application. If everything is ok, the request is forwarded to
	 * <code>handleLogin3()</code> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 */
	private void handleIPLogin1(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleIPLogin1";
		String sRid = null;
		Integer intRequiredLevel = null;
		String sLevel = null;
		HashMap htAllowedAuthsps = new HashMap();

		StringBuffer sb;

		try {
			sRid = (String) htServiceRequest.get("rid");

			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again

			// RM_38_01
			// IP login is not used when a user already has a TGT. The origin
			// ip-range will never be forced when already authenticated with an
			// AuthSP with a higher level
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id")) {
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// RM_38_02
				// If a user_id was provided in the request
				// we have to check here if the already existing
				// TGT is for the same user-id
				// see CVS
				if (checkCredentials(sTgt, sUid, sServerId)) {

					// redirect to application as user has already a valid tgt
					if (_htSessionContext.get("cross_authenticate") != null) {
						// redirect to application as user has already a valid
						// tgt
						if (_htSessionContext.get("cross_authenticate") != null) {
							// Cross A-Select does not implement
							// 'verify_credentials'
							// The TGT should be created now
							// TGTIssuer will redirect to local A-Select Server

							// RM_38_03
							// A new TGT is created because the TGTIssuer
							// implements the redirect with a create signature.
							// It is not logical to create a new TGT.
							_htSessionContext.put("user_id", sUid);
							_sessionManager.updateSession(sRid, _htSessionContext);

							HashMap htTgtContext = _tgtManager.getTGT(sTgt);
							String sAuthsp = (String) htTgtContext.get("authsp");

							// kill existing tgt
							_tgtManager.remove(sTgt);

							// issue new one but with the same lifetime as the
							// existing one
							HashMap htAdditional = new HashMap();
							// FIXME StorageManager can't update timestamp, this doesn't work. (Erwin, Peter)
							// htAdditional.put("tgt_exp_time", htTgtContext
							// .get("tgt_exp_time"));

							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
							oTGTIssuer.issueTGTandRedirect(sRid, _htSessionContext, sAuthsp, htAdditional, _servletRequest, servletResponse, null, true);
							return;
						}
					}

					try {
						String sRedirectUrl = (String) _htSessionContext.get("app_url");
						sRedirectUrl = URLDecoder.decode(sRedirectUrl, "UTF-8");
						sb = new StringBuffer(sRedirectUrl);

						// check whether the application url contains cgi
						// parameters
						if (sRedirectUrl.indexOf("?") > 0) {
							sb.append("&");
						}
						else {
							sb.append("?");
						}

						sUid = URLEncoder.encode(sUid, "UTF-8");
						sUid = URLEncoder.encode(sUid, "UTF-8");

						String sEncTgt = CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(sTgt));

						sb.append("aselect_credentials=").append(sEncTgt);
						sb.append("_").append(sUid).append("_");
						sb.append(sServerId);
						sb.append("&rid=").append(sRid);

						_sessionManager.deleteSession(sRid, _htSessionContext);
						servletResponse.sendRedirect(sb.toString());
					}
					catch (UnsupportedEncodingException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to encode user id.", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
					}
					catch (IOException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.", e);
						throw new ASelectException(Errors.ERROR_ASELECT_IO, e);
					}
				}
			}

			// get the required level of the application
			intRequiredLevel = _applicationManager.getRequiredLevel((String) _htSessionContext.get("app_id"));

			// check if IP AuthSP is enabled
			Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
					"id=Ip");

			sLevel = _configManager.getParam(authSPsection, "level");

			if (sLevel == null || Integer.parseInt(sLevel) < intRequiredLevel.intValue()) {
				sb = new StringBuffer(sMethod);
				sb.append("Could not perform IP authentication. Reason : ");

				// log this error in system log
				if (sLevel == null) {
					sb.append("The IP AuthSP is not (properly) configured.");
				}
				else {
					sb.append("The IP authsp security level is too low for application '"
							+ (String) _htSessionContext.get("app_id") + "'.");
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, sb.toString());

				throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			htAllowedAuthsps.put("Ip", htServiceRequest.get("client_ip"));
			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", htServiceRequest.get("client_ip"));
			_sessionManager.updateSession(sRid, _htSessionContext);

			// go for IP authsp
			htServiceRequest.put("authsp", "Ip");
			handleLogin3(htServiceRequest, servletResponse, pwOut);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=logout</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request can be used to logout a user by destroying his/her TGT. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Valid TGT <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * TGT is destroyed <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogout(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleLogout";
		String sLoggedOutForm = _configManager.getHTMLForm("loggedout", "", "");

		try {
			String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
			HashMap htTGTContext = _tgtManager.getTGT(sTgt);

			if (htTGTContext != null) {
				_tgtManager.remove(sTgt);

				Cookie cKillCookie = new Cookie("aselect_credentials", "jimmmorrisonisalive");

				String sCookieDomain = _configManager.getCookieDomain();
				if (sCookieDomain != null) {
					cKillCookie.setDomain(sCookieDomain);
				}

				servletResponse.addCookie(cKillCookie);

				String sRemoteAsUrl = null;
				String sRemoteOrg = null;

				sRemoteOrg = (String) htTGTContext.get("proxy_organization");
				if (sRemoteOrg == null)
					sRemoteOrg = (String) htTGTContext.get("organization");

				if (!sRemoteOrg.equals(_sMyOrg)) {
					try {
						CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
						String sResourcegroup = oCrossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
						if (sResourcegroup == null) {
							String sRelay = ASelectBrowserHandler.getSFSRelay(sRemoteOrg);
							if (sRelay != null) {
								sResourcegroup = _crossASelectManager.getRemoteParam(sRelay, "resourcegroup");
								sRemoteOrg = sRelay;
							}
							else {
								_systemLogger.log(Level.SEVERE, _sModule, sMethod,
										"No remote server and no relay found for: " + sRemoteOrg);
							}
						}
						SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
						Object oRemoteServer = oSAMResource.getAttributes();
						sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
					}
					catch (ASelectException ae) {
						_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ae);
						sRemoteAsUrl = null;
					}
				}
				if (sRemoteAsUrl != null) {
					String sRequest = (String) htServiceRequest.get("request");
					if (sRequest.equals("cross_logout")) {
						sRemoteAsUrl += "?request=cross_logout";
					}
					servletResponse.sendRedirect(sRemoteAsUrl);
					return;
				}
			}

			sLoggedOutForm = _configManager.updateTemplate(sLoggedOutForm, htTGTContext, _servletRequest);

			pwOut.println(sLoggedOutForm);

		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * This method handles the <code>request=create_tgt</code> user request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This request can be used to create TGTs for users without actually authentication them. This can only be used by
	 * priviliged applications which simply redirect the user with the correct information to the A-Select-Server with
	 * the request to create a TGT. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Signed request and a valid public key located in the priviliged keystore <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * A TGT wil be created <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleCreateTGT(HashMap htServiceRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleCreateTGTRequest";
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();

		try {
			// get output writer
			// Read expected parameters
			String sRid = (String) htServiceRequest.get("rid");
			String sUID = (String) htServiceRequest.get("uid");
			String sPrivilegedApplication = (String) htServiceRequest.get("app_id");
			String sSignature = (String) htServiceRequest.get("signature");
			String sAuthspLevel = (String) htServiceRequest.get("level");

			// Verify parameters
			if ((sRid == null) || (sUID == null) || (sPrivilegedApplication == null) || (sSignature == null)
					|| (sAuthspLevel == null)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request received: one or more parameters are missing.");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Verify signature
			try {
				sSignature = URLDecoder.decode(sSignature, "UTF-8");
				sUID = URLDecoder.decode(sUID, "UTF-8");
			}
			catch (UnsupportedEncodingException eUE) { // UTF-8 not supported
				_systemLogger
						.log(Level.WARNING, _sModule, sMethod, "Internal error: request could not be decoded", eUE);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append(sRid).append(sUID);
			sbBuffer.append(sPrivilegedApplication).append(sAuthspLevel);
			if (!CryptoEngine.getHandle().verifyPrivilegedSignature(sPrivilegedApplication, sbBuffer.toString(),
					sSignature)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid signature.");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Get session context
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// check authsp_level
			try {
				int iLevel = Integer.parseInt(sAuthspLevel);
				if (iLevel < 0) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Invalid request received: invalid AuthSP level.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			catch (NumberFormatException eNF) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: invalid AuthSP level.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eNF);
			}

			// check user ID
			IUDBConnector oUDBConnector = null;
			try {
				oUDBConnector = UDBConnectorFactory.getUDBConnector();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to connect with UDB.", e);
				throw e;
			}

			// 20121024, Bauke: added udb_user_ident mechanism
			HashMap<String, String> hmUserIdent = new HashMap<String, String>();
			if (!oUDBConnector.isUserEnabled(sUID, hmUserIdent)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request received: Unknown UID.");
				throw new ASelectException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			// Extend session context
			htSessionContext.put("user_id", sUID);
			htSessionContext.put("authsp", sPrivilegedApplication);
			htSessionContext.put("authsp_level", sAuthspLevel);

			if (!_sessionManager.updateSession(sRid, htSessionContext)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request received: could not update session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// Log succesful authentication
			authenticationLogger.log(new Object[] {
				"Login", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), _sMyOrg, sPrivilegedApplication, "granted"
			});

			// Issue TGT
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
			tgtIssuer.issueTGTandRedirect(sRid, _htSessionContext, sPrivilegedApplication, hmUserIdent/*additional*/, _servletRequest, servletResponse, null, true);

		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Get the AuthSP servers. Private method that fetches the authentication service providers from the user database
	 * of the A-Select Servers. The user may have been registered or entitled to use several authentication service
	 * providers. But only the ones that satisfy the level for the current application are returned by filtering the
	 * authsp's with lower levels out.
	 * 
	 * @param sRid
	 *            The RID.
	 * @param sUid
	 *            the s uid
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void getAuthsps(String sRid, String sUid)
	throws ASelectException
	{
		Integer intRequiredLevel = null;
		Integer intMaxLevel = null;
		HashMap htUserAuthsps = new HashMap();
		HashMap htAllowedAuthsps = new HashMap();
		String sMethod = "getAuthsps";

		try {

			IUDBConnector oUDBConnector = null;
			try {
				oUDBConnector = UDBConnectorFactory.getUDBConnector();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to connect with UDB.", e);
				throw e;
			}

			HashMap htUserProfile;
			htUserProfile = oUDBConnector.getUserProfile(sUid);
			if (!((String) htUserProfile.get("result_code")).equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to get user profile.");
				throw new ASelectException((String) htUserProfile.get("result_code"));
			}
			htUserAuthsps = (HashMap) htUserProfile.get("user_authsps");
			if (htUserAuthsps == null) {
				// should never happen
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "INTERNAL ERROR");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// which level is required for the application?
			intRequiredLevel = (Integer) _htSessionContext.get("level");
			if (intRequiredLevel == null) {
				// 'normal' request
				intRequiredLevel = _applicationManager.getRequiredLevel((String) _htSessionContext.get("app_id"));
				// RM_38_04
			}
			intMaxLevel = (Integer) _htSessionContext.get("max_level"); // 'max_level' may be null

			// fetch the authsps that the user has registered for and
			// satisfy the level for the current application
			Vector vAllowedAuthSPs;
			vAllowedAuthSPs = _authspHandlerManager.getConfiguredAuthSPs(intRequiredLevel, intMaxLevel);// getAllowedAuthSPs(intRequiredLevel.intValue(),
			// htUserAuthsps);
			if (vAllowedAuthSPs == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "INTERNAL ERROR" + sUid);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			for (int i = 0; i < vAllowedAuthSPs.size(); i++) {
				String sAuthSP = (String) vAllowedAuthSPs.elementAt(i);
				if (htUserAuthsps.containsKey(sAuthSP)) {
					htAllowedAuthsps.put(sAuthSP, htUserAuthsps.get(sAuthSP));
				}
			}
			if (htAllowedAuthsps.size() == 0) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No valid AuthSPs found for user: " + sUid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);
			}
			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", sUid);

			if (!_sessionManager.updateSession(sRid, _htSessionContext)) {
				// logged in sessionmanager
				throw new ASelectException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			}
			return;// Errors.ERROR_ASELECT_SUCCESS;
		}
		catch (ASelectException e) {
			throw e;
		}
	}

	/**
	 * This method will instantiate the protocol handler for the selected AuthSP. The protocol handler will compose a
	 * redirect url and return it. This method will return this redirect url. Some AuthSP's will require a signed
	 * request from the A-Select Server. The protocol handler will be responsible for placing it.
	 * 
	 * @param sRid
	 *            The RID.
	 * @param htLoginRequest
	 *            The request parameters.
	 * @return The error code.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String startAuthentication(String sRid, HashMap htLoginRequest)
	throws ASelectException
	{
		HashMap htAllowedAuthsps;
		String sAuthsp = null;
		String sMethod = "startAuthentication";

		sAuthsp = (String) htLoginRequest.get("authsp");

		htAllowedAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
		if (htAllowedAuthsps == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "allowed_user_authsps not found in session context");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (!htAllowedAuthsps.containsKey(sAuthsp)) {
			StringBuffer sbError = new StringBuffer("Invalid/unknown authsp id in request: ");
			sbError.append(sAuthsp);
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbError.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_htSessionContext.put("authsp", sAuthsp);
		_htSessionContext.put("my_url", htLoginRequest.get("my_url"));
		if (!_sessionManager.updateSession(sRid, _htSessionContext)) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not update session context");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		// everything seems okay -> instantiate the protocol handler for
		// the selected authsp and let it compute a signed authentication request
		IAuthSPProtocolHandler oProtocolHandler;
		try {
			Object oAuthSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",
					"id=" + sAuthsp);

			String sHandlerName = _configManager.getParam(oAuthSPsection, "handler");

			Class oClass = Class.forName(sHandlerName);
			oProtocolHandler = (IAuthSPProtocolHandler) oClass.newInstance();

			// get authsps config and retrieve active resource from SAMAgent
			String strRG = _configManager.getParam(oAuthSPsection, "resourcegroup");
			SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(strRG);
			Object objAuthSPResource = mySAMResource.getAttributes();
			oProtocolHandler.init(oAuthSPsection, objAuthSPResource);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to retrieve config for AuthSPs.", e);
			throw new ASelectException(e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to initialize handler AuthSPHandler.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		// let the protocol handler for the authsp do its work
		HashMap htResponse = oProtocolHandler.computeAuthenticationRequest(sRid, _htSessionContext);
		String sResultCode = (String) htResponse.get("result");
		if (sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			return (String) htResponse.get("redirect_url");
		}
		_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to create redirect url.");
		throw new ASelectException(sResultCode);
	}

	/**
	 * Private method to check whether the user's tgt is valid and satisfies the required level for the current
	 * application. <br>
	 * 
	 * @param sTgt
	 *            The ticket granting ticket.
	 * @param sUid
	 *            The user ID.
	 * @param sServerId
	 *            The server ID.
	 * @return True if credentials are valid, otherwise false.
	 */
	private boolean checkCredentials(String sTgt, String sUid, String sServerId)
	{
		HashMap htTGTContext;
		String sTGTLevel;
		Integer intRequiredLevel;

		htTGTContext = _tgtManager.getTGT(sTgt);
		if (htTGTContext == null) {
			return false;
		}

		if (!((String) htTGTContext.get("uid")).equals(sUid)) {
			return false;
		}

		if (!sServerId.equals(_sMyServerId)) {
			return false;
		}

		// check single sign-on groups
		Vector vCurSSOGroups = (Vector) _htSessionContext.get("sso_groups");
		Vector vOldSSOGroups = (Vector) htTGTContext.get("sso_groups");
		if (vCurSSOGroups != null && vOldSSOGroups != null) {
			if (!vCurSSOGroups.isEmpty() && !vOldSSOGroups.isEmpty()) {
				if (!_applicationManager.isValidSSOGroup(vCurSSOGroups, vOldSSOGroups))
					return false;
			}
		}

		intRequiredLevel = (Integer) _htSessionContext.get("level");

		sTGTLevel = (String) htTGTContext.get("authsp_level");
		if (Integer.parseInt(sTGTLevel) >= intRequiredLevel.intValue()) {
			return true;
		}
		// user did have a tgt but the level is not high enough
		// so continue authenticate
		return false;
	}

	/**
	 * Show the user info contained in the TGT context of the user. Requires a valid TGT. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param response
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void showUserInfo(HashMap htServiceRequest, HttpServletResponse response, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "showUserInfo";

		String sUserId = (String) htServiceRequest.get("aselect_credentials_uid");
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");

		String sUserInfoForm = _configManager.getHTMLForm("userinfo", "", "");
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[uid]", sUserId);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[a-select-server]", _sMyServerId);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[aselect_url]", sMyUrl);

		String sTemp;
		HashMap htTGTContext = _tgtManager.getTGT(sTgt);
		try {
			long lExpTime = _tgtManager.getExpirationTime(sTgt);
			sTemp = new Date(lExpTime).toString();
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", sTemp);
		}
		catch (ASelectStorageException e) {
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", "[unknown]");
		}

		sTemp = (String) htTGTContext.get("app_id");
		if (sTemp == null)
			sTemp = "[unknown]";
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[app_id]", sTemp);

		sUserInfoForm = _configManager.updateTemplate(sUserInfoForm, htTGTContext, _servletRequest);

		sTemp = (String) htTGTContext.get("authsp");
		if (sTemp != null) {
			try {
				Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
						"authsp", "id=" + sTemp);
				sTemp = _configManager.getParam(authSPsection, "friendly_name");
			}
			catch (ASelectConfigException eAC) {
				sTemp = "[unknown]";
			}
		}
		else {
			sTemp = "[unknown]";
		}

		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[authsp]", sTemp);

		sTemp = (String) htTGTContext.get("authsp_level");
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_level]", sTemp);

		sTemp = (String) htTGTContext.get("proxy_organization");
		if (sTemp == null)
			sTemp = (String) htTGTContext.get("organization");

		String sRemoteAsUrl = null;
		if (!sTemp.equals(_sMyOrg)) {
			try {
				CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
				String sResourcegroup = oCrossASelectManager.getRemoteParam(sTemp, "resourcegroup");
				if (sResourcegroup == null) {
					String sRelay = ASelectBrowserHandler.getSFSRelay(sTemp);
					if (sRelay != null) {
						sResourcegroup = _crossASelectManager.getRemoteParam(sRelay, "resourcegroup");
						sTemp = sRelay;
					}
					else {
						_systemLogger.log(Level.SEVERE, _sModule, sMethod,
								"No remote server and no relay found for: " + sTemp);
					}
				}
				SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
				Object oRemoteServer = oSAMResource.getAttributes();
				sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.", ae);
				sRemoteAsUrl = null;
			}
		}
		if (sRemoteAsUrl == null) {
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp);
		}
		else {
			String sTemp3 = "<A HREF=\"" + sRemoteAsUrl + "\">" + sTemp + "</A>";
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp3);
		}
		pwOut.println(sUserInfoForm);
	}
}
