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
 * $Id: ApplicationBrowserHandler.java,v 1.19 2006/05/03 10:10:45 tom Exp $ 
 * 
 * Changelog:
 * $Log: ApplicationBrowserHandler.java,v $
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
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.53  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.52  2005/09/07 08:28:51  erwin
 * Fixed problem with popup configuration handling (bug #77)
 *
 * Revision 1.51  2005/05/04 14:22:06  martijn
 * updates logging
 *
 * Revision 1.50  2005/05/04 09:34:59  martijn
 * bugfixes, improved logging
 *
 * Revision 1.49  2005/05/03 07:38:02  erwin
 * Added UID check in create TGT
 *
 * Revision 1.48  2005/04/28 09:11:30  erwin
 * Reformatted if/else structure in handleLogin1
 *
 * Revision 1.47  2005/04/27 14:17:14  erwin
 * - Added URL decoding for uid
 * - Added AuthSP level check
 *
 * Revision 1.46  2005/04/27 07:07:32  erwin
 * log level changed for "failed to retrieve..."
 *
 * Revision 1.45  2005/04/15 14:04:31  peter
 * javadoc and comment
 *
 * Revision 1.44  2005/04/12 11:21:44  peter
 * undo last commit (1.43)
 *
 * Revision 1.43  2005/04/12 10:13:44  peter
 * fixed sso_groups bug
 *
 * Revision 1.42  2005/04/11 14:56:31  peter
 * code restyle
 *
 * Revision 1.41  2005/04/11 12:53:18  peter
 * Solved cross issues:
 * - Handle logout now redirects to remote A-Select Server in case of cross.
 * - Logged out form is now static and has no dynamic [message] tag anymore.
 *
 * Revision 1.40  2005/04/11 09:36:31  erwin
 * Added useRemoteSigning() as check.
 *
 * Revision 1.39  2005/04/11 09:24:24  remco
 * also implemented forced_logon protocol change in cross (untested)
 *
 * Revision 1.38  2005/04/11 08:57:29  erwin
 * Added local A-Select signing support for cross A-Select.
 *
 * Revision 1.37  2005/04/08 12:41:12  martijn
 *
 * Revision 1.36  2005/04/08 08:06:08  peter
 * if user already has a TGT check if an optional requested uid equals the one in the TGT
 *
 * Revision 1.35  2005/04/08 07:56:13  erwin
 * Added localisation support for cross A-Select.
 *
 * Revision 1.34  2005/04/07 14:39:45  peter
 * added forced_authenticate; redesign of login1 in case of valid TGT
 *
 * Revision 1.33  2005/04/07 12:14:34  martijn
 * added single sign-on groups
 *
 * Revision 1.32  2005/04/07 07:37:38  peter
 * forced logon for cross aselect
 *
 * Revision 1.31  2005/04/07 06:37:12  erwin
 * Renamed "attribute" -> "param" to be compatible with configManager.
 *
 * Revision 1.30  2005/04/06 11:40:28  peter
 * Added support for optional uid in request authenticate
 *
 * Revision 1.29  2005/04/05 15:25:08  martijn
 * TGTIssuer.issueTGT() now only needs an optional old tgt and the printwriter isn't needed anymore
 *
 * Revision 1.28  2005/04/05 13:12:29  martijn
 * save old_tgt if forced authenticate and user has already a tgt
 *
 * Revision 1.27  2005/04/05 11:30:44  martijn
 *
 * Revision 1.26  2005/04/05 09:11:15  peter
 * added cross proxy logica in showuserinfo (logout page)
 *
 * Revision 1.25  2005/04/05 08:17:03  martijn
 *
 * Revision 1.24  2005/04/05 07:50:11  martijn
 * added forced_authenticate
 *
 * Revision 1.23  2005/04/04 12:33:34  erwin
 *
 * Revision 1.22  2005/04/01 14:26:58  peter
 * cross aselect redesign
 *
 * Revision 1.21  2005/03/24 13:23:45  erwin
 * Improved URL encoding/decoding
 * (this is handled in communication package for API calls)
 *
 * Revision 1.20  2005/03/22 15:19:22  peter
 * handleCrossLogin makes use of the CrossSelectorManager
 *
 * Revision 1.18  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.17  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.16  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.15  2005/03/17 13:42:34  tom
 * Minor code style fix
 *
 * Revision 1.14  2005/03/17 07:58:43  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 *
 * Revision 1.13  2005/03/16 13:30:05  erwin
 * Application manager was null and protected, this is fixed.
 *
 * Revision 1.12  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.11  2005/03/16 12:50:50  martijn
 *
 * Revision 1.10  2005/03/16 10:00:07  peter
 * Fixed Cross TGT if it already exists.
 *
 * Revision 1.9  2005/03/16 09:28:03  martijn
 * The config item 'cookie_domain' will now only be retrieved from the config at startup and not every time the ticket is issued.
 *
 * Revision 1.8  2005/03/15 16:04:10  erwin
 *
 * Revision 1.7  2005/03/15 15:29:04  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.6  2005/03/15 10:52:01  tom
 * Fixed import errors
 *
 * Revision 1.5  2005/03/15 10:51:41  tom
 * - Added new Abstract class functionality
 * - Added Javadoc
 *
 * Revision 1.4  2005/03/15 10:10:36  tom
 * Small Javadoc changes
 *
 * Revision 1.3  2005/03/15 10:06:52  tom
 * Added JavaDoc and Error Handling
 *
 * Revision 1.2  2005/03/15 08:29:56  tom
 * Added new tgt_exp_time handling
 *
 * Revision 1.1  2005/03/15 08:21:19  tom
 * Redesign of request handling
 *
 * Revision 1.18  2005/03/14 10:17:21  tom
 * Changed return parameters in cancel to match new error request
 *
 * Revision 1.17  2005/03/14 10:05:34  martijn
 * config item 'select_form_show_always' is renamed to 'always_show_select_form' in 'authsps' config section
 *
 * Revision 1.16  2005/03/14 09:39:04  peter
 * code-styling and error handling
 *
 * Revision 1.15  2005/03/10 16:44:12  erwin
 * Made compatible with new UDBConnectorFactory
 *
 * Revision 1.14  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.13  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 *
 * Revision 1.12  2005/03/09 15:16:51  martijn
 * fixed bug in getAuthsps(): if the hashtable returned by the udbconnector doesn't contain a key=user_authsps with value=HashMap, then a wrong error message was logged.
 *
 * Revision 1.11  2005/03/09 15:11:20  martijn
 *
 * Revision 1.10  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.9  2005/03/08 10:16:32  remco
 * javadoc added
 *
 * Revision 1.8  2005/03/08 10:03:40  remco
 * javadoc added
 *
 * Revision 1.3  2005/03/08 09:51:53  remco
 * javadoc added
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringEscapeUtils;
import org.aselect.server.application.Application;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.authspprotocol.handler.AuthSPHandlerManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectEntrustmentLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.aselect.ASelectAuthenticationProfile;
import org.aselect.server.request.handler.xsaml20.LogoutRequestSender;
import org.aselect.server.request.handler.xsaml20.ServiceProvider;
import org.aselect.server.request.handler.xsaml20.idp.UserSsoSession;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.server.udb.UDBConnectorFactory;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.communication.client.json.JSONCommunicator;
import org.aselect.system.communication.client.raw.RawCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

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
 * @author Alfa & Ariss 7-10-2008 - HtmlInfo de-activated 18-9-2008 - HtmlInfo integrated in A-Select (replaces
 *         tolk_htmlinfo) 14-11-2007 - Changes: - Support tolk_htmlinfo request: shows header info in a html page -
 *         DigiD Gateway integration - Added login25 method and some other changes to support SIAM "VerkeersPlein"
 *         authsp selection
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
 */
public class ApplicationBrowserHandler extends AbstractBrowserRequestHandler
{
	private static final int OBO_MAXTRIES = 3;
	private static final String SELECTFORMPREFIX = "select";
	private static final String SUBSELECTFORMPREFIX = "subselect";
	final String select_choice_COOKIE = "select_choice";
	private ApplicationManager _applicationManager;
	private CrossASelectManager _crossASelectManager;
	private AuthSPHandlerManager _authspHandlerManager;
	private CryptoEngine _cryptoEngine;
	private String _sConsentForm = null;
	private String _sServerUrl;
	private static boolean firstTime = true;  // do Saml bootstrap only once

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
	 * @throws ASelectException 
	 */
	public ApplicationBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		String sMethod = "ApplicationBrowserHandler";
		_sModule = "ApplicationBrowserHandler";
		_systemLogger.log(Level.FINEST, _sModule, _sModule, "== create == user language=" + _sUserLanguage);
		_applicationManager = ApplicationManager.getHandle();
		_authspHandlerManager = AuthSPHandlerManager.getHandle();
		_crossASelectManager = CrossASelectManager.getHandle();
		_cryptoEngine = CryptoEngine.getHandle();
		try {
			_sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		}
		catch (ASelectConfigException e) {
			_sServerUrl = _sMyServerId;
			//throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}
		if (firstTime) {
			firstTime = false;
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
				DefaultBootstrap.bootstrap();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Bootstrap done");
			}
			catch (ConfigurationException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "OpenSAML library could not be initialized", e);
			}
		}
	}
	
	/**
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oHandlerConfig
	 *            Object
	 * @throws ASelectException
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";	
		_systemLogger.log(Level.INFO, _sModule, sMethod, "I'm INIT");
	}

	/**
	 * Process application browser requests.<br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the output PrintWriter
	 * @throws ASelectException
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	// NOTE: pwOut is closed by the caller!!!
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "processBrowserRequest";
		boolean useUsi = false;

		String sRequest = (String) htServiceRequest.get("request");
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "ApplBrowREQ sRequest="+sRequest + " user language="+_sUserLanguage);
		
		// 20120611, Bauke: added "usi" handling
		if (sRequest != null && ("logout".equals(sRequest) || sRequest.startsWith("direct_login") || sRequest.startsWith("login"))) {
			_timerSensor.setTimerSensorLevel(1);  // enable sensor
			useUsi = true;
		}
		
		String sReqLanguage = (String) htServiceRequest.get("language");
		if (sReqLanguage != null && !sReqLanguage.equals("")) {
			_sUserLanguage = sReqLanguage;
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "Set user language=" + _sUserLanguage + " from Request");
		}
		// TGT was read if available

		// Bauke, 20090929: added localization, do this asap.
		String sRid = (String)htServiceRequest.get("rid");
		if (sRid != null) {
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			// 20120611, Bauke: added "usi" handling
			String sUsi = (String)_htSessionContext.get("usi");
			String sAppId = (String)_htSessionContext.get("app_id");
			if (useUsi) {
				if (Utils.hasValue(sUsi))  // overwrite
					_timerSensor.setTimerSensorId(sUsi);
				if (Utils.hasValue(sAppId))
					_timerSensor.setTimerSensorAppId(sAppId);
			}
			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  // 20111102
			if (sReqLanguage != null && !sReqLanguage.equals("")) {
				_htSessionContext.put("language", sReqLanguage); // store language for posterity
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
			}
			// Copy language & country to session if not present yet (session takes precedence)
			Utils.transferLocalization(_htSessionContext, _sUserLanguage, _sUserCountry);
			// And copy language back
			_sUserLanguage = (String) _htSessionContext.get("language"); // override
			String sUserState = (String)_htSessionContext.get("user_state");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "After transfer: userLanguage=" + _sUserLanguage+
					" user_state="+sUserState);
		}

		boolean bAllowLoginToken = "true".equals(ASelectAuthenticationProfile.get_sAllowLoginToken());
		String sAllowedLoginTokenMethod = ASelectAuthenticationProfile.get_sAllowedLoginTokenMethod();
		
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "bAllowLoginToken="+bAllowLoginToken + ", sAllowedLoginTokenMethod: " + sAllowedLoginTokenMethod);

		if (sRequest == null) {
			// Show info page if nothing else to do
			String sUrl = (String)htServiceRequest.get("my_url");
			String sAsUid = (String)htServiceRequest.get("aselect_credentials_uid");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "ApplBrowREQ request=null sUrl=" + sUrl+" aselect_credentials_uid="+sAsUid);

			if (sAsUid != null)
				showUserInfo(htServiceRequest, _servletResponse, pwOut);  // pauses sensor
			else {
				String sServerInfoForm = _configManager.getHTMLForm("serverinfo", _sUserLanguage, _sUserCountry);
				sServerInfoForm = Utils.replaceString(sServerInfoForm, "[message]", " ");

				try {
					Object aselect = _configManager.getSection(null, "aselect");
					String sFriendlyName = ASelectConfigManager.getSimpleParam(aselect, "organization_friendly_name", false);
					sServerInfoForm = Utils.replaceString(sServerInfoForm, "[organization_friendly]", sFriendlyName);
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Configuration error: " + e);
				}
				sServerInfoForm = _configManager.updateTemplate(sServerInfoForm, _htSessionContext, _servletRequest);
				Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
				
				if (_htSessionContext != null)
					_htSessionContext.put("user_state", "state_serverinfo");
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
				
				pwOut.println(sServerInfoForm);
			}
		}
//		else if (sRequest.equals("logout")) {	// RH, 20181105, o
		else if (sRequest.equals("logout") || sRequest.equals("logout_nosaml")) {	// RH, 20181105, n
//			handleLogout(htServiceRequest, _servletResponse, pwOut);	// RH, 20140819, o
			// RH, 20140819, sn
			//////////////////////////////////////////////////////
			boolean doSamlLogout = false;	// true = for testing, get this from e.g. presence of sp_issuer and/or sso_session in tgtcontext
			// RH, 20181105, sn
			if (!sRequest.equals("logout_nosaml")) {// special case if sp does not support logout	// RH, 20181105, n
				doSamlLogout = ( _htTGTContext != null ) && ( _htTGTContext.get("sp_issuer") != null ) &&  ( _htTGTContext.get("sso_session") != null );
			}	// RH, 20181105, n
			if (doSamlLogout) {
//				_systemLogger.log(Level.FINER, _sModule, sMethod, "doSamlLogout, _htTGTContext:" + _htTGTContext);	// RH, 20181105, o
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "handleSamlLogout, _htTGTContext:" + Auxiliary.obfuscate(_htTGTContext));	// RH, 20181105, n
				handleSamlLogout(htServiceRequest, _servletRequest, _servletResponse, pwOut);
			}
			else {
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "handleLogout, _htTGTContext:" + Auxiliary.obfuscate(_htTGTContext));	// RH, 20181105, n
				handleLogout(htServiceRequest, _servletResponse, pwOut);
			}
			// RH, 20140819, en

		}
		else if (sRequest.equals("org_choice")) {
			handleOrgChoice(htServiceRequest, _servletResponse);
		}
		
		// handle OnBehalfOf
		else if ( sRequest.equals("obo_choice")) {
			handleOnBehalfOf(htServiceRequest, _servletResponse, pwOut);
		}
		else if (sRequest.equals("alive")) {
			pwOut.println("<html><body>Server is ALIVE</body></html>");
		}
//		else if (bAllowLoginToken && sRequest.equals("login_token")) {
		else if ( bAllowLoginToken && sRequest.equals("login_token") && ( sAllowedLoginTokenMethod == null || _servletRequest.getMethod().equalsIgnoreCase(sAllowedLoginTokenMethod)) ) {
			handleLoginToken(htServiceRequest, _servletResponse, pwOut);
		}
		else {  // Precondition, need a session
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// If a valid session is found, it will be valid during the whole servlet request handling.
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// Session is available
			String sDirectAuthSP = (String) _htSessionContext.get("direct_authsp");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "direct_authsp="+sDirectAuthSP);
			if (sDirectAuthSP != null && !sRequest.startsWith("direct_login")) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"'direct_authsp' found, but not a 'direct_login' request, rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			// 20100828, Bauke:
			// Allow application to force the login user name upon us
			String sSpecials = Utils.getAselectSpecials(_htSessionContext, true, _systemLogger);  // decodes from base64 coded value
			if (Utils.hasValue(sSpecials)) {
				String sSearch = Utils.getParameterValueFromUrl(sSpecials, "set_forced_uid");
				if (sSearch != null)
					_htSessionContext.put("user_id", sSearch);
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
			}

			while (true) {
				if (sRequest.equals("login1")) {
					int rc = handleLogin1(htServiceRequest, _servletResponse, pwOut);
					if ( rc != 1 )
						return;
					sRequest = "login1";  // allow new login attempt
				}
				else if (sRequest.equals("login2")) {
					int rc = handleLogin2(htServiceRequest, _servletResponse, pwOut);
					if (rc != 1)
						return;
					sRequest = "login1";  // allow new login attempt
				}
				else
					break;  // other requests
			}
			if (sRequest.equals("login3")) {
				handleLogin3(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("cross_login")) {
				handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("login25")) {
				handleLogin25(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("ip_login")) {
				handleIPLogin1(htServiceRequest, pwOut);
			}
			else if (sRequest.startsWith("direct_login")) {
				handleDirectLogin(htServiceRequest, _servletResponse, pwOut);
			}
			else if (sRequest.equals("create_tgt")) {
				handleCreateTGT(htServiceRequest);
			}
			else {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
	}

	/**
	 * Handles the <code>request=org_choice</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Store the user's organization choice in the TGT and redirect the user
	 * to the application he desires.
	 * TGT has already been issued, Rid is still present (contains the application url)
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
	private void handleOrgChoice(HashMap htServiceRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleOrgChoice";
		
		String sRid = (String)htServiceRequest.get("rid");
		String sOrgId = (String)htServiceRequest.get("org_id");
		String sTgt = (String)htServiceRequest.get("aselect_credentials_tgt");
		if (sRid == null || sOrgId == null || sTgt == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing request parameter");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Level.INFO, _sModule, sMethod, "OrgChoice="+sOrgId);

		// Stop the user-time pause
		Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);
		// No need to write the session, it's used below by calculateAndReportSensorData() and then discarded
		
		// Store the chosen organization in the TGT
		// 20120712, Bauke, not needed, ASelectAuthenticationProfile has already read the TGT
		//HashMap<String,Object> _htTGTContext = _tgtManager.getTGT(sTgt);
		if (_htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Cannot get TGT");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_htTGTContext.put("org_id", sOrgId);
		_tgtManager.updateTGT(sTgt, _htTGTContext);

		// The tgt was just issued and updated, report sensor data
		Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_sbh", sRid, _htSessionContext, sTgt, true);
		_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
		
		String sAppUrl = (String)_htSessionContext.get("app_url");
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "REDIRECT to " + sAppUrl);
		
		TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
		String sLang = (String)_htTGTContext.get("language");
		oTGTIssuer.sendTgtRedirect(sAppUrl, sTgt, sRid, servletResponse, sLang);
	}

	/**
	 * Handles the <code>request=org_choice</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Store the user's organization choice in the TGT and redirect the user
	 * to the application he desires.
	 * TGT has already been issued, Rid is still present (contains the application url)
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
	private void handleOnBehalfOf(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleOnBehalfOf";

//		String sRid = (String)htServiceRequest.get("rid");	// we are logged in, old rid has gone
		String sOBOId = (String)htServiceRequest.get("obouid");
		String sTgt = (String)htServiceRequest.get("aselect_credentials_tgt");
		String sStep = (String)htServiceRequest.get("step");
		String sOBOyn = (String)htServiceRequest.get("oboyn");
		String sAppUrl = (String)_htTGTContext.get("obo_app_url");	// session already deleted, we need the app_url
		String sAppId = (String)_htTGTContext.get("app_id");
		
		String sUid = (String)_htTGTContext.get("uid");
		Integer iOboRetries = (Integer)_htTGTContext.get("obo_retries");
		
		if (sStep == null ) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing some request parameter");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		if ( !Utils.hasValue(sAppId) ||  !ApplicationManager.getHandle().getApplication(sAppId).isOBOEnabled() ) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "On Behalf Of not enabled for application: " + sAppId);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		HashMap oboParms = ApplicationManager.getHandle().getApplication(sAppId).getOBOParameters();
		int obo_maxRetries = OBO_MAXTRIES; 
		try {
			obo_maxRetries = Integer.parseInt((String)oboParms.get("maxtries"));
		} catch (NumberFormatException nfe ){
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid parameter maxtries: " +  oboParms.get("maxtries") + ", using default:" + obo_maxRetries );
		}
		
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "obouid="+Auxiliary.obfuscate(sOBOId) + ", step="+sStep + ", oboyn="+sOBOyn + ", obo_retries="+iOboRetries);
		if ( iOboRetries == null ) {
			iOboRetries = 0;
		}
		int iStep = Integer.parseInt(sStep);

		switch (iStep) {
		case 0:
			// RH, 20210504, sn
			_htTGTContext.put("oboyn", sOBOyn);
			_tgtManager.updateTGT(sTgt, _htTGTContext);
			// RH, 20210504, en
			if ("y".equalsIgnoreCase(sOBOyn)) {
				try {
					String sSelectForm;
					sSelectForm = org.aselect.server.utils.Utils.presentOnBehalfOf(_servletRequest, _configManager,
							htServiceRequest, null, (String)_htTGTContext.get("language"), 1 /* step 1, present obo request */);
					
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);

					pwOut.println(sSelectForm);
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Cannot present OnBehalfOf form");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				return;
			}
			else {	// no obo requested
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "No obo requested by user");
			}
			break;
		case 1:
		case 2:
			// test obo_id here 11-proef, also prevents XSS on obo
			// allow for re-entering obo from user
			iOboRetries++;
			if (iOboRetries > obo_maxRetries) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Maximum nuber of retries reached for on behalf of");
				// user friendly form already shown, so now the ungraceful method
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			boolean oboK = false;
			String status = null; // Permit  Deny / Inderterminate / Invalid
			if (org.aselect.system.utils.Utils.bsnCheck(sOBOId)) {

				String sIssuer = (String)htServiceRequest.get("a-select-server");
				if (oboParms.get("issuer") != null) {
					sIssuer = (String)oboParms.get("issuer") ;	// overrule issuer
				}
				
				String prefix = "";
				if ( oboParms.get("prefix") != null ) {
					prefix = (String)oboParms.get("prefix");
				}
				
				if ( oboParms.get("identificatieCodeGemachtigde") != null ) {	// FOR TESTING 
					sUid = (String)oboParms.get("identificatieCodeGemachtigde");	// only for wsserver request, does not update tgt
				}

				String sSubjectPrefix = "";
				if ( oboParms.get("subjectprefix") != null ) {
					sSubjectPrefix = (String)oboParms.get("subjectprefix");
				}
				
				String sSubject = sSubjectPrefix + sUid;
				String identificatieCodeVertegenwoordigde = prefix + sOBOId;
				String identificatieSoortVertegenwoordigde = (String)oboParms.get("identificatieSoortVertegenwoordigde");
				String identificatieCodeGemachtigde = prefix + sUid;
				String identificatieSoortGemachtigde = (String)oboParms.get("identificatieSoortGemachtigde");
				String identificatieCodeDienst = (String)oboParms.get("identificatieCodeDienst");
				String identificatieCodeDienstAanbieder= (String)oboParms.get("identificatieCodeDienstAanbieder");

				HashMap<String, String> parms = new HashMap<String, String>();
				// No attributes to add for assertion (yet)

				Assertion assertion = HandlerTools.createAuthnStatementAttributeStatementAssertion(parms, sIssuer, sSubject, true); //

				// Marshall to the Node
				MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
				Marshaller marshaller = factory.getMarshaller(assertion);

				Node node = null;
				try {
					node = marshaller.marshall(assertion);
				}
				catch (MarshallingException e) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not marshall assertion", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshalling done");
				String sAssertion = XMLHelper.nodeToString(node);

				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sAssertion: " + Auxiliary.obfuscate(sAssertion, Auxiliary.REGEX_PATTERNS));

				 IClientCommunicator _communicator;
				
				_communicator = new JSONCommunicator(_systemLogger);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator= 'json' loaded");

				String sURL = (String)oboParms.get("wsserverurl");

				HashMap jsonrequest = new HashMap();
				HashMap htRequestpairs = new HashMap();
				try {
//					sAssertion = Base64.encodeBytes(sAssertion.getBytes("UTF-8"));	// gives newlines, not accepted by json on receiver
					sAssertion = Base64.encodeBytes(sAssertion.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);	// violates strict Base64 specification
					String key_assertion = "assertion";
					htRequestpairs.put(key_assertion, URLEncoder.encode(sAssertion,  "UTF-8"));
					String key_identificatiecodevertegenwoordigde = "identificatiecodevertegenwoordigde";
					htRequestpairs.put(key_identificatiecodevertegenwoordigde, URLEncoder.encode(identificatieCodeVertegenwoordigde, "UTF-8"));
					String key_identificatiesoortvertegenwoordigde = "identificatiesoortvertegenwoordigde";
					htRequestpairs.put(key_identificatiesoortvertegenwoordigde, URLEncoder.encode(identificatieSoortVertegenwoordigde, "UTF-8"));
					String key_identificatiecodegemachtigde = "identificatiecodegemachtigde";
					htRequestpairs.put(key_identificatiecodegemachtigde, URLEncoder.encode(identificatieCodeGemachtigde, "UTF-8"));
					String key_identificatiesoortgemachtigde = "identificatiesoortgemachtigde";
					htRequestpairs.put(key_identificatiesoortgemachtigde, URLEncoder.encode(identificatieSoortGemachtigde, "UTF-8"));
					String key_identificatiecodedienst = "identificatiecodedienst";
					htRequestpairs.put(key_identificatiecodedienst, URLEncoder.encode(identificatieCodeDienst, "UTF-8"));
					String key_identificatiecodedienstaanbieder = "identificatiecodedienstaanbieder";
					htRequestpairs.put(key_identificatiecodedienstaanbieder, URLEncoder.encode(identificatieCodeDienstAanbieder, "UTF-8"));

					String key_issuer = "issuer";
					htRequestpairs.put(key_issuer, URLEncoder.encode(sIssuer, "UTF-8"));
					String key_subjectprefix = "subjectprefix";
					htRequestpairs.put(key_subjectprefix, URLEncoder.encode(sSubjectPrefix, "UTF-8"));
					
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Could not find or encode parameters for: " + sURL );
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				
				String jsonkey = "jsoninput";
				jsonrequest.put("request", (String)oboParms.get("wsserverrequest"));
				jsonrequest.put(jsonkey, htRequestpairs);
//				// set Configuration parameters
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "jsonrequest:" + jsonrequest);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Doing jsonrequest");
				
				// send message
				HashMap jsonResponse = new HashMap();

				try {
					jsonResponse = _communicator.sendMessage(jsonrequest, sURL);
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "jsonResponse:" + jsonResponse);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved jsonResponse");
					status = (String)jsonResponse.get((String)oboParms.get("wsserverresponse"));
					// status can be null if request failed with error
				} catch ( ASelectCommunicationException cex) {
//						status = "Deny"; 	// RH, 20150529, o
						status = null; 	// null for any (communication) problem	// RH, 20150529, n
						
				}
				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "MachtigenClient returned status: " + status);
				
			} else {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "BSN check failed");
				status = "Deny";
			}
			oboK = "Permit".equalsIgnoreCase(status);
			if ( oboK ) {
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Valide obo requested by user");
				_htTGTContext.put("obouid", sOBOId);
				_htTGTContext.remove("obo_retries");
				_htTGTContext.remove("obo_app_url");
				_tgtManager.updateTGT(sTgt, _htTGTContext);
				
//				ASelectEntrustmentLogger.getHandle().log((String)_htTGTContext.get("uid"), (String)_htTGTContext.get("client_ip"), (String)_htTGTContext.get("app_id"), sOBOId, status);
				ASelectEntrustmentLogger.getHandle().log(Auxiliary.obfuscate((String)_htTGTContext.get("uid")), (String)_htTGTContext.get("client_ip"), (String)_htTGTContext.get("app_id"), sOBOId, status);
			}
			else {	// not a bsn or invalid obo or communication problem
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Invalid bsn for obo, status: " + status );
//				ASelectEntrustmentLogger.getHandle().log((String)_htTGTContext.get("uid"), (String)_htTGTContext.get("client_ip"), (String)_htTGTContext.get("app_id"), sOBOId, status);
				ASelectEntrustmentLogger.getHandle().log(Auxiliary.obfuscate((String)_htTGTContext.get("uid")), (String)_htTGTContext.get("client_ip"), (String)_htTGTContext.get("app_id"), sOBOId, status);
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Retrying, retry number:" +iOboRetries);
				_htTGTContext.put("obo_retries", iOboRetries);
				// store oriuid, OBOServiceId, OBOValidFrom in tgt
				_tgtManager.updateTGT(sTgt, _htTGTContext);

				try {
					String sSelectForm;
					// RH, 20150529, sn
					if (status == null) {
						sSelectForm = org.aselect.server.utils.Utils.presentOnBehalfOf(_servletRequest, _configManager,
								htServiceRequest, null, (String)_htTGTContext.get("language"), 4 /* step 4, technical problem */);
					} else {
						if (iOboRetries < obo_maxRetries) {
							// allow for re-entering obo from user
							sSelectForm = org.aselect.server.utils.Utils.presentOnBehalfOf(_servletRequest, _configManager,
								htServiceRequest, null, (String)_htTGTContext.get("language"), 2 /* step 2, retry obo */);
						} else {
							// RH, 20150529, en
							sSelectForm = org.aselect.server.utils.Utils.presentOnBehalfOf(_servletRequest, _configManager,
									htServiceRequest, null, (String)_htTGTContext.get("language"), 3 /* step 3, max_retries */);
						}// RH, 20150529, sn
					}// RH, 20150529, en
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);

					pwOut.println(sSelectForm);
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Cannot present OnBehalfOf form");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				return;
			}
			break;
		default:
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid step parameter received");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		
		if (_htTGTContext == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Cannot get TGT");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// The tgt was just issued and updated, report sensor data
		Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_sbh", null, _htSessionContext, sTgt, true);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIRECT to " + sAppUrl);

		_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

		TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
		String sLang = (String)_htTGTContext.get("language");
//		oTGTIssuer.sendTgtRedirect(sAppUrl, sTgt, null, servletResponse, sLang);		// RH, 20210812, o
		// RH, 20210812, sn
		// Some handlers require the rid. so lets put it there
		String sRid = (String)_htTGTContext.get("rid");
		oTGTIssuer.sendTgtRedirect(sAppUrl, sTgt, sRid, servletResponse, sLang);
		// RH, 20210812, en
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
	private void handleDirectLogin(HashMap htServiceRequest, HttpServletResponse xservletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleDirectLogin";
		String sRid = null;
		// 20121024, Bauke: added udb_user_ident mechanism
		HashMap<String, String> hmUserIdent = new HashMap<String, String>();

		String sRequest = (String) htServiceRequest.get("request");
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "request="+sRequest+" htServReq="+Auxiliary.obfuscate(htServiceRequest));
		try {
			sRid = (String) htServiceRequest.get("rid");
			String sAuthSPId = (String) _htSessionContext.get("direct_authsp");
			_systemLogger.log(Level.FINE, _sModule, sMethod, "authsp from session="+sAuthSPId);
			if (sAuthSPId == null) {
				sAuthSPId = (String) htServiceRequest.get("authsp");
				_systemLogger.log(Level.FINE, _sModule, sMethod, "authsp from request="+sAuthSPId);
				if (sAuthSPId != null) {
					_htSessionContext.put("direct_authsp", sAuthSPId);
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
				}
			}
			if (sAuthSPId == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Missing 'direct_authsp' in session and request, rid='" + sRid + "'");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			IAuthSPDirectLoginProtocolHandler oProtocolHandler = _authspHandlerManager.getAuthSPDirectLoginProtocolHandler(sAuthSPId);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "ProtocolHandler="+oProtocolHandler.getClass());
			
			// Check if user already has a tgt so that he/she doesn't need to be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id"))
			{
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// check if a request was done for another user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "DLOGIN sTgt=" + sTgt + " sUid=" +
						Auxiliary.obfuscate(sUid) + " sServerId=" + sServerId + " sForcedUid=" + Auxiliary.obfuscate(sForcedUid));
				
				if (sForcedUid != null && !sUid.equals(sForcedUid)) { // user_id does not match
					_tgtManager.remove(sTgt);
				}
				else {
					// Reads the TGT into class variable _htTGTContext:
					int rc = checkCredentials(sTgt, sUid, sServerId); // valid credentials/level/SSO group
					if (rc >= 0) {  // ok
						Boolean forcedAuthenticate = (Boolean) _htSessionContext.get("forced_authenticate");
						if (forcedAuthenticate == null)
							forcedAuthenticate = false;
						_systemLogger.log(Level.INFO, _sModule, sMethod, "CheckCred OK forced=" + forcedAuthenticate);
						if (!forcedAuthenticate.booleanValue()) {
							// Valid tgt, no forced_authenticate, update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt
							// No redirectSyncNeeded() mechanism here
							boolean mustChooseOrg = false;
							HashMap<String,String> hUserOrganizations = null;
							if (rc == 1) {  // no organization choice was made
								// 20100318, Bauke: Organization selection is here
								AttributeGatherer ag = AttributeGatherer.getHandle();
								hUserOrganizations = ag.gatherOrganizations(_htTGTContext);
								
								// Also places org_id in the TGT context:
								mustChooseOrg = Utils.handleOrganizationChoice(_htTGTContext, hUserOrganizations);
							}
							_systemLogger.log(Level.INFO, MODULE, sMethod, "MustChoose="+mustChooseOrg+" UserOrgs="+hUserOrganizations);

							Utils.copyHashmapValue("app_id", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("local_organization", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("language", _htTGTContext, _htSessionContext);

							_htTGTContext.put("rid", sRid);

							//	RH, 20140925, sn
							///////////////////////////////////////////////////////////////////////////////////////////////////////////
							Utils.copyHashmapValue("local_organization", _htTGTContext, _htSessionContext);
							// Copy sp_rid as well: xsaml20
							Utils.copyHashmapValue("sp_rid", _htTGTContext, _htSessionContext);
							// 20110526, Bauke, copy sp_reqbinding too, it must survive SSO
							Utils.copyHashmapValue("sp_reqbinding", _htTGTContext, _htSessionContext);
							// RH, 20191128, sn
							// Utils.copyHashmapValue does not remove RelayState if not found in _htSessionContext
							if (_htSessionContext.get("RelayState") == null) {
								_htTGTContext.remove("RelayState");
							} else {	// RH, 20191128, en
								Utils.copyHashmapValue("RelayState", _htTGTContext, _htSessionContext);
							}	// RH, 20191128, n
							// Add the SP to SSO administration - xsaml20
							String sAppId = (String) _htSessionContext.get("app_id");
							String sTgtAppId = (String) _htTGTContext.get("app_id");
							String spIssuer = (String) _htSessionContext.get("sp_issuer");
							// Utils.copyHashmapValue("app_id", htTGTContext, _htSessionContext);
							if (sAppId != null) {
								if (spIssuer == null || sTgtAppId == null)
									_htTGTContext.put("app_id", sAppId);
							}
							if (spIssuer != null) { // saml20 sessions
								_htTGTContext.put("sp_issuer", spIssuer); // save latest issuer
								UserSsoSession ssoSession = (UserSsoSession) _htTGTContext.get("sso_session");
								if (ssoSession == null) {
									_systemLogger.log(Level.INFO, MODULE, sMethod, "NEW SSO session for " + Auxiliary.obfuscate(sUid)
											+ " issuer=" + spIssuer);
									ssoSession = new UserSsoSession(sUid, ""); // sTgt);
								}
								ServiceProvider sp = new ServiceProvider(spIssuer);
								ssoSession.addServiceProvider(sp);
								_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD SSO session " + ssoSession);
								_htTGTContext.put("sso_session", ssoSession);
							}

							// Overwrite with the latest value of sp_assert_url,
							// so the customer can reach his home-SP again.
							Utils.copyHashmapValue("sp_assert_url", _htTGTContext, _htSessionContext);
							/////////////////////////////////////////////////////////////////////////////////////
							//	RH, 20140925, en

							// 20170608, RH: for Oauth2
							Utils.copyHashmapValue("oauthsessionid", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionstate", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionredirect_uri", _htTGTContext, _htSessionContext);
							// 20180830, RH, sn
							Utils.copyHashmapValue("oauthsessionresp_types", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionscope", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionclient_id", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionnonce", _htTGTContext, _htSessionContext);
							// 20180830, RH, en
							Utils.copyHashmapValue("oauthsessionresponse_mode", _htTGTContext, _htSessionContext);	// RH, 20190905, n
							// RH, 20191206, sn
							Utils.copyHashmapValue("oauthsessionaud", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionprompts", _htTGTContext, _htSessionContext);
							// RH, 20191206, en
							
							_tgtManager.updateTGT(sTgt, _htTGTContext);
							
							// 20100210, Bauke: Present the Organization selection to the user
							// Leaves the Rid session in place, needed for the application url
							if (rc == 1 && mustChooseOrg) {
								Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);
								//_sessionManager.update(sRid, _htSessionContext); // Write session
								// pauseSensorDate() already does this: _sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
								// The user must choose his organization
								String sSelectForm = org.aselect.server.utils.Utils.presentOrganizationChoice(_servletRequest,
										_configManager, _htSessionContext, sRid, (String)_htTGTContext.get("language"), hUserOrganizations);

								pwOut.println(sSelectForm);
								return;
							}

							// Redirect to application as user has already a valid tgt
							// RH, 20140925, so
//							String sRedirectUrl;
//							if (_htSessionContext.get("remote_session") == null) {
//								sRedirectUrl = (String)_htSessionContext.get("app_url");
//							}
//							else {
//								sRedirectUrl = (String)_htSessionContext.get("local_as_url");
//							}
							// RH, 20140925, eo
							String sRedirectUrl = extractRedirectURL(_htSessionContext);		// RH, 20140925, n

							_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);
							// 20111101, Bauke: added Sensor
							Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_sbh", sRid, _htSessionContext, sTgt, true);
							// Session must be removed
							_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

							String sLang = (String)_htTGTContext.get("language");
							TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
							oTGTIssuer.sendTgtRedirect(sRedirectUrl, sTgt, sRid, _servletResponse, sLang);
							return;
						}
						// else: forcedAuthenticate: fall through
					}
					
					////////////////////////////////////////////// handle forced_passive	////////////////////////////////////
					Boolean forced_passive = (Boolean) _htSessionContext.get("forced_passive");
					_systemLogger.log(Level.INFO, _sModule, sMethod, "forced_passive=" + forced_passive);
					if (forced_passive != null && forced_passive.booleanValue()) {
						TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
						String sLang = (String)_htSessionContext.get("language");// maybe no tgt context
						String sRedirectUrl = extractRedirectURL(_htSessionContext);
						oTGTIssuer.sendTgtRedirect(sRedirectUrl, null, sRid, _servletResponse, sLang);	// redirect without tgt
						return; // Quit
					}
					//////////////////////////////////////////////////////////////////////////////////////////////
					
					
					
					// TGT found but not sufficient. It could be partially sufficient though
					// (see the "next_authsp" mechanism).
					
					/*
					 * We know the authsp here, and it's level, we can examine the TGT and see what level we already have.
					 * if TGT-level >= authsp_level then we can skip a first_authsp and go to the next_authsp, etc
					 */
					String sAppId = (String)_htSessionContext.get("app_id");
					Application aApp = _applicationManager.getApplication(sAppId);
					String first_authsp = aApp.getFirstAuthsp();
					String next_authsp = _authspHandlerManager.getNextAuthSP(sAuthSPId, sAppId);
					int iAuthspLevel = _authspHandlerManager.getLevel(sAuthSPId);
					int iTgtLevel = getLevelFromTGT(_htTGTContext);
					_systemLogger.log(Level.INFO, _sModule, sMethod, "NEXT_AUTHSP app_id="+sAppId+" authspLevel="+iAuthspLevel+
							" tgtLevel="+iTgtLevel+" first_authsp="+first_authsp+" next_authsp="+next_authsp);
					if (first_authsp != null && next_authsp != null && iTgtLevel >= iAuthspLevel) {
						// Skip to next_authsp
						// NOTE: sms is not a direct_authsp, therefore this does not work:
						//  _htSessionContext.put("direct_authsp", next_authsp);
						//  handleDirectLogin(htServiceRequest, servletResponse, pwOut);
						
						_htSessionContext.remove("direct_authsp");	// No other direct_authsp's yet
						_htSessionContext.put("forced_authsp", next_authsp);
						// RH, 20140424, sn
						Integer iSubLevel = null;
						try {
							iSubLevel = _applicationManager.getSubLevel(sAppId);
							_htSessionContext.put("sub_level", iSubLevel);  // need not be saved
						}
						catch (ASelectException ae) {
							_systemLogger.log(Level.FINER, _sModule, sMethod, "No sub_level found for application: " + sAppId );
						}
						// RH, 20140424, en

						getUserAuthsps(sRid, sUid);  // can change the session too
						_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
						
						String sNextauthspForm = _configManager.getHTMLForm("nextauthsp", _sUserLanguage, _sUserCountry);
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[rid]", sRid);
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[a-select-server]",  (String) htServiceRequest.get("a-select-server"));
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[user_id]", sUid);
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[authsp]", next_authsp);
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[request]", "login3");
						String sLanguage = (String) htServiceRequest.get("language");  // 20101027 _
						String sCountry = (String) htServiceRequest.get("country");  // 20101027 _
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[language]", sLanguage);
						sNextauthspForm = Utils.replaceString(sNextauthspForm, "[country]", sCountry);
						sNextauthspForm = _configManager.updateTemplate(sNextauthspForm, _htSessionContext, _servletRequest);
						
						_htSessionContext.put("user_state", "state_nextauthsp");
						_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);
						Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
						//_sessionManager.update(sRid, _htSessionContext); // Write session

						pwOut.println(sNextauthspForm);						
						return;
					}

					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) _htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) _htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg)) {
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
						_htSessionContext.put("user_state", "state_crosslogin");
						Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
						handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
						return;
					}
					if ("direct_login2".equals(sRequest)) {
						if (!isUserAselectEnabled(sUid, hmUserIdent)) {  // Check the UDB using the "AselectAccountEnabled" field
							htServiceRequest.put("password", "");  // Force error message in handleDirectLoginRequest()
						}
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					// showDirectLoginForm(htServiceRequest,pwOut);
					_htSessionContext.put("user_state", "state_directlogin");
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
					oProtocolHandler.handleDirectLoginRequest(htServiceRequest, _servletRequest, _servletResponse, _htSessionContext,
									hmUserIdent, pwOut, _sMyServerId, _sUserLanguage, _sUserCountry);
					_systemLogger.log(Level.FINE, _sModule, sMethod, "DirectLoginRequest handled (TGT)");
					return;
				}
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "No TGT, Continue");
			// no TGT found or killed (other uid)
			
			////////////////////////////////////////////// handle forced_passive	////////////////////////////////////
			Boolean forced_passive = (Boolean) _htSessionContext.get("forced_passive");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "forced_passive=" + forced_passive);
			if (forced_passive != null && forced_passive.booleanValue()) {
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sLang = (String)_htSessionContext.get("language");// maybe no tgt context
				String sRedirectUrl = extractRedirectURL(_htSessionContext);
				oTGTIssuer.sendTgtRedirect(sRedirectUrl, null, sRid, _servletResponse, sLang);	// redirect without tgt
				return; // Quit
			}
			//////////////////////////////////////////////////////////////////////////////////////////////

			
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization")) {
				handleCrossLogin(htServiceRequest, _servletResponse, pwOut);
				return;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			if (sForcedUid != null) {
				htServiceRequest.put("user_id", sForcedUid);
				// showDirectLoginForm(htServiceRequest,pwOut);
			}
			if ("direct_login2".equals(sRequest)) {
				String sUid = (String) htServiceRequest.get("user_id");
				if (!isUserAselectEnabled(sUid, hmUserIdent)) {  // Check the UDB using the "AselectAccountEnabled" field
					htServiceRequest.put("password", "");  // Force error message in handleDirectLoginRequest()
				}
			}
			
			// Will issue a TGT if everything is ok
			_htSessionContext.put("user_state", "state_directlogin");
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			oProtocolHandler.handleDirectLoginRequest(htServiceRequest, _servletRequest, _servletResponse, _htSessionContext,
									hmUserIdent, pwOut, _sMyServerId, _sUserLanguage, _sUserCountry);
			_systemLogger.log(Level.FINE, _sModule, sMethod, "DirectLoginRequest handled (no TGT)");
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
	private int handleLogin1(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleLogin1";
		String sRid = null;
		StringBuffer sbUrl;

		_systemLogger.log(Level.FINEST, _sModule, sMethod, "Login1 SessionContext:" + Auxiliary.obfuscate(_htSessionContext) +
						", ServiceRequest:" + Auxiliary.obfuscate(htServiceRequest));
		try {
			sRid = (String) htServiceRequest.get("rid");

			// Check if user already has a tgt so that he/she doesnt need to be authenticated again
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id"))
			{
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// Check if a request was done for a different user-id
				String sForcedUid = (String) _htSessionContext.get("forced_uid");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "SSO branch uid=" + Auxiliary.obfuscate(sUid) + " forced_uid=" + Auxiliary.obfuscate(sForcedUid));
				if (sForcedUid != null && !sForcedUid.equals("saml20_user") && !sForcedUid.equals("siam_user")
						&& !sUid.equals(sForcedUid)) { 
					// user_id does not match
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Forced uid does not match, remove TGT");
					_tgtManager.remove(sTgt);
				}
				else {
					// Reads the TGT into class variable _htTGTContext:
					int rc = checkCredentials(sTgt, sUid, sServerId); // valid credentials/level/SSO group
					if (rc < 0)
						_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT invalid or missing");
					else {
						Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate");
						if (boolForced == null)
							boolForced = false;
						_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT OK rc="+rc+" forced_authenticate=" + boolForced);
						if (!boolForced.booleanValue()) {
							// valid tgt, no forced_authenticate
							
							if (redirectSyncNeeded(_htTGTContext)) {  // looks for "redirect_sync_time"
								_systemLogger.log(Level.INFO, _sModule, sMethod, "redirectSyncNeeded, goto ISTS");
								// redirect to the ISTS
								String sIsts = (String)_htTGTContext.get("redirect_ists_url");
								String sPostForm = (String)_htTGTContext.get("redirect_post_form");
								String sSelectForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
										sPostForm, _sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
								sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
								sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
								sSelectForm = Utils.replaceString(sSelectForm, "[handler_url]", sIsts);
								Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can update the session
								
								pwOut.println(sSelectForm);
								return 0;
							}

							// redirect to application as user has already a valid tgt
							String sRedirectUrl;
							sRedirectUrl = extractRedirectURL(_htSessionContext);
							_systemLogger.log(Level.INFO, _sModule, sMethod, "No forced_authenticate, redirect="+sRedirectUrl);
							// update TGT with app_id or local_organization
							// needed for attribute gathering in verify_tgt

							_htTGTContext.put("rid", sRid);
							Utils.copyHashmapValue("local_organization", _htTGTContext, _htSessionContext);
							// Copy sp_rid as well: xsaml20
							Utils.copyHashmapValue("sp_rid", _htTGTContext, _htSessionContext);
							// 20110526, Bauke, copy sp_reqbinding too, it must survive SSO
							Utils.copyHashmapValue("sp_reqbinding", _htTGTContext, _htSessionContext);
							// RH, 20191128, sn
							// Utils.copyHashmapValue does not remove RelayState if not found in _htSessionContext
							if (_htSessionContext.get("RelayState") == null) {
								_htTGTContext.remove("RelayState");
							} else {	// RH, 20191128, en
								Utils.copyHashmapValue("RelayState", _htTGTContext, _htSessionContext);
							}	// RH, 20191128, n


							// Add the SP to SSO administration - xsaml20
							String sAppId = (String) _htSessionContext.get("app_id");
							String sTgtAppId = (String) _htTGTContext.get("app_id");
							String spIssuer = (String) _htSessionContext.get("sp_issuer");
							// Utils.copyHashmapValue("app_id", htTGTContext, _htSessionContext);
							if (sAppId != null) {
								if (spIssuer == null || sTgtAppId == null)
									_htTGTContext.put("app_id", sAppId);
							}
							if (spIssuer != null) { // saml20 sessions
								_htTGTContext.put("sp_issuer", spIssuer); // save latest issuer
								UserSsoSession ssoSession = (UserSsoSession) _htTGTContext.get("sso_session");
								if (ssoSession == null) {
									_systemLogger.log(Level.INFO, MODULE, sMethod, "NEW SSO session for " + Auxiliary.obfuscate(sUid)
											+ " issuer=" + spIssuer);
									ssoSession = new UserSsoSession(sUid, ""); // sTgt);
								}
								ServiceProvider sp = new ServiceProvider(spIssuer);
								ssoSession.addServiceProvider(sp);
//								_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD SSO session " + ssoSession);	// RH, 20190129, o
//								_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD SSO session " + Auxiliary.obfuscate(ssoSession));	// RH, 20190129, n	// RH, 20210713, o
								// obfuscation of Object does nothing, so no obfuscation occurs, therefore make it String
								_systemLogger.log(Level.INFO, _sModule, sMethod, "UPD SSO session " + Auxiliary.obfuscate(ssoSession.toString()));	// RH, 20190129, n	// RH, 20210713, n
								_htTGTContext.put("sso_session", ssoSession);
							}

							// Overwrite with the latest value of sp_assert_url,
							// so the customer can reach his home-SP again.
							Utils.copyHashmapValue("sp_assert_url", _htTGTContext, _htSessionContext);
							
							// 20170608, RH: for Oauth2
							Utils.copyHashmapValue("oauthsessionid", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionstate", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionredirect_uri", _htTGTContext, _htSessionContext);
							// 20180830, RH, sn
							Utils.copyHashmapValue("oauthsessionresp_types", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionscope", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionclient_id", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionnonce", _htTGTContext, _htSessionContext);
							// 20180830, RH, en
							Utils.copyHashmapValue("oauthsessionresponse_mode", _htTGTContext, _htSessionContext);	// RH, 20190905, n
							// RH, 20191206, sn
							Utils.copyHashmapValue("oauthsessionaud", _htTGTContext, _htSessionContext);
							Utils.copyHashmapValue("oauthsessionprompts", _htTGTContext, _htSessionContext);
							// RH, 20191206, en

							_tgtManager.updateTGT(sTgt, _htTGTContext);
							_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR " + sRedirectUrl);

							// 20090313, Bauke: add info screen for the user, shows SP's already logged in
							ASelectConfigManager configManager = ASelectConfigManager.getHandle();
							if (spIssuer != null && configManager.getUserInfoSettings().contains("session"))
								showSessionInfo(htServiceRequest, servletResponse, pwOut, sRedirectUrl, sTgt, _htTGTContext, sRid, spIssuer);
							else {
								// 20111101, Bauke: added Sensor
								Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_sbh", sRid, _htSessionContext, sTgt, true);
								_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

								TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
								String sLang = (String)_htTGTContext.get("language");
								oTGTIssuer.sendTgtRedirect(sRedirectUrl, sTgt, sRid, servletResponse, sLang);
							}
							return 0;
						}
						// bad TGT or forced_authenticate
					}
//					_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT not OK");	// RH, 20200526, o
					_systemLogger.log(Level.INFO, _sModule, sMethod, "TGT not OK or forced_authenticate");	// RH, 20200526, n

					////////////////////////////////////////////// handle forced_passive	////////////////////////////////////
					Boolean forced_passive = (Boolean) _htSessionContext.get("forced_passive");
					_systemLogger.log(Level.INFO, _sModule, sMethod, "forced_passive=" + forced_passive);
					if (forced_passive != null && forced_passive.booleanValue()) {
						TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
						String sLang = (String)_htSessionContext.get("language");// maybe no tgt context
						String sRedirectUrl = extractRedirectURL(_htSessionContext);
						oTGTIssuer.sendTgtRedirect(sRedirectUrl, null, sRid, servletResponse, sLang);	// redirect without tgt
						return 0; // Quit
					}
					//////////////////////////////////////////////////////////////////////////////////////////////
					
					if (!handleUserConsent(htServiceRequest, servletResponse, pwOut, sRid)) {
						_systemLogger.log(Level.INFO, _sModule, sMethod, "No user consent");
						return 0; // No consent, Quit
					}

					// Authenicate with same user-id that was stored in the TGT
					// If TGT was issued in cross mode, the user now has to
					// authenticate with a higher level in cross mode again
					String sTempOrg = (String) _htTGTContext.get("proxy_organization");
					if (sTempOrg == null)
						sTempOrg = (String) _htTGTContext.get("organization");
					if (!sTempOrg.equals(_sMyOrg) && // 20090111, Bauke Added test below:
							_crossASelectManager.isCrossSelectorEnabled() && _configManager.isCrossFallBackEnabled())
					{
						_htSessionContext.put("forced_uid", sUid);
						_htSessionContext.put("forced_organization", sTempOrg);
						_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
						_systemLogger.log(Level.INFO, _sModule, sMethod, "To CROSS MyOrg="+_sMyOrg+" != org="+sTempOrg);
						handleCrossLogin(htServiceRequest, servletResponse, pwOut);
						return 0;
					}
					// User was originally authenticated at this A-Select Server
					// The userid is already known from the TGT
					htServiceRequest.put("user_id", sUid);
					rc = handleLogin2(htServiceRequest, servletResponse, pwOut);
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "Return for retry, rc=" + rc);
					// RH, 20190625, sn
					boolean keepTgt = isSpecialSSOGroups();
					if (keepTgt) {
						_systemLogger.log(Level.INFO, _sModule, sMethod, "Retaining tgt due to special sso_groups configuration");
					} else {
					// RH, 20190625, en
						_tgtManager.remove(sTgt);	// remove tgt, retry login
					}	// RH, 20190625, n
//					return;	// RH, 20140328, o
					return rc;	// RH, 20140328, n
				}
			}
			_systemLogger.log(Level.INFO, _sModule, sMethod, "No TGT or removed (other uid) tgt_read="+(_htTGTContext!=null));

			////////////////////////////////////////////// handle forced_passive	////////////////////////////////////
			Boolean forced_passive = (Boolean) _htSessionContext.get("forced_passive");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "forced_passive=" + forced_passive);
			if (forced_passive != null && forced_passive.booleanValue()) {
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sLang = (String)_htSessionContext.get("language");	// no tgt context
				String sRedirectUrl = extractRedirectURL(_htSessionContext);
				oTGTIssuer.sendTgtRedirect(sRedirectUrl, null, sRid, servletResponse, sLang);	// redirect without tgt
				return 0; // Quit
			}
			//////////////////////////////////////////////////////////////////////////////////////////////

			
			boolean bSuccess = handleUserConsent(htServiceRequest, servletResponse, pwOut, sRid);
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
			if (!bSuccess)
				return 0; // Quit

			// 20090120, Bauke store Client IP and User Agent in the Session
			// Note the current session is available through _htSessionContext
			Utils.copyHashmapValue("client_ip", _htSessionContext, htServiceRequest);
			Utils.copyHashmapValue("user_agent", _htSessionContext, htServiceRequest);
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()

			// no TGT found or killed (other uid)
			if (!_configManager.isUDBEnabled() || _htSessionContext.containsKey("forced_organization"))
			{
				_systemLogger.log(Level.INFO, _sModule, sMethod, "UDBEnabled="+_configManager.isUDBEnabled()+
						" forced_organzation="+_htSessionContext.containsKey("forced_organization")+": To Cross 2");
				handleCrossLogin(htServiceRequest, servletResponse, pwOut);
				return 0;
			}
			String sForcedUid = (String) _htSessionContext.get("forced_uid");
			String sForcedAuthsp = (String) _htSessionContext.get("forced_authsp");
			String sState = (String)_htSessionContext.get("user_state");
			
			// 20130820, Bauke: force user back to the 'select' screen! Probably pressed F5 (refresh screen)
			if ("state_select".equals(sState)) {
				sForcedUid = "saml20_user";
			}
			if (sForcedUid != null || sForcedAuthsp != null) {
				if (sForcedUid != null)
					htServiceRequest.put("user_id", sForcedUid);
				if (sForcedAuthsp != null)
					htServiceRequest.put("forced_authsp", sForcedAuthsp);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Forced uid:"+Auxiliary.obfuscate(sForcedUid)+" OR forced authsp:"+sForcedAuthsp+", to login2");
				handleLogin2(htServiceRequest, servletResponse, pwOut);
				int rc = 0;
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Return, rc=" + rc);
				return rc;
			}

			// Show login (user_id) form
			_systemLogger.log(Level.INFO, _sModule, sMethod, "No user id, show LOGIN form");
			String sLoginForm = _configManager.getHTMLForm("login", _sUserLanguage, _sUserCountry);
			sLoginForm = Utils.replaceString(sLoginForm, "[rid]", sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sLoginForm = Utils.replaceString(sLoginForm, "[a-select-server]", _sMyServerId);
			sLoginForm = Utils.replaceString(sLoginForm, "[request]", "login2");  // NEXT STEP
			sLoginForm = Utils.replaceString(sLoginForm, "[cross_request]", "cross_login");

			sbUrl = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error").append(
					"&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=").append(
					_sMyServerId).append("&rid=").append(sRid);
			sLoginForm = Utils.replaceString(sLoginForm, "[cancel]", sbUrl.toString());

			String sErrorMessage = (String)_htSessionContext.get("error_message");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "error_message="+sErrorMessage);
			
			if (sErrorMessage != null) {
				sErrorMessage = _configManager.getErrorMessage(MODULE, sErrorMessage, _sUserLanguage, _sUserCountry);
				sLoginForm = Utils.replaceString(sLoginForm, "[error_message]", sErrorMessage);
			}
			sLoginForm = _configManager.updateTemplate(sLoginForm, _htSessionContext, _servletRequest);
			
			// Bauke 20110720: Extract if_cond=... from the application URL
			String sSpecials = Utils.getAselectSpecials(_htSessionContext, true/*decode too*/, _systemLogger);
			sLoginForm = Utils.handleAllConditionals(sLoginForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);
			
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			//_sessionManager.update(sRid, _htSessionContext); // Write session
			_htSessionContext.put("user_state", "state_login");
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
			pwOut.println(sLoginForm);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return 0;
	}

	/**
	 * @param sMethod
	 * @return
	 */
	protected boolean isSpecialSSOGroups() {
		// check single sign-on groups, special case, all have but one application
		final String sMethod = "inspectSpecialSSOGroups";

		boolean keepTgt = false;
		if (_htSessionContext != null && _htTGTContext != null) {
			Vector vCurSSOGroups = (Vector)_htSessionContext.get("sso_groups");
			String sessionAppId = (String) _htSessionContext.get("app_id");	// RH, 20190823, n
			Vector vOldSSOGroups = (Vector)_htTGTContext.get("sso_groups");
			String tgtAppId = (String) _htTGTContext.get("app_id");	// RH, 20190823, n
			HashMap appsperssogroup = _applicationManager.getAppsPerSSOGroup();
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found sso_groups configuration session: " +vCurSSOGroups + " and tgt: " 
					+ vOldSSOGroups);
			if (vCurSSOGroups != null && vCurSSOGroups.size() == 1 && !"0".equals(vCurSSOGroups.elementAt(0))
					&& 
				vOldSSOGroups != null && vOldSSOGroups.size() == 1 && !"0".equals(vOldSSOGroups.elementAt(0))) {
				// RH, 20190823, sn
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found apps per sso_group session : " +vCurSSOGroups.get(0) + "/" + appsperssogroup.get(vCurSSOGroups.get(0)) + " and tgt: " 
						+ vOldSSOGroups.get(0) + "/" + appsperssogroup.get(vOldSSOGroups.get(0)));
				if ( ((Vector)appsperssogroup.get(vCurSSOGroups.get(0))).size() == 1 && ((Vector)appsperssogroup.get(vOldSSOGroups.get(0))).size() == 1 
					) {
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found special sso_groups configuration");
					// RH, 20190823, en
					keepTgt = true;
				}
			}
		}
		return keepTgt;
	}

	/**
	 * @return
	 */
	private String extractRedirectURL(Map _htSessionContext)
	{
		String sRedirectUrl;
		if (_htSessionContext.get("remote_session") == null) {
			sRedirectUrl = (String) _htSessionContext.get("app_url");
		}
		else if (_htSessionContext.get("sp_assert_url") != null) {
			// xsaml20 addition
			sRedirectUrl = (String) _htSessionContext.get("sp_assert_url");
		}
		else {
			sRedirectUrl = (String) _htSessionContext.get("local_as_url");
		}
		return sRedirectUrl;
	}

	/**
	 * Show session info.
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sRedirectUrl
	 *            the redirect url
	 * @param sTgt
	 *            the tgt
	 * @param htTGTContext
	 *            the tgt context
	 * @param sRid
	 *            the rid
	 * @param spUrl
	 *            the url
	 * @throws ASelectException
	 */
	private void showSessionInfo(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut,
			String sRedirectUrl, String sTgt, HashMap htTGTContext, String sRid, String spUrl)
	throws ASelectException
	{
		final String sMethod = "showSessionInfo";
		long now = new Date().getTime();

		_systemLogger.log(Level.INFO, _sModule, sMethod, "redirect url=" + sRedirectUrl);
		String sInfoForm = _configManager.getHTMLForm("session_info", _sUserLanguage, _sUserCountry);
		sInfoForm = Utils.replaceString(sInfoForm, "[aselect_url]", sRedirectUrl);
		sInfoForm = Utils.replaceString(sInfoForm, "[a-select-server]", _sMyServerId);
		sInfoForm = Utils.replaceString(sInfoForm, "[rid]", sRid);

		String sEncryptedTgt = (sTgt == null) ? "" : _cryptoEngine.encryptTGT(Utils.hexStringToByteArray(sTgt));
		sInfoForm = Utils.replaceString(sInfoForm, "[aselect_credentials]", sEncryptedTgt);

		String sCreateTime = (String) htTGTContext.get("createtime");
		long lCreateTime = 0;
		try {
			lCreateTime = Long.parseLong(sCreateTime);
		}
		catch (Exception exc) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "CreateTime was not set");
		}

		ASelectConfigManager oConfigManager = ASelectConfigManager.getHandle();
		Object oTicketSection = oConfigManager.getSection(null, "storagemanager", "id=tgt");
		String sTimeOut = ASelectConfigManager.getSimpleParam(oTicketSection, "timeout", false);
		if (sTimeOut != null) {
			long timeOutTime = Long.parseLong(sTimeOut);
			timeOutTime = timeOutTime * 1000;
			long secondsToGo = (lCreateTime + timeOutTime - now) / 1000;
			long minutesToGo = secondsToGo / 60;
			if (minutesToGo < 0)
				minutesToGo = 0;
			long hoursToGo = minutesToGo / 60;
			minutesToGo -= 60 * hoursToGo;
			sInfoForm = Utils.replaceString(sInfoForm, "[hours_left]", Long.toString(hoursToGo));
			sInfoForm = Utils.replaceString(sInfoForm, "[minutes_left]", String.format("%02d", minutesToGo));
		}
		else {
			sInfoForm = Utils.replaceString(sInfoForm, "[hours_left]", "");
			sInfoForm = Utils.replaceString(sInfoForm, "[minutes_left]", "");
		}
		String sFriendlyName = ApplicationManager.getHandle().getFriendlyName(spUrl);
		if (sFriendlyName == null)
			sFriendlyName = spUrl;
		sInfoForm = Utils.replaceString(sInfoForm, "[current_sp]", sFriendlyName);

		String sOtherSPs = "";
		UserSsoSession ssoSession = (UserSsoSession) htTGTContext.get("sso_session");
		if (ssoSession != null) {
			List<ServiceProvider> spList = ssoSession.getServiceProviders();
			for (ServiceProvider sp : spList) {
				String sOtherUrl = sp.getServiceProviderUrl();
				if (!spUrl.equals(sOtherUrl)) {
					sFriendlyName = ApplicationManager.getHandle().getFriendlyName(sOtherUrl);
					if (sFriendlyName == null)
						sFriendlyName = sOtherUrl;
					sOtherSPs += sFriendlyName + "<br/>";
				}
			}
		}
		if (_htSessionContext != null)
			_htSessionContext.put("user_state", "state_session_info");
		sInfoForm = Utils.replaceString(sInfoForm, "[other_sps]", sOtherSPs);
		sInfoForm = _configManager.updateTemplate(sInfoForm, _htSessionContext, _servletRequest);
		Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
		//_sessionManager.update(sRid, _htSessionContext); // Write session
		_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
		pwOut.println(sInfoForm);
	}

	// Return: true when user consent is already available, else false
	//
	/**
	 * Handle user consent.
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sRid
	 *            the s rid
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
	private boolean handleUserConsent(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut, String sRid)
	throws ASelectException
	{
		String user_consent_COOKIE = "user_consent";
		final String sMethod = "handleUserConsent";

		ASelectConfigManager configManager = ASelectConfigManager.getHandle();
		String sUserInfo = configManager.getUserInfoSettings();
		if (!sUserInfo.contains("consent")) // No "consent" or "save_consent"
			return true;

		Boolean setConsentCookie = sUserInfo.contains("save_consent");
		if (setConsentCookie) {
			String sUserConsent = HandlerTools.getCookieValue(_servletRequest, user_consent_COOKIE, _systemLogger);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "user_consent=" + sUserConsent);
			if (sUserConsent != null && sUserConsent.equals("true"))
				return true;
		}
		// "consent" or "save_consent" is present

		// We need the user's consent to continue
		String sReqConsent = (String) htServiceRequest.get("consent");
		//if ("true".equals(sReqConsent) || "false".equals(sReqConsent)) {
			// 20120216: Already resumed in processBrowserRequest: Tools.resumeSensorData(_systemLogger, _htSessionContext);
			// 20120216: _sessionManager.update(sRid, _htSessionContext);
		//}
		if ("true".equals(sReqConsent)) { // new consent given
			if (setConsentCookie) {
				// Remember the user's answer by setting a Consent Cookie
				String sCookieDomain = _configManager.getCookieDomain();
				HandlerTools.putCookieValue(servletResponse, user_consent_COOKIE, "true",
						sCookieDomain, null, 157680101/*5 years*/, 1/*httpOnly*/, _systemLogger);
			}
			return true;
		}
		if ("false".equals(sReqConsent)) { // User did not give his consent
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_CANCEL);
		}

		// Ask for consent by presenting the userconsent.html form
		Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);
		//_sessionManager.update(sRid, _htSessionContext); // Write session
		_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
		try {
			_sConsentForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
					"userconsent", _sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
			_sConsentForm = Utils.replaceString(_sConsentForm, "[request]", "login1");
			_sConsentForm = Utils.replaceString(_sConsentForm, "[rid]", sRid);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[a-select-server]", _sMyServerId);
			_sConsentForm = Utils.replaceString(_sConsentForm, "[consent]", "true");

			String sAsUrl = _configManager.getRedirectURL();
			_sConsentForm = Utils.replaceString(_sConsentForm, "[aselect_url]", sAsUrl);
			StringBuffer sCancel = new StringBuffer(sAsUrl).append("?request=login1").append("&rid=").append(sRid)
					.append("&a-select-server=").append(_sMyServerId).append("&consent=false");
			_sConsentForm = Utils.replaceString(_sConsentForm, "[cancel]", sCancel.toString());

			_systemLogger.log(Level.INFO, _sModule, sMethod, "Display ConsentForm");
			pwOut.println(_sConsentForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to display ConsentForm: ", e);
		}
		return false; // means: Consent Form displayed, no consent available yet
	}

	/**
	 * Handles the <code>request=login2</code> request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The request created by the HTML page presented by the <code>handleLogin1</code> function, is verified here.<br>
	 * For the entered user-id a lookup is done in the user database to determine all enabled AuthSP's for this user.
	 * For every AuthSP a verification is done if it matches the required level.<br>
	 * All valid AuthSP's are presented to the user by means of a 'drop-down' list in a HTML page. This HTML page will
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
	 *            
	 * @return 0 = success, 1 = bad user input (back to login1)
	 * 
	 * @throws ASelectException
	 */
	private int handleLogin2(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRid = null;
		String sUid = null;
		String sMethod = "handleLogin2";

		StringBuffer sb;
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "Login2 " + Auxiliary.obfuscate(htServiceRequest));

		ASelectConfigManager configManager = ASelectConfigManager.getHandle();
		String sUserInfo = configManager.getUserInfoSettings();
		boolean bAuthspFromSelect = sUserInfo.contains("authsps_from_select");
		try {
			sRid = (String) htServiceRequest.get("rid");
			String sAuthsp = (String) _htSessionContext.get("forced_authsp");
			String sAppId = (String) _htSessionContext.get("app_id"); // RH, 20140424, n
			if (sAuthsp != null) {
				// Bauke 20080511: added
				// Redirect to the AuthSP's ISTS
				String sAsUrl = _configManager.getRedirectURL(); // <redirect_url> in aselect.xml
				sAsUrl = sAsUrl + "/" + sAuthsp + "?rid=" + sRid; // e.g. saml20_ists
				// RH, 20100907, sn, add app_id, requestorfriendlyname so authsp can use this at will
//				String sAppId = (String) _htSessionContext.get("app_id");  // 20101027 // RH, 20140424, o, moved to top
				String sFName = null;
				try {
					sFName = _applicationManager.getFriendlyName(sAppId);
					if (sFName != null && !"".equals(sFName)) {
						sAsUrl = sAsUrl + "&" + "requestorfriendlyname" + "="  +  URLEncoder.encode(sFName, "UTF-8");
					}
				}
				catch (ASelectException ae) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Redirect without FriendlyName. Could not find or encode FriendlyName for: " + sAppId );
				}
				// RH, 20100907, en
				
				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR to " + sAsUrl + " forced_authsp=" + sAuthsp);
				servletResponse.sendRedirect(sAsUrl);
				return 0;
			}
			// Has done it's work if present, note that getAuthsps() will store the session
			_htSessionContext.remove("forced_uid");  // 20101027 _, solves JDBC issue where forced_uid was not removed!
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added

			sUid = (String) htServiceRequest.get("user_id");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'user_id'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// If uid contains spaces, they where transformed to '+'
			// Translate them back.
			try {
				sUid = URLDecoder.decode(sUid, "UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to decode user id.");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}

			// RH, 20140424, sn
			Integer iSubLevel = null;
			try {
				iSubLevel = _applicationManager.getSubLevel(sAppId);
				_htSessionContext.put("sub_level", iSubLevel);  // need not be saved
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.FINER, _sModule, sMethod, "No min_level found for application: " + sAppId );
			}
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger); 
			// RH, 20140424, en
			
			
			try {
				// Get authsps for this user, result is a collection of authsps with a login name to be used for that authsp
				// Stored in the session under "allowed_user_authsps"
				getUserAuthsps(sRid, sUid);  // will update _htSessionContext!
			}
			catch (ASelectException e) {
				if (_crossASelectManager.isCrossSelectorEnabled() && _configManager.isCrossFallBackEnabled()) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve AuthSPs for user="+sUid+" goto CROSS");
					handleCrossLogin(htServiceRequest, servletResponse, pwOut);
					return 0;
				}
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve AuthSPs for user " + Auxiliary.obfuscate(sUid));
				// Would like to go back to login1 to give the user another chance
				_htSessionContext.put("error_message", Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
				return 1;
			}

			// Bauke: added shortcut when using "Verkeersplein" method
			String sFixedAuthsp = (String) _htSessionContext.get("fixed_authsp");
			if (sFixedAuthsp != null) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "fixed_authsp=" + sFixedAuthsp);
				htServiceRequest.put("authsp", sFixedAuthsp);
				
				// Also save entered uid as 'sel_uid'
				String sUserId = (String) _htSessionContext.get("user_id");
				if (sUserId != null) {
					htServiceRequest.put("sel_uid", sUserId);
					_htSessionContext.put("sel_uid", sUserId);
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
				}
				String sFixedUid = (String) _htSessionContext.get("fixed_uid");
				if (sFixedUid != null) {
					// From here on use the fixed_uid as 'user_id'
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Fixed user_id=" + Auxiliary.obfuscate(sFixedUid));
					htServiceRequest.put("user_id", sFixedUid);
					_htSessionContext.put("user_id", sFixedUid);
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added
				}
				handleLogin3(htServiceRequest, servletResponse, pwOut);
				return 0;
			}

			// We now have the list of authsps that the user may use. Show the selectform
			HashMap htAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
			// Should the user be bothered with the selection form
			// if only one method is available?
			String sFormShow = _configManager.getParam(_configManager.getSection(null, "authsps"), "always_show_select_form");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "User="+Auxiliary.obfuscate(sUid)+" Authsps="+htAuthsps+" always_show_select_form="+sFormShow);
			if (htAuthsps.size() == 1 && !bAuthspFromSelect) {
				try {
					if (sFormShow.equalsIgnoreCase("false")) {
						// continue with login3
						Set keys = htAuthsps.keySet();
						for (Object s : keys) {
							htServiceRequest.put("authsp", (String) s);
							break;
						}
						_systemLogger.log(Level.INFO, _sModule, sMethod, "Single authsp, goto login3");
						handleLogin3(htServiceRequest, servletResponse, pwOut);
						return 0;
					}
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Failed to retrieve config 'always_show_select_form'. Using default (yes).");
				}
			}
			// end only 1 valid authsp or bAuthspFromSelect

			// Multiple candidates, present the select.html form
			_systemLogger.log(Level.INFO, _sModule, sMethod, "Multiple authsps or 'authsps_from_select' was set: show 'select' form");
			// 20130514, Bauke: remember what the user sees on the screen
			_htSessionContext.put("user_state", "state_select");
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);

			// RH, 20121119, sn
			// Handle application specific select form
			String sSelectFormName = SELECTFORMPREFIX; // "select"
//			String sAppId = (String) _htSessionContext.get("app_id");	// RH, 20121119, o, moved to top
			if (sAppId != null && (_applicationManager.getSelectForm(sAppId) != null) ) {
				sSelectFormName +=  _applicationManager.getSelectForm(sAppId); // Add application specific suffix
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Found application specific select form: " + sSelectFormName + " for app_id: " + sAppId);
			}
			String sSelectForm = _configManager.getHTMLForm(sSelectFormName, _sUserLanguage, _sUserCountry);

			sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
			sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
			sSelectForm = Utils.replaceString(sSelectForm, "[user_id]", sUid);
			sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", (String) htServiceRequest.get("my_url"));
			sSelectForm = Utils.replaceString(sSelectForm, "[request]", "login3");
			String sLanguage = (String)_htSessionContext.get("language");  // 20101027 _
			String sCountry = (String)_htSessionContext.get("country");  // 20101027 _
			sSelectForm = Utils.replaceString(sSelectForm, "[language]", sLanguage);
			sSelectForm = Utils.replaceString(sSelectForm, "[country]", sCountry);
			
			// 20130411: What AuthSP's must be presented to the user?
			if (bAuthspFromSelect) {
				// 20130411, Bauke: Take AuthSP's from select.html
				String sUrl = "", sName = "", sSelectChoice = "";

				try {
					sSelectChoice = HandlerTools.getEncryptedCookie(_servletRequest, select_choice_COOKIE, _systemLogger);
				}
				catch (ASelectException ae) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt cookie: " + select_choice_COOKIE);
				}
				if (Utils.hasValue(sSelectChoice)) {
					_systemLogger.log(Level.INFO, _sModule, sMethod, "select_choice=" + sSelectChoice);
					// Earlier choice present, get it selected
					// Contents of the cookie: <authsp_url>;<authsp_name>
					// In the form look for: <option value="..." ...
					// Note the authsp_name can contain double quotes, they must be escaped for HTML usage.
					sSelectChoice = sSelectChoice.replaceAll("\"", "&quot;");
					int idxChoice = sSelectForm.indexOf(sSelectChoice);
					if (idxChoice >= 0) {
						// Cookie choice is still present in the form, "select" it
						int idxValue = sSelectForm.lastIndexOf("value", idxChoice);
						if (idxValue >= 0) {
							sSelectForm = sSelectForm.substring(0, idxValue).concat("selected ").concat(sSelectForm.substring(idxValue));
						}
						// Replacements in the form, split using the semicolon
						// If no semicolon is present, we only have the "url" part available.
						sUrl = sSelectChoice;
						int idx = sSelectChoice.indexOf(';');
						if (idx >= 0) {
							sUrl = sSelectChoice.substring(0, idx);
							sName = sSelectChoice.substring(idx+1);
						}
					}
				}
				
				sSelectForm = Utils.replaceString(sSelectForm, "[authsp_url]", sUrl);
				sSelectForm = Utils.replaceString(sSelectForm, "[authsp_name]", sName);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "url="+sUrl+" name="+sName);
			}
			else {  // The Classic Solution, take authsp's from the configuration
				String sFriendlyName = "";
				String sAuthspName = "";
				sb = new StringBuffer();
				Set<String> keys = htAuthsps.keySet();
				
				for (Object s : keys) {
					sAuthspName = (String) s;
					try {
						Object authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
								"authsp", "id=" + sAuthspName);
						sFriendlyName = _configManager.getParam(authSPsection, "friendly_name");
						sb.append("<OPTION VALUE=").append(sAuthspName).append(">");
						sb.append(sFriendlyName);
						sb.append("</OPTION>");
					}
					catch (ASelectConfigException ace) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.");
						throw ace;
					}
				}
				sSelectForm = Utils.replaceString(sSelectForm, "[allowed_user_authsps]", sb.toString());
			}

			// Create the Cancel action:
			sb = new StringBuffer((String) htServiceRequest.get("my_url")).append("?request=error")
					.append("&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=")
					.append(_sMyServerId).append("&rid=").append(sRid);

			sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sb.toString());
			sSelectForm = _configManager.updateTemplate(sSelectForm, _htSessionContext, _servletRequest);
			
			//
			// 20151222, Bauke: these lines were missing, therefore no conditions (if_cond, if_error)
			//String sSpecials = Utils.getAselectSpecials(_htSessionContext, true/*decode too*/, _systemLogger);
			//sSelectForm = Utils.handleAllConditionals(sSelectForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);
			//

			// _systemLogger.log(Level.FINER, _sModule, sMethod, "Form select=["+sSelectForm+"]");
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			//_sessionManager.update(sRid, _htSessionContext); // Write session
			// pauseSensorData does this already: _sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
			pwOut.println(sSelectForm);
			return 0;
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

		_systemLogger.log(Level.FINEST, _sModule, sMethod, "login3 " + Auxiliary.obfuscate(htServiceRequest));
		try {
			sRid = (String)htServiceRequest.get("rid");
			sAuthsp = (String)htServiceRequest.get("authsp");
			if (sAuthsp == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'authsp'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// 20130411, Bauke: moved before the "authsp_from_select" code
			String sAppId = (String)_htSessionContext.get("app_id");
			String sFriendlyName = null;
			try {
				sFriendlyName = _applicationManager.getFriendlyName(sAppId);
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Redirect without FriendlyName. Could not find or encode FriendlyName for: " + sAppId );
			}
			// RH, 20100907, en
			
			// 20130411, Bauke: Register the choice made by the user
			ASelectConfigManager configManager = ASelectConfigManager.getHandle();
			String sUserInfo = configManager.getUserInfoSettings();
			
			// 20120815, Bauke: Before startAuthentication, because it reads from config
			Object authSPsection = getAuthspParametersFromConfig(sAuthsp);

			String sSaveAppId = sAppId;  // save session version of app_id
			boolean bAuthspFromSelect = sUserInfo.contains("authsps_from_select");
			String sChosenAppId = (String)htServiceRequest.get("app_id");  // looks like <url_or_id>;<user_frienly_name>
			String sSocialLogin = (String)htServiceRequest.get("social_login");  // 20140216, Bauke: added
			_systemLogger.log(Level.INFO, _sModule, sMethod, "app_id="+sAppId+" chosenAppId="+sChosenAppId+
						" authsps_from_select="+bAuthspFromSelect+" social_login="+sSocialLogin);
			if (bAuthspFromSelect && Utils.hasValue(sChosenAppId)) {
				// Save user choice (value of app_id) in the cookie
				// Note: use the server's cookie domain, not the one set in the AuthSP, see getAuthspParametersFromConfig()
				// 20130502, Bauke: Handled by the test above:
				//if (!Utils.hasValue(sChosenAppId)) {
				//	_systemLogger.log(Level.WARNING, _sModule, sMethod, "No app_id found in request, \"authsps_from_select\"=true");
				//	throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				//}

				// Split sChosenAppId
				// Note the authsp_name can contain double quotes, they must be escaped for HTML usage.
				// but the name is not used here: sChosenAppId = sChosenAppId.replaceAll("\"", "&quot;");
				// If no semicolon is present, we only have the "url" part available.
				String sChosenPart1 = sChosenAppId;
				int idx = sChosenAppId.indexOf(';');
				if (idx >= 0) {
					sChosenPart1 = sChosenAppId.substring(0, idx);
				}
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Using authsps_from_select mechanism, sChosenAppId="+sChosenAppId);
				
				// 20130821, Bauke: introduced setEntrypedCookie() method
				HandlerTools.setEncryptedCookie(servletResponse, select_choice_COOKIE, sChosenAppId, _configManager.getCookieDomain(), 157680101/*5 years*/, _systemLogger);
				// Old:
				//sChosenAppId = _cryptoEngine.encryptData(sChosenAppId.getBytes());  // _configManager.getDefaultPrivateKey());
				//String sCookieDomain = _configManager.getCookieDomain();
				//HandlerTools.putCookieValue(servletResponse, select_choice_COOKIE, sChosenAppId,
				//		sCookieDomain, null, 157680101/*5 years*/, 1/*httpOnly*/, _systemLogger);
				
				// And temporarily replace the provided "app_id" with the user's choice
				// This value will be used by startAuthentication() to create the redirect_url
				_htSessionContext.put("app_id", sChosenPart1);  // need not be saved
			}
			// End of registration

			
			//	RH, 20140424, sn
			Object oAuthSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"),
					"authsp", "id=" + sAuthsp);
//			boolean bUDBLookup = _configManager.getParam(oAuthSPsection, "udb_lookup");
			boolean bUDBLookup = false;
			String sUDBLookup = null;
			try {
				sUDBLookup = _configManager.getParam(oAuthSPsection, "udb_lookup");
				bUDBLookup = Boolean.parseBoolean(sUDBLookup);
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found udb_lookup=" + sUDBLookup);
			} catch (ASelectConfigException ace) {
				// No problem, just skip
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found udb_lookup=" + sUDBLookup);
			}
			if (bUDBLookup) {	// do extra udb lookup
				// we want to change user_id but not sure if this will work because tgt might get destroyed when finding other user_id
				// for test get user_id from form
				HashMap htAllowedAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Before lookup htAllowedAuthsps=" + htAllowedAuthsps);
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Before lookup _htSessionContext=" +Auxiliary.obfuscate( _htSessionContext));
				String sUid = (String) _htSessionContext.get("user_id");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Looking up in UDB user_id:" + Auxiliary.obfuscate(sUid));
				// RH, 20140424, sn
				Integer iSubLevel = null;
				try {
					iSubLevel = _applicationManager.getSubLevel(sAppId);
					_htSessionContext.put("sub_level", iSubLevel);  // need not be saved
				}
				catch (ASelectException ae) {
					_systemLogger.log(Level.FINER, _sModule, sMethod, "No min_level found for application: " + sAppId );
				}
				// RH, 20140424, en

				getUserAuthsps(sRid, sUid);
				htAllowedAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "After lookup htAllowedAuthsps=" + htAllowedAuthsps);
			}
			//	RH, 20140424, en

			// 20111013, Bauke: added absent phonenumber handling
//			HashMap htResponse = startAuthentication(sRid, htServiceRequest);	// RH, 20180712, o
			HashMap htResponse = startAuthentication(sRid, htServiceRequest, pwOut);	// RH, 20180712, n
			if (htResponse == null) return;
			
			if (bAuthspFromSelect && Utils.hasValue(sChosenAppId))  // restore app_id after startAuthentication() has done it's work
				_htSessionContext.put("app_id", sSaveAppId);
			
			String sResultCode = (String) htResponse.get("result");
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to create redirect url, result="+sResultCode);
				throw new ASelectException(sResultCode);
			}

			sRedirectUrl = (String) htResponse.get("redirect_url");
			try {
				try {
					sPopup = _configManager.getParam(authSPsection, "popup");
				}
				catch (ASelectConfigException e) {
					// No popup configured -> sPopup is null already
				}
				// RH, 20100907, sn, add app_id, requestorfriendlyname so authsp can use this at will
				if (Utils.hasValue(sFriendlyName)) {
					sRedirectUrl = sRedirectUrl + "&" + "requestorfriendlyname" + "="  +  URLEncoder.encode(sFriendlyName, "UTF-8");
				}
				// RH, 20100907, en
				// 20140216, Bauke: added social login
				//if (Utils.hasValue(sSocialLogin)) {
				//	sRedirectUrl = sRedirectUrl + "&" + "social_login" + "="  +  URLEncoder.encode(sSocialAuth, "UTF-8");
				//}

				_systemLogger.log(Level.FINEST, _sModule, sMethod, "REDIRECT " + sRedirectUrl);
				if (sPopup == null || sPopup.equalsIgnoreCase("false")) {
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102, control goes to a different server
					_htSessionContext.put("authsp_visited", "true");
					_htSessionContext.put("user_state", "state_redirect");
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
					servletResponse.sendRedirect(sRedirectUrl);
					return;
				}

				// must use popup so show the popup page
				String sPopupForm = _configManager.getHTMLForm("popup", _sUserLanguage, _sUserCountry);
				sPopupForm = Utils.replaceString(sPopupForm, "[authsp_url]", sRedirectUrl);
				String strFriendlyName = _configManager.getParam(authSPsection, "friendly_name");
				sPopupForm = Utils.replaceString(sPopupForm, "[authsp]", strFriendlyName);
				sPopupForm = _configManager.updateTemplate(sPopupForm, _htSessionContext, _servletRequest);
				Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  // 20111102, control to the user
				
				_htSessionContext.put("user_state", "state_popup");
				_htSessionContext.put("authsp_visited", "true");
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
				pwOut.println(sPopupForm);
				return;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve config for AuthSPs.");
				throw new ASelectException(e.getMessage());
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.");
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
		String sMethod = "handleCrossLogin";

		_systemLogger.log(Level.FINEST, _sModule, sMethod, "CrossLogin htServiceRequest=" + Auxiliary.obfuscate(htServiceRequest));
		try {
			// is cross enabled? (configuration)
			if (!_crossASelectManager.remoteServersEnabled()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Cross A-Select is disabled since it is not (properly) configured.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
			}

			// Is equal to the sRid value we already have in the caller
			String sRid = (String) htServiceRequest.get("rid");
			Integer intAppLevel = (Integer) _htSessionContext.get("level");
			if (intAppLevel == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not fetch level from session context.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			sRemoteOrg = (String) _htSessionContext.get("forced_organization");

			// check if the request was done for a specific user_id
			sUid = (String) _htSessionContext.get("forced_uid");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN sRid=" + sRid + ", intAppLevel="
					+ intAppLevel + ", sRemoteOrg=" + sRemoteOrg + ", forced_uid=" + Auxiliary.obfuscate(sUid));

			if (sRemoteOrg == null) {
				if (!_crossASelectManager.isCrossSelectorEnabled()) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod,
							"Dynamic 'cross_selector' is disabled, parameter 'remote_organization' is required but not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}

				// No optional parameter 'remote_organization found, determine the remote organization
				// some selector handlers may need the user_id if it is known already
				HashMap htIdentification = null;
				if (sUid != null) {
					htServiceRequest.put("user_id", sUid);  // NOTE: in the Service Request, not the Session
				}
				try {
					htIdentification = _crossASelectManager.getSelectorHandler().
							getRemoteServerId(htServiceRequest, servletResponse, pwOut);
				}
				catch (ASelectException ace) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to retrieve the remote server id.");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG, ace);
				}
				if (htIdentification == null) {
					_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN !htIdentification");
					// The handler was not ready yet and presented a HTML form to the end user 
					// to gather more information. This form will POST 'request=cross_authenticate' again.
					return;
				}
				sRemoteOrg = (String) htIdentification.get("organization_id");
				String sTemp = (String) htIdentification.get("user_id");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "XLOGIN htIdentification=" + htIdentification);

				// Selector handler might have translated the user_id
				if (sTemp != null)
					sUid = (String) htIdentification.get("user_id");
			}
			//_htSessionContext.put("remote_organization", sRemoteOrg);
			// 20120403, Bauke: no longer needed this method does not change the session
			//_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

			// storage_manager_fix_for_lost_fields
			// 20120403, Bauke: no longer needed this method does not change the session
			//if (!_sessionManager.update Session(sRid, _htSessionContext)) {
			//	_systemLogger.log(Level.WARNING, _sModule, sMethod, "could not update session context");
			//	throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			//}

			Object oRemoteServer;
			String sRemoteAsUrl;
			String sRemoteServer;
			try {
				// continue cross a-select login processing
				String sResourcegroup = _crossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
				if (sResourcegroup == null) {
					StringBuffer sbWarning = new StringBuffer("Unknown organization '");
					sbWarning.append(sRemoteOrg);
					sbWarning.append("'");
					_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbWarning.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_UNKNOWN_ORG);
				}
				SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
				oRemoteServer = oSAMResource.getAttributes();
				sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
				sRemoteServer = _crossASelectManager.getRemoteParam(sRemoteOrg, "server");
			}
			catch (ASelectSAMException ase) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
				throw ase;
			}
			catch (ASelectConfigException ace) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read config.");
				throw ace;
			}

			StringBuffer sbMyAppUrl = new StringBuffer();
			sbMyAppUrl.append((String) htServiceRequest.get("my_url"));
			sbMyAppUrl.append("?local_rid=").append(sRid);

			RawCommunicator oCommunicator = new RawCommunicator(_systemLogger); // Default = API communciation

			HashMap htRequestTable = new HashMap();
			htRequestTable.put("request", "authenticate");

			Boolean boolForced = (Boolean) _htSessionContext.get("forced_authenticate"); // a Boolean
			if (boolForced == null)
				boolForced = false;
			htRequestTable.put("forced_authenticate", boolForced); // boolean
			htRequestTable.put("forced_logon", boolForced.toString()); // and this is a String!
			htRequestTable.put("local_as_url", sbMyAppUrl.toString());

			Object oASelectConfig = _configManager.getSection(null, "aselect");
			String sMyOrgId = _configManager.getParam(oASelectConfig, "organization");
			htRequestTable.put("local_organization", sMyOrgId);

			Integer intLevel = (Integer) _htSessionContext.get("level");
			htRequestTable.put("required_level", intLevel.toString());
			htRequestTable.put("level", intLevel); // 20090111, Bauke added
			htRequestTable.put("a-select-server", sRemoteServer);

			if (sUid != null) {
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

			// check if request should be signed
			if (_crossASelectManager.useRemoteSigning()) {
				_cryptoEngine.signRequest(htRequestTable);
			}
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "XLOGIN htRequestTable=" + Auxiliary.obfuscate(htRequestTable));

			HashMap htResponseTable = oCommunicator.sendMessage(htRequestTable, sRemoteAsUrl);
			if (htResponseTable.isEmpty()) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not reach remote A-Select Server: "
						+ sRemoteAsUrl);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "XLOGIN htResponseTable=" + htResponseTable);

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
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "REDIR " + sbUrl);
				servletResponse.sendRedirect(sbUrl.toString());
			}
			catch (IOException e) {
				StringBuffer sbWarning = new StringBuffer("Failed to redirect user to: ");
				sbWarning.append(sRemoteServer);
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbWarning.toString());
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
	private void handleIPLogin1(HashMap htServiceRequest, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleIPLogin1";
		String sRid = null;
		Integer intRequiredLevel = null;
		String sLevel = null;
		HashMap htAllowedAuthsps = new HashMap();

		StringBuffer sb;

		_systemLogger.log(Level.INFO, _sModule, sMethod, "IPLogin1");
		try {
			sRid = (String) htServiceRequest.get("rid");
			// check if user already has a tgt so that he/she doesnt need to
			// be authenticated again

			// RM_28_01
			// ip-range will never be forced when already authenticated with an
			// AuthSP with a higher level
			if (_configManager.isSingleSignOn() && htServiceRequest.containsKey("aselect_credentials_tgt")
					&& htServiceRequest.containsKey("aselect_credentials_uid")
					&& htServiceRequest.containsKey("aselect_credentials_server_id"))
			{
				String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");
				String sUid = (String) htServiceRequest.get("aselect_credentials_uid");
				String sServerId = (String) htServiceRequest.get("aselect_credentials_server_id");

				// Reads the TGT into class variable _htTGTContext:
				int rc = checkCredentials(sTgt, sUid, sServerId);
				if (rc >= 0) {
					// redirect to application as user has already a valid tgt
					if (_htSessionContext.get("cross_authenticate") != null) {
						// Cross A-Select does not implement 'verify_credentials'
						// The TGT should be created now, TGTIssuer will redirect to local A-Select Server
						_htSessionContext.put("user_id", sUid);

						// RH, should be set through AbstractBrowserRequestHandler
						// but this seems to be the wrong one (AbstractBrowserRequestHandler sets the idp address)
						_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "
								+ _htSessionContext.get("client_ip"));
						_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());
						_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
						_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip is now "
								+ _htSessionContext.get("client_ip"));

						String sAuthsp = (String)_htTGTContext.get("authsp");
						_tgtManager.remove(sTgt);

						HandlerTools.setRequestorFriendlyCookie(_servletResponse, _htSessionContext, _systemLogger);  // 20130825

						// issue new one but with the same lifetime as the existing one
						HashMap htAdditional = new HashMap();
						TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
						oTGTIssuer.issueTGTandRedirect(sRid, _htSessionContext, sAuthsp, htAdditional, _servletRequest, _servletResponse, null, true);
						return;
					}

					try {
						String sRedirectUrl = (String) _htSessionContext.get("app_url");
						sRedirectUrl = URLDecoder.decode(sRedirectUrl, "UTF-8");
						sb = new StringBuffer(sRedirectUrl);

						// check whether the application url contains cgi parameters
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

						// 20111101, Bauke: added Sensor
						Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_sbh", sRid, _htSessionContext, sTgt, true);
						_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

						_systemLogger.log(Level.FINEST, _sModule, sMethod, "REDIR " + sb);
						_servletResponse.sendRedirect(sb.toString());
					}
					catch (UnsupportedEncodingException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to encode user id.");
						throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
					}
					catch (IOException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to redirect user.");
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
				_systemLogger.log(Level.FINEST, _sModule, sMethod, sb.toString());

				throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			htAllowedAuthsps.put("Ip", htServiceRequest.get("client_ip"));
			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", htServiceRequest.get("client_ip"));
			//Utils.setSessionStatus(_htSessionContext, "upd", _systemLogger);
			//_sessionManager.updateSession(sRid, _htSessionContext);
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

			// go for IP authsp
			htServiceRequest.put("authsp", "Ip");
			handleLogin3(htServiceRequest, _servletResponse, pwOut);
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
	 */
	private void handleLogout(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleLogout";
		String sRemoteAsUrl = null;

		try {
			String sTgt = (String)htServiceRequest.get("aselect_credentials_tgt");
			// 20120712, Bauke, not needed, ASelectAuthenticationProfile has already read the TGT
			// HashMap _htTGTContext = _tgtManager.getTGT(sTgt);

			String sCookieDomain = _configManager.getCookieDomain();
			_systemLogger.log(Level.INFO, _sModule, sMethod, "domain="+sCookieDomain);
			HandlerTools.delCookieValue(servletResponse, "aselect_credentials", sCookieDomain, null, _systemLogger);
			// path=/ so applications can access it
			HandlerTools.delCookieValue(servletResponse, "ssoname", sCookieDomain, "/", _systemLogger);
			
			String social_login = null; // RH, 20181002, n
			String sAppId = null;	// RH, 20181004, n
			
			if (_htTGTContext != null) {
				// 20120611, Bauke: added "usi"
				String sUsi = (String)_htTGTContext.get("usi");
				if (Utils.hasValue(sUsi))  // overwrite
					_timerSensor.setTimerSensorId(sUsi);
//				String sAppId = (String)_htTGTContext.get("app_id");	// RH, 20181004, o
				sAppId = (String)_htTGTContext.get("app_id");	// RH, 20181004, n
				if (Utils.hasValue(sAppId))
					_timerSensor.setTimerSensorAppId(sAppId);

				social_login = (String)_htTGTContext.get("social_login");	// RH, 20181002

				_tgtManager.remove(sTgt);

				String sRemoteOrg = (String) _htTGTContext.get("proxy_organization");
				if (sRemoteOrg == null)
					sRemoteOrg = (String) _htTGTContext.get("organization");

				_systemLogger.log(Level.INFO, _sModule, sMethod, "_sMyOrg="+_sMyOrg+" sRemoteOrg="+sRemoteOrg);
				if (!sRemoteOrg.equals(_sMyOrg)) {
					try {
						CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
						String sResourcegroup = oCrossASelectManager.getRemoteParam(sRemoteOrg, "resourcegroup");
						SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
						Object oRemoteServer = oSAMResource.getAttributes();
						sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
					}
					catch (ASelectException ae) {
						_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
						sRemoteAsUrl = null;
					}
				}
			}
			
			if (sRemoteAsUrl == null) {  // 20120809, Bauke: added
				sRemoteAsUrl = (String)htServiceRequest.get("logout_return_url");
			}
			
			// 20120929, Bauke: only allow a redirect from our server when the user was logged in!!
			//
			// Also expect: logout_return_url=http:/www.google.com%2f%0aSet-Cookie%3a+my_cookie%3d%22hello%22%3b
			// but we want to allow: url's with & or ? in them
			if (sRemoteAsUrl != null && _htTGTContext != null) {
				Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
				
				sRemoteAsUrl = URLDecoder.decode(sRemoteAsUrl, "UTF-8");
				int idx = sRemoteAsUrl.indexOf("\r");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "idx\\r="+idx);
				if (idx >= 0) sRemoteAsUrl = sRemoteAsUrl.substring(0, idx);
				idx = sRemoteAsUrl.indexOf("\n");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "idx\\n="+idx);
				if (idx >= 0) sRemoteAsUrl = sRemoteAsUrl.substring(0, idx);
				
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added, was update()
				_systemLogger.log(Level.INFO, _sModule, sMethod, "REDIR "+sRemoteAsUrl+" _sMyOrg="+_sMyOrg);
				servletResponse.sendRedirect(sRemoteAsUrl);  // cannot have urlencoded stuff inside
				return;
			}

			// Otherwise present the "loggedout.html" form
			String sLoggedOutForm = _configManager.getHTMLForm("loggedout", _sUserLanguage, _sUserCountry);
			sLoggedOutForm = _configManager.updateTemplate(sLoggedOutForm, null/*no session*/, _servletRequest);
			// RH, 20181002, sn
			if (social_login == null) {	// try to get it from the cookie
				social_login = HandlerTools.getEncryptedCookie(_servletRequest, "social_login", _systemLogger);
			}
			if (social_login != null) {
				sLoggedOutForm = Utils.replaceString(sLoggedOutForm, "[social_login]", social_login);
			}
			// RH, 20181002, en
			// RH, 20181004, sn
			if (sAppId == null) {	// try to get it from the cookie
				sAppId = HandlerTools.getEncryptedCookie(_servletRequest, "app_id", _systemLogger);
			}
			if (sAppId != null) {
				sLoggedOutForm = Utils.replaceString(sLoggedOutForm, "[app_id]", sAppId);
			}
			// RH, 20181004, en
			
			
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			// no RID _sessionManager.update(sRid, _htSessionContext); // Write session
			if (_htSessionContext != null) {
				_htSessionContext.put("user_state", "state_loggedout");
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added, was update()
			}
			pwOut.println(sLoggedOutForm);
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
	 * The request can be used to logout a user by sending a saml logoutrequest. <br>
	 * e.g. if the user sends a normal request=logout but actually was a saml user and should have send a samlrequest <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * Valid TGT <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to user
	 * @param pwOut
	 *            Used to write information back to the user (HTML)
	 * @throws ASelectException
	 */
	private void handleSamlLogout(HashMap htServiceRequest, HttpServletRequest servletRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleSamlLogout";
		String sRemoteAsUrl = null;

		_systemLogger.log(Level.FINER, _sModule, sMethod, "handleSamlLogout");

			String sTgt = (String)htServiceRequest.get("aselect_credentials_tgt");
			
			if (_htTGTContext != null) {	// must be true for samllogout
				LogoutRequestSender logoutRequestSender = new LogoutRequestSender();
//				String sIssuer = (String)_htTGTContext.get("sp_issuer");
				String sIssuer = _sServerUrl;	// set idp as issuer
				String sNameID = (String)_htTGTContext.get("name_id");
				String sAppId = (String)_htTGTContext.get("app_id");
				//  find a way to get the default, maybe from application section
				// If we allow this we must sanitize this url !!!
				String sLogoutReturnUrl = (String)htServiceRequest.get("logout_return_url");
				if (sLogoutReturnUrl != null) {
					_systemLogger.log(Level.FINER, _sModule, sMethod, "Found logout_return_url in request: " + sLogoutReturnUrl);
					// For backward compatibility, avoid double decoding
					boolean doDecode = true; // backward compatibility
					HashMap<String, Vector<String>> parameters2decode = _configManager.getParameters2decode();
					if ( parameters2decode != null && !parameters2decode.isEmpty()) {
						Vector<String> appl = parameters2decode.get("logout_return_url");
						if ( Utils.hasValue(sAppId) && appl != null && appl.contains(sAppId) ) {	// already decoded
							doDecode = false;
							_systemLogger.log(Level.FINER, _sModule, sMethod, "logout_return_url already urldecoded");
						}
					}
					if ( doDecode ) {
						try {
							sLogoutReturnUrl = URLDecoder.decode(sLogoutReturnUrl, "UTF-8");
							_systemLogger.log(Level.FINER, _sModule, sMethod, "logout_return_url after decoding: " + sLogoutReturnUrl);
						}
						catch (UnsupportedEncodingException e) {
							_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unable to urldecode, unsupported encoding UTF-8");
							throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);					
						}
					}
				}
				// We need to get the logout url from somewhere too
				String url = _sServerUrl + "/saml20_idp_slo_http_request";	// default

				// RH, 20191118, sn
				String target = _applicationManager.getLocalSamlLogoutTarget(sAppId);
				if (Utils.hasValue(target)) {
					url  = _sServerUrl + target;
				}
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "Using local samllogout url:" + url);
				// RH, 20191118, sn

				
				// 20120611, Bauke: added "usi"
				String sUsi = (String)_htTGTContext.get("usi");
				if (Utils.hasValue(sUsi))  // overwrite
					_timerSensor.setTimerSensorId(sUsi);
				if (Utils.hasValue(sAppId))
					_timerSensor.setTimerSensorAppId(sAppId);

				_systemLogger.log(Level.FINER, _sModule, sMethod, "Compose sendLogoutRequest to: " + url);

				logoutRequestSender.sendLogoutRequest(servletRequest, servletResponse, sTgt, url, sIssuer/* issuer */, sNameID,
						"urn:oasis:names:tc:SAML:2.0:logout:user", sLogoutReturnUrl, null, null);

				return;
			} else {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No tgt found!");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
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
	private void handleCreateTGT(HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "handleCreateTGTRequest";
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();

		_systemLogger.log(Level.INFO, _sModule, sMethod, "CreateTGTRequest");
		try {
			// get output writer
			// Read expected parameters
			String sRid = (String) htServiceRequest.get("rid");
			String sUID = (String) htServiceRequest.get("uid");
			String sPrivilegedApplication = (String) htServiceRequest.get("app_id");
			String sSignature = (String) htServiceRequest.get("signature");
			String sAuthspLevel = (String) htServiceRequest.get("level"); // NOTE: String!!

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
			catch (UnsupportedEncodingException eUE) { // Interne fout UTF-8 niet ondersteund
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error: request could not be decoded");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append(sRid).append(sUID);
			sbBuffer.append(sPrivilegedApplication).append(sAuthspLevel);
			if (!CryptoEngine.getHandle().verifyPrivilegedSignature(sPrivilegedApplication, sbBuffer.toString(), sSignature)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Application:" + sPrivilegedApplication
						+ " Invalid signature:" + sSignature);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// 20101027, Bauke: skip reading the session again, it's already available in _htSessionContext!
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

			// 20121024, Bauke: added udb_user_ident mechanism
			HashMap<String, String> hmUserIdent = new HashMap<String, String>();
			isUserAselectEnabled(sUID, hmUserIdent);  // Check the UDB using the "AselectAccountEnabled" field

			// Extend session context
			_htSessionContext.put("user_id", sUID);  // 20101027 use _ht...
			_htSessionContext.put("authsp", sPrivilegedApplication);
			_htSessionContext.put("authsp_level", sAuthspLevel);
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
			
			// Log succesful authentication
			authenticationLogger.log(new Object[] {
				"Login", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), _sMyOrg, sPrivilegedApplication, "granted"
			});

			// 20130825, Bauke: save friendly name after session is gone
			HandlerTools.setRequestorFriendlyCookie(_servletResponse, _htSessionContext, _systemLogger);  // 20130825
			
			// Issue TGT
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
			tgtIssuer.issueTGTandRedirect(sRid, _htSessionContext, sPrivilegedApplication, hmUserIdent/*additional*/, _servletRequest, _servletResponse, null, true/*redirect*/);
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
	 * Get the AuthSP servers for the given user.
	 * Private method that fetches the authentication service providers from the user database
	 * of the A-Select Servers.
	 * The user may have been registered or entitled to use several authentication service providers.
	 * But only the ones that satisfy the level for the current application are returned by filtering the
	 * authsp's with lower levels out.
	 * 
	 * @param sRid
	 *            The RID.
	 * @param sUid
	 *            the uid
	 * @throws ASelectException
	 */
	private void getUserAuthsps(String sRid, String sUid)
	throws ASelectException
	{
		String sMethod = "getUserAuthsps";
		HashMap htUserAuthsps = new HashMap();

		try {
			IUDBConnector oUDBConnector = null;
			try {
				oUDBConnector = UDBConnectorFactory.getUDBConnector();
			}
			catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to connect with UDB.", e);
				throw e;
			}

			// Get user's attributes from the UDB
			HashMap htUserProfile = oUDBConnector.getUserProfile(sUid);
			if (!((String) htUserProfile.get("result_code")).equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Failed to get user profile, result="+(String)htUserProfile.get("result_code"));
				throw new ASelectException((String) htUserProfile.get("result_code"));
			}
			htUserAuthsps = (HashMap) htUserProfile.get("user_authsps");
			if (htUserAuthsps == null) {  // should never happen
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "INTERNAL ERROR no \"user_authsps\" found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			String udbType = (String)htUserProfile.get("udb_type");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "uid=" + Auxiliary.obfuscate(sUid) + " udb_type="+udbType+" profile=" + htUserProfile
					+ " user_authsps=" + htUserAuthsps + " SessionContext=" + _htSessionContext);
			
			

			// Which level is required for the application?
			// 20090110, Bauke added required_level!
			Integer intMaxLevel = (Integer) _htSessionContext.get("max_level"); // 'max_level' can be null
			Integer intLevel = (Integer) _htSessionContext.get("level");
			String sRequiredLevel = (String) _htSessionContext.get("required_level");
			Integer intSubLevel = (Integer) _htSessionContext.get("sub_level");

			Integer intRequiredLevel = (sRequiredLevel == null) ? intLevel : Integer.valueOf(sRequiredLevel);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "required_level=" + intRequiredLevel + " level="
					+ intLevel + " maxlevel=" + intMaxLevel);

			// Fetch the authsps that the user has registered for and
			// that satisfy the level for the current application
			
//			Vector vConfiguredAuthSPs = _authspHandlerManager.getConfiguredAuthSPs(intRequiredLevel, intMaxLevel);	// RH, 20140424, o
			// RH, 20140424, sn
			Vector vConfiguredAuthSPs = null;
			if ( intSubLevel == null) {	// They old way
				vConfiguredAuthSPs = _authspHandlerManager.getConfiguredAuthSPs(intRequiredLevel, intMaxLevel);
			} else {
				vConfiguredAuthSPs = _authspHandlerManager.getConfiguredAuthSPs(intSubLevel, intMaxLevel);
			}
			// RH, 20140424, sn

			if (vConfiguredAuthSPs == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "INTERNAL ERROR" + sUid);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// 20130405, Bauke:
			// If "noudb" is in effect, the user attributes cannot have been set.
			// In that case, we will substitute the uid that was entered by the user for it.
			// Added so the Radius AuthSP could work without having a "UDB".
			boolean isNoUdb = "noudb".equals(udbType);
			HashMap htAllowedAuthsps = new HashMap();
			for (int i = 0; i < vConfiguredAuthSPs.size(); i++) {
				String sAuthSP = (String) vConfiguredAuthSPs.elementAt(i);
				if (htUserAuthsps.containsKey(sAuthSP)) {
					String authSpAttr = (String)htUserAuthsps.get(sAuthSP);
					htAllowedAuthsps.put(sAuthSP, isNoUdb? sUid: authSpAttr);
				}
			}
			if (htAllowedAuthsps.size() == 0) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No valid AuthSPs found for user: " + Auxiliary.obfuscate(sUid));
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);
			}
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "Allowed AuthSPs " + htAllowedAuthsps);

			_htSessionContext.put("allowed_user_authsps", htAllowedAuthsps);
			_htSessionContext.put("user_id", sUid);

			// RH, should be set through AbstractBrowserRequestHandler
			// but this seems to be the wrong one (AbstractBrowserRequestHandler
			// sets the idp address on the idp)
			_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "+
					_htSessionContext.get("client_ip")+", set to "+get_servletRequest().getRemoteAddr());
			
			_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());			
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
			return;
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
	 */
//	private HashMap startAuthentication(String sRid, HashMap htLoginRequest)
	private HashMap startAuthentication(String sRid, HashMap htLoginRequest, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "startAuthentication";
		
		String sAuthsp = (String)htLoginRequest.get("authsp");
		String sSocialLogin = (String)htLoginRequest.get("social_login");  // 20140216, Bauke: added, can be null
		HashMap htAllowedAuthsps = (HashMap) _htSessionContext.get("allowed_user_authsps");
		if (htAllowedAuthsps == null) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "allowed_user_authsps not found in session context");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (!htAllowedAuthsps.containsKey(sAuthsp)) {
			StringBuffer sbError = new StringBuffer("Invalid/unknown authsp id in request, authsp=").append(sAuthsp);
			sbError = sbError.append(", valid are: "+htAllowedAuthsps);
			_systemLogger.log(Level.WARNING, _sModule, sMethod, sbError.toString());
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// _systemLogger.log(Level.INFO, _sModule, sMethod, "session="+_htSessionContext+" login="+htLoginRequest);
		_htSessionContext.put("authsp", sAuthsp);
		_htSessionContext.put("social_login", sSocialLogin);
		_htSessionContext.put("my_url", htLoginRequest.get("my_url"));
		// RH, 20210601, sn
		if (htLoginRequest.get("idin_bank_select") != null) {
			_htSessionContext.put("idin_bank_select", htLoginRequest.get("idin_bank_select"));
		}
		// RH, 20210601, en
		
		// RH, should be set through AbstractBrowserRequestHandler
		// but this seems to be the wrong one (AbstractBrowserRequestHandler sets the idp address on the idp)
		_systemLogger.log(Level.INFO, _sModule, sMethod, "_htSessionContext client_ip was "
				+ _htSessionContext.get("client_ip") + ", set to " + get_servletRequest().getRemoteAddr()+" sCF="+_sCorrectionFacility);
		
		_htSessionContext.put("client_ip", get_servletRequest().getRemoteAddr());
		// 20111013, Bauke: added absent phonenumber handling, to be used by computeAuthenticationRequest():
		_htSessionContext.put("sms_correction_facility", Boolean.toString(Utils.hasValue(_sCorrectionFacility)));
		
		//Tools.pauseSensorData(_systemLogger, _htSessionContext);  // 20111102, done one level higher, before redirection		
		_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

		// Everything seems okay -> instantiate the protocol handler for
		// the selected authsp and let it compute a signed authentication request
		IAuthSPProtocolHandler oProtocolHandler;
		Object oAuthSPsection = null; 	// RH, 20180712, n
		try {
//			Object oAuthSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",	"id=" + sAuthsp); 	// RH, 20180712, o
			oAuthSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp",	"id=" + sAuthsp); 	// RH, 20180712, n
			String sHandlerName = _configManager.getParam(oAuthSPsection, "handler");

			Class oClass = Class.forName(sHandlerName);
			oProtocolHandler = (IAuthSPProtocolHandler) oClass.newInstance();

			// Get authsps config and retrieve active resource from SAMAgent
			String strRG = _configManager.getParam(oAuthSPsection, "resourcegroup");
			SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(strRG);
			Object objAuthSPResource = mySAMResource.getAttributes();
			_systemLogger.log(Level.FINE, _sModule, sMethod, "to init");
			oProtocolHandler.init(oAuthSPsection, objAuthSPResource);
			_systemLogger.log(Level.FINE, _sModule, sMethod, "from init");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to retrieve config for AuthSPHandler="+sAuthsp);
			throw new ASelectException(e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to initialize handler AuthSPHandler="+sAuthsp);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		
		// RH, 20180712, sn
		// Do subselect here
		// oAuthSPsection cannot be null here
		String	subselect_form = _configManager.getSimpleParam(oAuthSPsection, "subselectform", false);
		// we should push even more to the AuthSPHandler so it will return a preformatted html snippet
		if (subselect_form != null && subselect_form.length()>0  /* authsp subselect == true */ && !"true".equalsIgnoreCase((String)htLoginRequest.get("subselect")) ) {
			// RH, 20121119, sn
			// Handle application specific select form
			String sSelectFormName = SUBSELECTFORMPREFIX + subselect_form; // "select"
			String sSelectForm = _configManager.getHTMLForm(sSelectFormName, _sUserLanguage, _sUserCountry);

			sSelectForm = Utils.replaceString(sSelectForm, "[rid]", sRid);
			sSelectForm = Utils.replaceString(sSelectForm, "[a-select-server]", _sMyServerId);
			sSelectForm = Utils.replaceString(sSelectForm, "[user_id]", (String) htLoginRequest.get("user_id"));
			sSelectForm = Utils.replaceString(sSelectForm, "[aselect_url]", (String) htLoginRequest.get("my_url"));
			sSelectForm = Utils.replaceString(sSelectForm, "[request]", "login3");
			sSelectForm = Utils.replaceString(sSelectForm, "[authsp]", sAuthsp);
			String sLanguage = (String)_htSessionContext.get("language");
			String sCountry = (String)_htSessionContext.get("country");
			sSelectForm = Utils.replaceString(sSelectForm, "[language]", sLanguage);
			sSelectForm = Utils.replaceString(sSelectForm, "[country]", sCountry);

			sSelectForm = Utils.replaceString(sSelectForm, "[authsp_subselect]", (String) oProtocolHandler.inquireSubselect(null));
			// will be
			// oProtocolHandler.getSubselect() or something
			// Create the Cancel action:
			StringBuffer sb = new StringBuffer((String) htLoginRequest.get("my_url")).append("?request=error")
					.append("&result_code=").append(Errors.ERROR_ASELECT_SERVER_CANCEL).append("&a-select-server=")
					.append(_sMyServerId).append("&rid=").append(sRid);

			sSelectForm = Utils.replaceString(sSelectForm, "[cancel]", sb.toString());
			sSelectForm = _configManager.updateTemplate(sSelectForm, _htSessionContext, _servletRequest);
			

			// _systemLogger.log(Level.FINER, _sModule, sMethod, "Form select=["+sSelectForm+"]");
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			//_sessionManager.update(sRid, _htSessionContext); // Write session
			// pauseSensorData does this already: _sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: changed, was update()
			_systemLogger.log(Level.FINE, _sModule, sMethod, "present subselect");
			pwOut.println(sSelectForm);
			return null;
		}
		// RH, 20180712, en
		

		_systemLogger.log(Level.FINE, _sModule, sMethod, "to compute");
		// let the protocol handler for the authsp do its work
		HashMap htResponse = oProtocolHandler.computeAuthenticationRequest(sRid, _htSessionContext);
		return htResponse;
	}
	
	/**
	 * Private method to check whether the user's tgt is valid and satisfies the required level for the current
	 * application. TGT must be available in _htTGTContext.
	 * 
	 * @param sTgt
	 *            The ticket granting ticket.
	 * @param sUid
	 *            The user ID.
	 * @param sServerId
	 *            The server ID.
	 * @return -1 - credentials not ok, 0 - ok, 1 - ok, but no organization choice made yet.
	 */
	private int checkCredentials(String sTgt, String sUid, String sServerId)
	{
		String sMethod = "checkCredentials";
		Integer intRequiredLevel;

		// 20120712, Bauke, not needed, ASelectAuthenticationProfile has already read the TGT
		//_htTGTContext = _tgtManager.getTGT(sTgt);
//		if (_htTGTContext == null) {	// RH, 20191118, o	// should also check tgt validity
			if ( _htTGTContext == null  || Utils.hasValue((String)_htTGTContext.get("invalidatedby")) ) {	// RH, 20191118, n
			return -1;
		}
		if (!((String)_htTGTContext.get("uid")).equals(sUid)) {
			return -1;
		}
		if (!sServerId.equals(_sMyServerId)) {
			return -1;
		}
		
		_systemLogger.log(Level.INFO, _sModule, sMethod, "checkCred SSO");
		if (!isSpecialSSOGroups()) {	// RH, 20200526, n
		// check single sign-on groups
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "checking sso_groups");
		Vector vCurSSOGroups = (Vector)_htSessionContext.get("sso_groups");
		Vector vOldSSOGroups = (Vector)_htTGTContext.get("sso_groups");
		if (vCurSSOGroups != null && vOldSSOGroups != null) {
			if (!vCurSSOGroups.isEmpty() && !vOldSSOGroups.isEmpty()) {
				if (!_applicationManager.isValidSSOGroup(vCurSSOGroups, vOldSSOGroups))
					return -1;
			}
		}
		// RH, 20200526, sn
		} else {
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "found special sso_groups, skip checking isValidSSOGroup");
		}
		// RH, 20200526, en
		
		intRequiredLevel = (Integer)_htSessionContext.get("level");
		int iTGTLevel = getLevelFromTGT(_htTGTContext);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "CHECK LEVEL, requires: " + intRequiredLevel+" tgt: "+iTGTLevel);
		if (iTGTLevel < intRequiredLevel.intValue()) {
			return -1;  // level is not high enough
		}

		// No organization gathering specified: no org_id in TGT
		// Organization gathering specified but no organization found or choice not made yet: org_id="" in TGT
		// Choice made by the user: org_id has a value
		String sOrgId = (String)_htTGTContext.get("org_id");
		if (sOrgId != null && sOrgId.equals(""))
			return 1;  // No organization choice was made yet

		// OK!
		return 0;
	}

	/**
	 * Gets the authentication level from the TGT.
	 * 
	 * @param htTGTContext - the TGT context
	 * @return the level
	 */
	private int getLevelFromTGT(HashMap htTGTContext)
	{
		String sTGTLevel = null;
		String sAddedPatching = _configManager.getAddedPatching();

		// "sel_level" takes precedence over "authsp_level" unless configuration decides otherwise
		if (!sAddedPatching.contains("use_authsp_level"))
			sTGTLevel = (String) htTGTContext.get("sel_level");  // 20110828, Bauke: added
		if (!Utils.hasValue(sTGTLevel))  // old mechanism
			sTGTLevel = (String) htTGTContext.get("authsp_level");
		return (sTGTLevel == null)? 0: Integer.parseInt(sTGTLevel);
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
		String sTemp;

		String sUserId = (String) htServiceRequest.get("aselect_credentials_uid");
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sTgt = (String) htServiceRequest.get("aselect_credentials_tgt");

		String sUserInfoForm = _configManager.getHTMLForm("userinfo", _sUserLanguage, _sUserCountry);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[uid]", sUserId);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[a-select-server]", _sMyServerId);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[aselect_url]", sMyUrl);

		// 20120712, Bauke, not needed, ASelectAuthenticationProfile has already read the TGT
		// HashMap _htTGTContext = _tgtManager.getTGT(sTgt);
		try {
			long lExpTime = _tgtManager.getExpirationTime(sTgt);
			sTemp = new Date(lExpTime).toString();
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", sTemp);
		}
		catch (ASelectStorageException e) {
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_exp_time]", "[unknown]");
		}

		// In case the SAML20 logout procedure reaches this handler:
		String sEncTgt = CryptoEngine.getHandle().encryptTGT(Utils.hexStringToByteArray(sTgt));
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_blob]", sEncTgt);
		// End of SAML20 patch

		sTemp = (String) _htTGTContext.get("app_id");
		// RH, 20100805, Experimental insert of friendly_name
		String sFName = _applicationManager.getFriendlyName(sTemp);
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[friendly_name]", sFName);  // backward compatibility
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[requestor_friendly_name]", sFName);  // 20130822, Bauke: added
		
		if (sTemp == null)
			sTemp = "[unknown]";
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[app_id]", sTemp);
		sUserInfoForm = _configManager.updateTemplate(sUserInfoForm, null/*no session*/, _servletRequest);

		// RH, 20181002, sn
		sTemp = (String) _htTGTContext.get("social_login");
		if (sTemp == null)
			sTemp = "[unknown]";
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[social_login]", sTemp);
		// RH, 20181002, en
		
		sTemp = (String) _htTGTContext.get("authsp");
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

		sTemp = (String) _htTGTContext.get("authsp_level");
		sUserInfoForm = Utils.replaceString(sUserInfoForm, "[tgt_level]", sTemp);

		sTemp = (String) _htTGTContext.get("proxy_organization");
		if (sTemp == null)
			sTemp = (String) _htTGTContext.get("organization");

		String sRemoteAsUrl = null;
		if (!sTemp.equals(_sMyOrg)) {
			// 20090113, Bauke: This is only mandatory when we reached "organization" using cross!
			try {
				CrossASelectManager oCrossASelectManager = CrossASelectManager.getHandle();
				String sResourcegroup = oCrossASelectManager.getRemoteParam(sTemp, "resourcegroup");
				if (sResourcegroup != null) {
					SAMResource oSAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourcegroup);
					Object oRemoteServer = oSAMResource.getAttributes();
					try {
						sRemoteAsUrl = _configManager.getParam(oRemoteServer, "url");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.INFO, _sModule, sMethod, "Remote url not available");
					}
				}
				else
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Remote resourcegroup not available");
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Failed to read SAM.");
			}
			catch (Exception ae) { // Bauke: added
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Not a 'cross' organization: " + sTemp);
			}
		}
		if (sRemoteAsUrl == null) {
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp);
		}
		else {
			String sTemp3 = "<A HREF=\"" + sRemoteAsUrl + "\">" + sTemp + "</A>";
			sUserInfoForm = Utils.replaceString(sUserInfoForm, "[org]", sTemp3);
		}
		Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
		if (_htSessionContext != null) {
			_htSessionContext.put("user_state", "state_userinfo");
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: added, was update()
		}
		pwOut.println(sUserInfoForm);
	}

	// Bauke - Verkeersplein functionality added
	//
	/**
	 * Handle login25.
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the output PrintWriter
	 * @throws ASelectException
	 */
	private void handleLogin25(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleLogin25";
		String sRid = null;
		String sAuthsp = null;
		String sUid = null, sUserId = null, sForcedUid = null;

		try {
			sAuthsp = (String) htServiceRequest.get("authsp");
			sRid = (String) htServiceRequest.get("rid");
			sUid = (String) _htSessionContext.get("uid");
			sUserId = (String) _htSessionContext.get("user_id");
			sForcedUid = (String) _htSessionContext.get("forced_uid");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "Login25 uid=" + Auxiliary.obfuscate(sUid) + " user_id=" + Auxiliary.obfuscate(sUserId)
					+ " forced_uid=" + Auxiliary.obfuscate(sForcedUid) + " authsp=" + sAuthsp);
			if (sAuthsp == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request, missing parmeter 'authsp'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (sUid != null)
				_htSessionContext.remove("uid"); // forces the user to enter a user id
			if (sUserId != null)
				_htSessionContext.remove("user_id");
			if (sForcedUid != null)
				_htSessionContext.remove("forced_uid");
			_htSessionContext.put("fixed_authsp", sAuthsp); // must be present
			if (sForcedUid != null)
				_htSessionContext.put("fixed_uid", sForcedUid);

			_htSessionContext.put("user_state", "state_login25");  // 20131019, Bauke: remove "state_select"
			_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);
			
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "htSessionContext=" + Auxiliary.obfuscate(_htSessionContext));
			handleLogin1(htServiceRequest, servletResponse, pwOut);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// Example call: 
	//   https://aselect.anoigo.nl/aselectserver/server?request=login_token&uid=bauke&password=xxx&
	//		a-select-server=aselectserver1&app_id=app1&authsp=Ldap&shared_secret=1234		
	/**
	 * Login and return a Saml token as a result
	 * 
	 * @param htServiceRequest
	 *            the service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the output PrintWriter
	 * @throws ASelectException
	 */
	private void handleLoginToken(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		final int SPLIT_HEADER = 3500;
		String sMethod = "handleLoginToken";
		AuthSPHandlerManager _authspHandlerManager = AuthSPHandlerManager.getHandle();
		String sStatus = "401 Unauthorized";

		String sResponse = "";

		String sAppId = (String)htServiceRequest.get("app_id");
		String sAuthSp = (String)htServiceRequest.get("authsp");
		String sUid = (String)htServiceRequest.get("uid");
		String sPassword = (String)htServiceRequest.get("password");
		String sSharedSecret = (String)htServiceRequest.get("shared_secret");

		String sOutputFormat = (String)htServiceRequest.get("output_format");

		String sSignature = (String)htServiceRequest.get("signature");
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "reveived sSignature:" + sSignature);
		
		boolean sSigningRequired = _applicationManager.isSigningRequired(sAppId);
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "sSigningRequired:" + sSigningRequired);

		String sApplSharedSecret = _applicationManager.getApplication(sAppId).getSharedSecret();
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "sApplSharedSecret:" + sApplSharedSecret);

//		if ("".equals(sAppId) || "".equals(sAuthSp) || "".equals(sUid) ||
		if (sAppId == null || "".equals(sAppId) || sAuthSp == null || "".equals(sAuthSp) || sUid == null || "".equals(sUid) ||
//					"".equals(sPassword)|| "".equals(sSharedSecret)) {
//			"".equals(sPassword)|| ( !sSigningRequired && "".equals(sSharedSecret) )) {
				sPassword == null || "".equals(sPassword) || 
				( sApplSharedSecret != null  && ( sSharedSecret == null ||  "".equals(sSharedSecret) )  ) ||
				( sSigningRequired && ( sSignature == null ||  "".equals(sSignature) )  )) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Mandatory parameter is missing");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// Perform an authenticate request
		_systemLogger.log(Level.INFO, MODULE, sMethod, "AUTHN { ");
		HashMap<String, String> hmRequest = new HashMap<String, String>();
		hmRequest.put("request", "authenticate");
		hmRequest.put("app_id", sAppId);
		hmRequest.put("a-select-server", _sMyServerId);
		hmRequest.put("app_url", "login_token");
		hmRequest.put("shared_secret", sSharedSecret);
		
		if (sSigningRequired) {	// not defensive because of backward compatibility
			hmRequest.put("check-signature", "true");
			hmRequest.put("signature", sSignature);
		}
		else { 
			hmRequest.put("check-signature", "false");  // this is an internal call, so don't
		}
	
		// No "usi" available in this entry
		hmRequest.put("usi", Tools.generateUniqueSensorId());  // 20120111, Bauke added
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "hmRequest=" + Auxiliary.obfuscate(hmRequest));
		
		// Exception for bad shared_secret:
		HashMap<String, Object> hmResponse = handleAuthenticateAndCreateSession(hmRequest, null);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "hmResponse=" + Auxiliary.obfuscate(hmResponse));

		String sResultCode = (String) hmResponse.get("result_code");
		if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {  // never happens (either success or exception is raised
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "} AUTHN unsuccessful, result_code=" + sResultCode);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "} AUTHN htResponse=" + Auxiliary.obfuscate(hmResponse));

		// Retrieve the session just created
		String sRid = (String)hmResponse.get("rid");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Supplied rid=" + sRid);

		// The session was created by handleAuthenticateAndCreateSession()
		_htSessionContext = (HashMap)hmResponse.get("session");  // 20120404, Bauke: was getSessionContext(sRid)
		if (_htSessionContext == null) {
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
		}
		_htSessionContext.put("direct_authsp", sAuthSp);  // for handleDirectLogin2
		_htSessionContext.put("organization", _sMyOrg);
		_htSessionContext.put("client_ip", "login_token");
		
		_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
		
		// Check login user and password
		HashMap<String, String> hmDirectRequest = new HashMap<String, String>();
		hmDirectRequest.put("request", "direct_login2");
		hmDirectRequest.put("rid", sRid);
		hmDirectRequest.put("user_id", sUid);
		hmDirectRequest.put("password", sPassword);
		
		// Only perform user/password authentication (will update the session):
		IAuthSPDirectLoginProtocolHandler oProtocolHandler = _authspHandlerManager.getAuthSPDirectLoginProtocolHandler(sAuthSp);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "HttpSR="+servletResponse);
		boolean bSuccess = oProtocolHandler.handleDirectLoginRequest(hmDirectRequest, null/*serlvet request*/, null/*servlet response*/,
					_htSessionContext, null/*additional*/, null /*output writer*/, _sMyServerId, "en", "nl");
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Success="+bSuccess+" hm="+Auxiliary.obfuscate(hmDirectRequest));
		
		// Pass result in the header, but only if successful
		if (bSuccess) {
			sStatus = "200 OK";
			// Reload session for results
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}

			// Gather attributes
			HashMap hmContext = new HashMap();
			hmContext.put("uid", sUid);
			hmContext.put("app_id", sAppId);
			hmContext.put("authsp", sAuthSp);
			hmContext.put("organization", _sMyOrg);
			Utils.copyHashmapValue("authsp_type", hmContext, _htSessionContext);
			Utils.copyHashmapValue("authsp_level", hmContext, _htSessionContext);
			
			AttributeGatherer oAttributeGatherer = AttributeGatherer.getHandle();
			HashMap<String, Object> htAttribs = oAttributeGatherer.gatherAttributes(hmContext);
			
			// Return Saml 20 token
			String subject = sRid.toString(); // transientID, elsewhere the TGT value is used
			
			String sWantSigning = "true";  // always signing on
			Assertion assertion = HandlerTools.createAttributeStatementAssertion(htAttribs, _sServerUrl, subject, "true".equalsIgnoreCase(sWantSigning));
			String sResult = XMLHelper.nodeToString(assertion.getDOM());
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sResult="+Auxiliary.obfuscate(sResult, Auxiliary.REGEX_PATTERNS));

			if ("saml".equalsIgnoreCase(sOutputFormat)) {
				sResponse = sResult;
			}
			else if ("samlhtml".equalsIgnoreCase(sOutputFormat)) {
				sResponse = StringEscapeUtils.escapeHtml(sResult);
			}
			else if ("cgi".equalsIgnoreCase(sOutputFormat)) {
				sResponse =  org.aselect.server.utils.Utils.serializeAttributes(htAttribs);
				BASE64Decoder b64dec = new BASE64Decoder();
				sResponse = new String(b64dec.decodeBuffer(sResponse));
			}
			else if ("cgibase64".equalsIgnoreCase(sOutputFormat)) {
				sResponse =  org.aselect.server.utils.Utils.serializeAttributes(htAttribs);
			}
			else {
				// backward compatibility
				sResponse = "<html><head><title>"+sStatus+"</title></head><body><h1>"+sStatus+"</h1></body></html>";
				try {
					BASE64Encoder b64enc = new BASE64Encoder();
					sResult = b64enc.encode(sResult.getBytes("UTF-8"));
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				
				// Set headers, split in chunks
				for (int i=1; ; i++) {
					int len = sResult.length();
					int hdrLen = (len <= SPLIT_HEADER)? len: SPLIT_HEADER;
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "i="+i+" len="+len+" hdrLen="+hdrLen);
					servletResponse.setHeader("X-saml-attribute-token"+Integer.toString(i), sResult.substring(0, hdrLen));
					// pwOut.flush() at this point will only set the first header 
					if (len <= SPLIT_HEADER)
						break;
					sResult = sResult.substring(SPLIT_HEADER);
				}
			}
			servletResponse.setStatus(HttpServletResponse.SC_OK);
		}
		else {
//			servletResponse.setStatus(401);
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Sending UNAUTHORIZED");
			servletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		}
				
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();
		authenticationLogger.log(new Object[] {
				"login_token", Auxiliary.obfuscate(sUid), (String) htServiceRequest.get("client_ip"), _sMyOrg, sAppId, bSuccess ? "granted" : "denied"
			});
		
		pwOut.flush();  // otherwise: java.lang.ArrayIndexOutOfBoundsException: 8192 when output gets large
//		pwOut.append("<html><head><title>"+sStatus+"</title></head><body><h1>"+sStatus+"</h1></body></html>");
		_systemLogger.log(Level.FINE, MODULE, sMethod, "Sending response="+sResponse);
		pwOut.append(sResponse);
		_systemLogger.log(Level.FINE, MODULE, sMethod, "done");
	}
}
