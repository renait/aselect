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
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler.wsfed;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.utils.Utils;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.crypto.Auxiliary;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSubject;

//
// Account Partner = IdP
//
public class AccountSTS extends ProtoRequestHandler
{
	public final static String MODULE = "AccountSTS";
	private final static String RETURN_SUFFIX = "_return";
	private final static String SESSION_ID_PREFIX = ""; // 20081125 "wsfed_";
	
	private static final String WCTX_DEFAULT_PATTERN = "[\\w-]*";	// wsfed standard wctx content complies to letters, digits and minus

	private IClientCommunicator _oClientCommunicator;
	private TGTManager _oTGTManager;

	private String _sTemplate = null;
	private String _sPostTemplate = null;
	private String _sMyAppId;
	private String _sPassTransientId;
	private String _sIstsUrl;
	private String _sProviderId;
	private String _sNameIdFormat;
	// Removed 20080423: private String _sDefaultWreply;
	private String _sUserDomain;
	private String _sCookieDomain;
	protected HashMap _htSecLevels;
	protected HashMap _htSP_LoginReturn;
	protected HashMap _htSP_LogoutReturn;

	protected HashMap _htWauthAppidMapping;	// RH, 20141014, n

	protected HashMap<String, Pattern> _htSP_wctxregex;	// RH, 20130916, n
	protected HashMap<String, String>	_htSP_SignAlgorithm;	// RH, 20130924, alg for signing the returned token
	
	private Integer _iMinLevelProcess = null;
	private Integer _iMinLevelProcessReturn = null;
	private boolean _doCleanup = false;

	// protected HashMap _htSP_ErrorUrl;

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#getSessionIdPrefix()
	 */
	protected String getSessionIdPrefix()
	{
		return SESSION_ID_PREFIX;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#useConfigToCreateSamlBuilder()
	 */
	protected boolean useConfigToCreateSamlBuilder()
	{
		return true;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		_oTGTManager = TGTManager.getHandle();

		try {
			super.init(oServletConfig, oConfig);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "specific init processing");

			_oClientCommunicator = initClientCommunicator(oConfig);
			_sUserDomain = ASelectConfigManager.getParamFromSection(null, "aselect", "user_domain", false);
			if (_sUserDomain == null)
				_sUserDomain = "digid.nl";
			_sMyAppId = ASelectConfigManager.getParamFromSection(oConfig, "application", "id", true);
			_sPassTransientId = ASelectConfigManager.getSimpleParam(oConfig, "pass_transient_id", false);
			_sIstsUrl = ASelectConfigManager.getSimpleParam(oConfig, "ists_url", true);
			_sProviderId = ASelectConfigManager.getSimpleParam(oConfig, "provider_id", true);
			_sNameIdFormat = ASelectConfigManager.getSimpleParam(oConfig, "nameid_format", true);
			// _sDefaultWreply = Utils.getSimpleParam(oConfig, "default_wreply", true);
			_sTemplate = readTemplateFromConfig(oConfig, "template");

			_sCookieDomain = _configManager.getCookieDomain();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Cookie domain is: " + _sCookieDomain);

			_vIdPUrls = new Vector(); // Vector will contain 'url' key values
			_htIdPs = new HashMap(); // contains url->id
			getTableFromConfig(oConfig, _vIdPUrls, _htIdPs, "identity_providers", "idp", "url",/*->*/"id",
					true/* mandatory */, true/* unique values */);

			_htSecLevels = new HashMap(); // contains level -> urn
			getTableFromConfig(oConfig, null, _htSecLevels, "authentication_method", "security", "level",/*->*/"uri",
					false/* mandatory */, false/* unique values */);

			// We just parse the config multiple times, since it's only done once
			_htSP_LoginReturn = new HashMap();
			getTableFromConfig(oConfig, null, _htSP_LoginReturn, "service_providers", "sp", "uri",/*->*/
			"login_return_url", false/* mandatory */, false/* unique values */);

			_htSP_SignAlgorithm = new HashMap<String, String>();// RH, 20130924, n

			// RH, 20130916, sn
			// We just parse the config multiple times, since it's only done once
			// Restrict wctx parameter input
			_htSP_wctxregex = new HashMap<String, Pattern>();
//			getTableFromConfig(oConfig, null, _htSP_wctxregex, "service_providers", "sp", "uri",/*->*/
//			"wctx_regex", false/* mandatory */, false/* unique values */);
			Iterator itr = _htSP_LoginReturn.keySet().iterator();
			while (itr.hasNext()) {
				String sKey = (String)itr.next();

				Object oProviders_section = ASelectConfigManager.getSimpleSection(oConfig, "service_providers", true);
				Object oSP_section = _configManager.getSection(oProviders_section, "sp", "uri=" + sKey);
				String sRegex = (String) ASelectConfigManager.getSimpleParam(oSP_section, "wctx_regex", false);

//				String sRegex = (String)_htSP_wctxregex.get(sKey);
				if (sRegex == null || "".equals(sRegex))	{
					sRegex  = WCTX_DEFAULT_PATTERN;	
				}
				_systemLogger.log(Level.FINER, MODULE, sMethod, "regex for: " + sKey + " = " + sRegex);
				Pattern _pRexex;
				try {
					_pRexex = Pattern.compile(sRegex);
					_htSP_wctxregex.put(sKey, _pRexex);
				}
				catch (Exception e) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Not a valid pattern: " + sRegex, e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				// RH, 20130924, sn
				String sAlg = (String) ASelectConfigManager.getSimpleParam(oSP_section, "signature_algorithm", false);
				if ( sAlg != null ) {
					_htSP_SignAlgorithm.put(sKey, sAlg);
				}
				// RH, 20130924, en				
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "regexes loaded: " + _htSP_wctxregex);
			// RH, 20130916, en			
			
			
			_htSP_LogoutReturn = new HashMap();
			getTableFromConfig(oConfig, null, _htSP_LogoutReturn, "service_providers", "sp", "uri",/*->*/
			"logout_return_url", false/* mandatory */, false/* unique values */);

			// RH, 20141014, sn
			//	wauth to app_id mapping
			_htWauthAppidMapping = new HashMap();
			getTableFromConfig(oConfig, null, _htWauthAppidMapping, "application_mapping", "app", "wauth",/*->*/
			"app_id", false/* mandatory */, false/* unique values */);
			// RH, 20141014, sn
			
			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");

			String _sMinLevelProcess = ASelectConfigManager.getSimpleParam(oConfig, "min_level_process", false);
			if (_sMinLevelProcess != null) {
				_iMinLevelProcess = Integer.valueOf(_sMinLevelProcess);
			}
			String _sMinLevelProcessReturn = ASelectConfigManager.getSimpleParam(oConfig, "min_level_processreturn", false);
			if (_sMinLevelProcessReturn != null) {
				_iMinLevelProcessReturn = Integer.valueOf(_sMinLevelProcessReturn);
			}
			// RH, 20181127, sn
			// This is for pilot testing, we should have a cleanup file per identity provider
			String _sDoCleanup = ASelectConfigManager.getSimpleParam(oConfig, "docleanup", false);
			if (_sDoCleanup != null) {
				_doCleanup = Boolean.parseBoolean(_sDoCleanup);
			}
			// RH, 20181127, en
			
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	// https://idp.symdemo.com:8880/IDP-F?wa=wsignin1.0
	// wreply=https://sp.symspdemo.com:8780/SP-P
	// wct=2007-06-07T20:40:22Z
	// wtrealm=https://sp.symspdemo.com:8780/sp.xml
	//
	// Requestor IP/STS Challenge (Step 5)
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "process";
		String sPathInfo = servletRequest.getPathInfo();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Path=" + sPathInfo);
		HandlerTools.logCookies(servletRequest, _systemLogger);

		String sPwa = servletRequest.getParameter("wa"); // action	// RH, 20181127, n

		if (sPathInfo.endsWith(RETURN_SUFFIX)) {
			// This is for pilot testing, we should have a cleanup file per identity provider
			if (_doCleanup && sPwa != null && sPwa.equals("wsignout1.0")) {	// This is a return from wsfed wsignoutcleanup html 
				return processSignout(servletRequest, servletResponse);
			}
			return processReturn(servletRequest, servletResponse);
		}

//		String sPwa = servletRequest.getParameter("wa"); // action	// RH, 20181127, o
		String sPwreply = servletRequest.getParameter("wreply"); // response redirect URL, not given by ADFS!
		String sPwctx = servletRequest.getParameter("wctx"); // context value, pass unchanged
		// String sPwct = request.getParameter("wct"); // current time
		String sPwtrealm = servletRequest.getParameter("wtrealm"); // requesting realm (resource accessed)
		String sPwhr = servletRequest.getParameter("whr"); // requestor's home realm (account partner's client realm)
		
		String sPwauth = servletRequest.getParameter("wauth"); // authentication method, will be (mis)used to select app_id which then determines authentication method
		
		

		if (sPwa != null && sPwa.equals("wsignout1.0"))	{
			if (_doCleanup) {
				// Show the wsfed_cleaunup page to the user (should contain "autoreturn" to this handler _return with a wa=wsignout1.0 
				return showCleanupForm(servletRequest, servletResponse, sPwreply);
			}
			return processSignout(servletRequest, servletResponse);
		}

		if (sPwa == null || !sPwa.equals("wsignin1.0")) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown or missing \"wa\" in call");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		// If we don't know the realm, kick them out
		if (sPwtrealm == null || !_htSP_LoginReturn.containsKey(sPwtrealm)) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown or missing \"wtrealm\" in call");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		
		// If wctx doesn't match the required pattern, kick them out
//		if ( !((Pattern)_htSP_wctxregex.get(sPwtrealm)).matcher(sPwctx).matches()) {	// RH, 20141031, o
		if ( sPwctx != null &&  !((Pattern)_htSP_wctxregex.get(sPwtrealm)).matcher(sPwctx).matches()) {	// RH, 20141031, n
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "wctx doesn't match pattern for realm: " + sPwtrealm);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}

		String sReply = (String) _htSP_LoginReturn.get(sPwtrealm);
		// ADFS does not pass a 'wreply' parameter!!
		if (sPwreply == null) {
			sPwreply = sReply; // _sDefaultWreply; // "https://adfsresource.treyresearch.net/adfs/ls";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'wreply' parameter in request, using: " + sPwreply);
//		}	// RH, 20171212, o
			// RH, 20171212, sn
		} else {
			if ( !_htSP_LoginReturn.containsValue(sPwreply) ) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "'wreply' parameter not allowed: " + sPwreply);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		// RH, 20171212, en

		// RH, 20180529, sn
		// If we don't know the wauth, kick them out
		if (sPwauth != null && !_htWauthAppidMapping.containsKey(sPwauth)) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unknown \"wauth\" in call");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		// RH, 20180529, en
		
		
		_systemLogger.log(Level.FINER, MODULE, sMethod, "wsfed_ap PATH=" + servletRequest.getPathInfo() + " "
				+ servletRequest.getMethod() + " " + servletRequest.getQueryString());
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "wsfed_ap PATH=" + servletRequest.getPathInfo() + " "
//				+ servletRequest.getMethod() + " " + servletRequest.getQueryString());	// RH, 20171212, o

		HashMap htSessionData = new HashMap();
		if (sPwtrealm != null)
			htSessionData.put("wtrealm", sPwtrealm);
		if (sPwreply != null)
			htSessionData.put("wreply", sPwreply);
		if (sPwctx != null)
			htSessionData.put("wctx", sPwctx);
		
		// Look for a possible TGT
		String sTgt = getCredentialsFromCookie(servletRequest);
		if (sTgt != null) {
			HashMap htTGTContext = getContextFromTgt(sTgt, true); // Check expiration
//			if (htTGTContext != null) {	// RH, 20150915, o
			if ( htTGTContext != null && 
					(_iMinLevelProcess == null || 
						( htTGTContext.get("authsp_level") != null 
//					&& _iMinLevelProcess.compareTo(Integer.valueOf((String)htTGTContext.get("authsp_level"))) <= 0)) ) {	// RH, 20150915, n	// RH, 20171208, o
							&& _iMinLevelProcess.compareTo(Integer.valueOf((String)htTGTContext.get("authsp_level"))) <= 0)) 
//						&& _sMyAppId.equals((String)htTGTContext.get("app_id"))	// RH, 20171208, n	// temporary fix	// RH, 20180529, o
						&& ( sPwauth == null && _sMyAppId.equals((String)htTGTContext.get("app_id")) 
								|| sPwauth != null && _htWauthAppidMapping.get(sPwauth) != null && ((String)_htWauthAppidMapping.get(sPwauth)).equals(htTGTContext.get("app_id")))	// RH, 20180529, n
				) {	// RH, 20171208, n
				// Valid TGT context found, Update TGT timestamp
				_oTGTManager.updateTGT(sTgt, htTGTContext);
				// Return to the caller
				String sUid = (String) htTGTContext.get("uid");
				HashMap htAllAttributes = getAttributesFromTgtAndGatherer(htTGTContext);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Posting requestortoken");
				// RH, 20180523, sn
				if (sPwauth != null && _htWauthAppidMapping.get(sPwauth) != null && ((String)_htWauthAppidMapping.get(sPwauth)).equals(htTGTContext.get("app_id"))) {
					htSessionData.put("wauth", sPwauth);
					htSessionData.put("app_id", htTGTContext.get("app_id"));	// RH, 20190704, n
				}
				// RH, 20180523, en
				// We've done some elementary checking on the htSessionData. Maybe narrow this down some more, // RH, 20180523, n
				return postRequestorToken(servletRequest, servletResponse, sUid, htSessionData, htAllAttributes);
			} else {
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No tgt context found or authsp level too low, doing authenticate");
				// RH, 20171212, sn
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No tgt context found or authsp level too low or app_id not valid, doing authenticate");
				if (htTGTContext != null) {
					htSessionData.put("wauth", sPwauth);	// RH, 20180529, n
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Updating tgt with: " + htSessionData );
					htTGTContext.putAll(htSessionData);
					_oTGTManager.updateTGT(sTgt, htTGTContext);
				}
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Updated tgt: " + Auxiliary.obfuscate(htTGTContext) );
				// RH, 20171212, en
			}
		}
		String sASelectURL = _sServerUrl;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Start Authenticate");

		// RH, 20141014, so
//		HashMap<String, Object> htResponse = performAuthenticateRequest(sASelectURL, sPathInfo, RETURN_SUFFIX,
//					_sMyAppId, false/*don't check signature*/, _oClientCommunicator);
		// RH, 20141014, eo

		// RH, 20141014, sn
		String sMappedAppId = _sMyAppId;	// _sMyAppId becomes default
		if (_htWauthAppidMapping.size() > 0 && sPwauth != null && !"".equals(sPwauth) ) {	// do we have at least one mapping defined and is there a mapping query parm
			String s = (String)_htWauthAppidMapping.get(sPwauth);
			if (s != null ) {	// we found a mapping
				sMappedAppId = s;
			}
		}
		HashMap<String, Object> htResponse = performAuthenticateRequest(sASelectURL, sPathInfo, RETURN_SUFFIX,
				sMappedAppId, false/*don't check signature*/, _oClientCommunicator);
		// RH, 20141014, en

		// RH, 20180523, sn
		if (sPwauth != null && _htWauthAppidMapping.get(sPwauth) != null && ((String)_htWauthAppidMapping.get(sPwauth)).equals(sMappedAppId)) {
			htSessionData.put("wauth", sPwauth);
		}
		
		String sRid = (String) htResponse.get("rid");  // rid for the newly generated session
		_htSessionContext = (HashMap)htResponse.get("session");
		
		// We need this stuff when we come back. Store as an additional session record
		_htSessionContext = storeSessionDataWithRid(servletResponse, htSessionData, _htSessionContext, SESSION_ID_PREFIX, sRid);

		// Let the user get himself identified
		String sActionUrl = sASelectURL + _sIstsUrl;
		String sReplyTo = sASelectURL + sPathInfo + RETURN_SUFFIX;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Form ActionUrl=" + sActionUrl);
		handleShowForm(_sTemplate, sPwhr, sActionUrl, sPwctx, sReplyTo, Tools.samlCurrentTime(),
						sASelectURL, sRid, _sASelectServerID, servletRequest, servletResponse);

		return new RequestState(null);
	}

	// Expect:
	// GET aselect_credentials=b...x&rid=770DE0D7302C36CA&a-select-server=aselectserver1
	//
	// Receive Resource Token - Step 9
	// OR: we can get here from the A-Select server directly (credentials are set in that case)
	// Return requestor token to the caller, must be POSTed
	//
	/**
	 * Process return.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState processReturn(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "processReturn";
		// Redirection from RP?
		String sPwa = request.getParameter("wa"); // action
		String sPwresult = request.getParameter("wresult"); // resource token

		// Redirection from A-Select server?
		String sUrlRid = request.getParameter("rid");
		// String sUrlServer = (String) request.getParameter("a-select-server");
		String sUrlTgt = (String) request.getParameter("aselect_credentials");

//		_systemLogger.log(Level.INFO, MODULE, sMethod, "sPwa=" + sPwa + " wresult=" + sPwresult + " sUrlRid=" + sUrlRid);	// RH, 20180523, o
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sPwa=" + sPwa + " wresult=" + Auxiliary.obfuscate(sPwresult) + " sUrlRid=" + sUrlRid);// RH, 20180523, n
		String sUid = null;
		String sTgt = null;
		HashMap htCredentials = null;
		HashMap htAttributes = null;
		try {
			// RH, 20141027, so, only allow return from A-Select server
			/*
			if (sPwa != null && !sPwa.equals("")) {
				// From Resource Partner, get attributes from resource token
				htAttributes = extractUidAndAttributes(sPwresult);
				sUid = (String) htAttributes.get("uid");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "From Resource Partner, uid=" + sUid);
				// RM_42_01
			}
			else {
			*/
			// RH, 20141027, eo, only allow return from A-Select server
			// From A-Select server
			sUrlTgt = decryptCredentials(sUrlTgt);	// throws exception if decryption fails
			_systemLogger.log(Level.INFO, MODULE, sMethod, "From A-Select TGT="+Tools.clipString(sUrlTgt, 40, true));

			// Get credentials and attributes using Cookie
			htCredentials = getASelectCredentials(request);
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "getAselectCredentials: " + htCredentials);	// RH, 20180503, o
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "getAselectCredentials: " + Auxiliary.obfuscate(htCredentials));	// RH, 20180503, n
			
			// RH, 20150915, sn
			if ( htCredentials == null || htCredentials.get("authsp_level") == null  ||
				( _iMinLevelProcessReturn != null 
				&& _iMinLevelProcessReturn.compareTo(Integer.valueOf((String)htCredentials.get("authsp_level"))) > 0 ) ) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No tgt context found or authsp level too low");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			//	RH, 20150915, en 
				
			sUid = (String) htCredentials.get("uid");
			if (sUid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No parameter 'uid' found");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			String sAttributes = (String) htCredentials.get("attributes");
			if (sAttributes != null)
				htAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sAttributes);

			String sLevel = (String) htCredentials.get("authsp_level");
			String sTryLevel = (String) htAttributes.get("authsp_level");
			if (sTryLevel == null && sLevel != null) {
				htAttributes.put("auhsp_level", sLevel);
			}
				sTgt = (String) htCredentials.get("tgt");
				// RH, 20141027, so, only allow return from A-Select server
//			}
		// RH, 20141027, eo, only allow return from A-Select server
			String sTryUid = (String) htAttributes.get("uid");
			if (sTryUid == null)
				htAttributes.put("uid", sUid);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "htAttributes=" + htAttributes + " pass_transient_id="
					+ _sPassTransientId);

			// RH, 20141027, so, only allow return from A-Select server
			/*
			if (htCredentials == null) {
				// Create Token and POST it to the caller
				// No credentials were made yet, Issue a TGT
				// RH, 20141014, sn
				// Wauth: we need app_id from session so first do a retrieveSessionDataFromRid(request, SESSION_ID_PREFIX) and then createContextAndIssueTGT
				HashMap htSessionData = retrieveSessionDataFromRid(request, SESSION_ID_PREFIX);
				if (htSessionData == null)
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
				String sAppId = (String)htSessionData.get("app_id");
				if (sAppId == null || "".equals(sAppId)) sAppId = _sMyAppId; 	// defaults
				sTgt = createContextAndIssueTGT(response, null, null, _sASelectServerID, _sASelectOrganization,
						sAppId, sTgt, htAttributes);
				// RH, 20141014, en

//				sTgt = createContextAndIssueTGT(response, null, null, _sASelectServerID, _sASelectOrganization,
//						_sMyAppId, sTgt, htAttributes);// RH, 20141014, o

				// Create Token and POST it to the caller
				// RH, 20141014, so
//				HashMap htSessionData = retrieveSessionDataFromRid(request, SESSION_ID_PREFIX);
//				if (htSessionData == null)
//					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
				// RH, 20141014, eo
				if ("true".equals(_sPassTransientId))
					htAttributes.put("transient_id", sTgt);
				return postRequestorToken(request, response, sUid, htSessionData, htAttributes);
			}
			else {
			*/
						// RH, 20141027, eo, only allow return from A-Select server
			if ("true".equals(_sPassTransientId))
				htAttributes.put("transient_id", sTgt);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Posting requestortoken");//	RH, 20150915, n
			return postRequestorToken(request, response, sUid, htCredentials, htAttributes);
				// RH, 20141027, so, only allow return from A-Select server
//			}
			// RH, 20141027, eo, only allow return from A-Select server

		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Post requestor token.
	 * 
	 * @param servletRequest
	 *            the request
	 * @param servletResponse
	 *            the response
	 * @param sUid
	 *            the s uid
	 * @param htSessionData
	 *            the ht session data
	 * @param htAttributes
	 *            the ht attributes
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	private RequestState postRequestorToken(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String sUid,
			HashMap htSessionData, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "postRequestorToken";

		// Retrieve data stored in Step 5
		String sAudience = (String) htSessionData.get("wtrealm");
		String sPwreply = (String) htSessionData.get("wreply");
		String sPwctx = (String) htSessionData.get("wctx"); // context, must be returned unchanged
		_systemLogger.log(Level.INFO, MODULE, sMethod, "wtrealm=" + sAudience + " wreply=" + sPwreply + " wctx="
				+ sPwctx);
		// sPwctx = sPwctx.replaceAll("\\.*", "");
		String sPwauth = (String) htSessionData.get("wauth"); // RH, 20180503

		// RH, 20171212, sn
		/*
		if (sAudience == null || sPwreply == null || sPwctx == null) {
			HashMap htStoredSessionData = retrieveSessionDataFromRid(servletRequest, SESSION_ID_PREFIX);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved htStoredSessionData=" + htStoredSessionData );
			if (htStoredSessionData != null) {
				if (sAudience == null) {
					sAudience = (String) htStoredSessionData.get("wtrealm");
				}
				if (sPwreply == null) {
					sPwreply = (String) htStoredSessionData.get("wreply");
				}
				if (sPwctx == null) {
					sPwctx = (String) htStoredSessionData.get("wctx"); // context, must be returned unchanged
				}
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "final, wtrealm=" + sAudience + " wreply=" + sPwreply + " wctx="
					+ sPwctx);
		}
		*/
		// RH, 20171212, en
		
		try {
			String sAuthMeth = SAMLSubject.CONF_BEARER; // default value

			String sLevel = sLevel = (String) htAttributes.get("sel_level");
			if (sLevel == null) sLevel = (String) htAttributes.get("authsp_level");
			if (sLevel == null) sLevel = (String) htAttributes.get("betrouwbaarheidsniveau");
			if (sLevel != null) {
				String urn = (String) _htSecLevels.get(sLevel);
				if (urn != null)
					sAuthMeth = urn; // default when sPwauth not found, backward compatibility
			}
			
//			if (sPwauth != null)  sAuthMeth = sPwauth;	// sPwauth should have been checked		// RH, 20180523, n	// RH, 20180529, o
			if (sPwauth != null 
					&& _htWauthAppidMapping.get(sPwauth) != null && ((String)_htWauthAppidMapping.get(sPwauth)).equals(htSessionData.get("app_id")))
			{
				sAuthMeth = sPwauth;	// sPwauth, we must check again	// RH, 20180529
			}
			
//			String sRequestorToken = createRequestorToken(request, _sProviderId, sUid, _sUserDomain, _sNameIdFormat,
//					sAudience, htAttributes, sSubjConf);	// RH, 20130924, o
			String sRequestorToken = createRequestorToken(servletRequest, _sProviderId, sUid, _sUserDomain, _sNameIdFormat,
					sAudience, htAttributes, sAuthMeth, _htSP_SignAlgorithm.get(sAudience));	// RH, 20130924, n
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Token OUT: RequestorToken wresult=" + Auxiliary.obfuscate(sRequestorToken,  Auxiliary.REGEX_PATTERNS));

			// Return Requestor Token - Step 6
			// POST to Requestor's STS (IdP): take wreply and wctx from Step 5
			String sInputs = buildHtmlInput("wa", "wsignin1.0");
			sInputs += buildHtmlInput("wctx", sPwctx);
			// sInputs += buildHtmlInput("whr", sProviderId); // ADFS?
			sInputs += buildHtmlInput("wresult", Tools.htmlEncode(sRequestorToken));

			// Kill the cookie so it can not be used again (to prevent loops)
			HandlerTools.delCookieValue(servletResponse, SESSION_ID_PREFIX + "rid", _sCookieDomain, null, _systemLogger);
			// To support wslogout, we need to store the realm with the browser
			HandlerTools.putCookieValue(servletResponse, SESSION_ID_PREFIX + "realm", sAudience,
						_sCookieDomain, null, -1, 1/*httpOnly*/, _systemLogger);

				// _systemLogger.log(Level.INFO, MODULE, sMethod, "Inputs=" + sInputs);
	//			handlePostForm(_sPostTemplate, Tools.htmlEncode(sPwreply), sInputs, servletRequest, servletResponse);	// RH, 20171212, o
			handlePostForm(_sPostTemplate, sPwreply == null ? "" : Tools.htmlEncode(sPwreply), sInputs, servletRequest, servletResponse);	// RH, 20171212, n

			return new RequestState(null);
		}
		catch (SAMLException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAML Exception: ", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#serializeTheseAttributes(java.util.HashMap)
	 */
	public String serializeTheseAttributes(HashMap htAttribs)
	throws ASelectException
	{
		String sMethod = "serializeTheseAttributes";
		
		String sSerializedAttributes = Utils.serializeAttributes(htAttribs);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "sSerializedAttributes=" + sSerializedAttributes);
		return sSerializedAttributes;
	}

	/**
	 * Process signout.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState processSignout(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "processSignout";

		// First look for a possible TGT
		// HashMap htCredentialsParams = getCredentialsFromCookie(request);
		// Bauke 20081209: getCredentialsFromCookie now returns a string
		String sTgt = getCredentialsFromCookie(request);
		String sWtRealm = null;
		// if (htCredentialsParams != null) {sWtRealm
		// String sTgt = (String)htCredentialsParams.get("tgt");
		String saved_wreply = null;	// RH, 20181204, n
		if (sTgt != null) {
			HashMap htTGTContext = getContextFromTgt(sTgt, false); // Don't check expiration
			if (htTGTContext != null) { // Valid TGT context found
				sWtRealm = (String) htTGTContext.get("wtrealm");
				if (_doCleanup) {	// RH, 20181204, sn
					saved_wreply = (String) htTGTContext.get("wsfed_accountsts_wreply");
				}	// RH, 20181204, en
				_oTGTManager.remove(sTgt);
			}
		}
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "wtrealm=" + sWtRealm);
		// Remove the TGT cookie
		HandlerTools.delCookieValue(response, "aselect_credentials", _sCookieDomain, null, _systemLogger);
		// path=/ so applications can access it
		HandlerTools.delCookieValue(response, "ssoname", _sCookieDomain, "/", _systemLogger);
		// }

		try {
			// Find out where we need to send the user back to
			if (sWtRealm == null) {
				sWtRealm = HandlerTools.getCookieValue(request, SESSION_ID_PREFIX + "realm", _systemLogger);
			}
			String sReply = (String) _htSP_LogoutReturn.get(sWtRealm);
			// RH, 20151026, sn
//			if (sReply != null & sReply.length() > 0 && sReply.endsWith("*")) {	// add wreply query string to logout return url	// RH, 20190115, o
			if (sReply != null && sReply.length() > 0 && sReply.endsWith("*")) {	// add wreply query string to logout return url	// RH, 20190115, n
				StringBuffer s = new StringBuffer();
				s.append(sReply.substring(0, sReply.length() - 1));	// snap off the "*"
//				String wreply = request.getParameter("wreply");	// contains url encoded url	// RH, 20181204, o
				// RH, 20181204, sn
				String wreply = null;
				if (_doCleanup) {
					wreply = saved_wreply;
				}
				if (wreply == null) {
					wreply = request.getParameter("wreply");	// contains url encoded url	// RH, 20181204, o
				}
				// RH, 20181204, en
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handling  wreply: " + wreply);
				if (wreply != null && wreply.length() > 0) {
					wreply = URLDecoder.decode(wreply, "UTF-8");
					URL replyURL = new URL(wreply);	// we want wreply to be a url
					String queryPart = replyURL.getQuery(); // get the query part to add to our return url
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found  queryPart: " + queryPart);
					if (queryPart != null && queryPart.length()>0) {
						if (s.indexOf("?")>0)	{
							s.append("&");
						} else {
							s.append("?");
						}
						s.append(queryPart);
					}
				}
				sReply = s.toString();
			}
			// RH, 20151026, en
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Used " + sWtRealm
					+ " to find return address, REDIRECT to SP=" + sReply);

			// To play it nice, we should clean-up the 'realm' cookie,
			// But ... ADFS sometimes seems to allow the user to logout when they're already logged out
			// in that case the 'realm' would come in handy to return the user, therefore ...
			// don't: delCookieValue(response, SESSION_ID_PREFIX+"realm", _sCookieDomain);

			response.sendRedirect(sReply.toString());
			return new RequestState(null);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_IO, e);
		}
	}

	// RH, 20181127, sn
	// This is for pilot testing, we should have a cleanup file per identity provider
	private RequestState showCleanupForm (HttpServletRequest _servletRequest, HttpServletResponse _servletResponse, String wreply) throws ASelectException {
		String sMethod = "showCleanupForm";

		PrintWriter pwOut = null;

		try {
			pwOut = org.aselect.system.utils.Utils.prepareForHtmlOutput(_servletRequest, _servletResponse);
	
			String sTgt = getCredentialsFromCookie(_servletRequest);
			if (sTgt != null) {
				HashMap htTGTContext = getContextFromTgt(sTgt, false); // Do not check expiration
				if ( htTGTContext != null ) {
					htTGTContext.put("wsfed_accountsts_wreply", wreply);
					// Valid TGT context found, Update TGT wsfed_accountsts_wreply
					_oTGTManager.updateTGT(sTgt, htTGTContext);
				}
			}
			String sCleanupOutForm = _configManager.getHTMLForm("wsfed_cleanup", _sUserLanguage, _sUserCountry);
			sCleanupOutForm = _configManager.updateTemplate(sCleanupOutForm, null/*no session*/, _servletRequest);
	
			// We should pause and restart the timersensor
			pwOut.println(sCleanupOutForm);
		}
		catch (ASelectException ae) {
//			_timerSensor.setTimerSensorType(0);
//			showErrorPage(ae.getMessage(), htServiceRequest, pwOut);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO Exception", ae);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, ae);
		}
		catch (IOException ioe) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO Exception", ioe);
			throw new ASelectException(Errors.ERROR_ASELECT_IO, ioe);
		}
		catch (Exception e) {
			// produces a stack trace on FINEST level, when 'e' is given as a separate argument to log()
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
//			try {
//				if (_timerSensor.getTimerSensorLevel() >= 1) {  // used
//					_timerSensor.timerSensorFinish(bSuccess);
//					SendQueue.getHandle().addEntry(_timerSensor.timerSensorPack());
//				}
//			}
//			catch (Exception e) { }
		}
		return new RequestState(null);

	}
	// RH, 20181127, en
	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.ProtoRequestHandler#destroy()
	 */
	public void destroy()
	{
	}
}
