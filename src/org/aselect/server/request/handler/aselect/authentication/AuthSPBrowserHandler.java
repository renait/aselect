/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: AuthSPBrowserHandler.java,v 1.2 2006/05/03 10:10:18 tom Exp $
 * 
 * Changelog: 
 * $Log: AuthSPBrowserHandler.java,v $
 * Revision 1.2  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
 *
 * Revision 1.2  2006/02/08 08:07:34  martijn
 * getSession() renamed to getSessionContext()
 *
 * Revision 1.1  2006/01/13 08:40:26  martijn
 * *** empty log message ***
 *
 * Revision 1.1.2.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.13  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.12  2005/04/27 11:57:19  erwin
 * Fixed logging for unknown AuthSP and error in handling response.
 *
 * Revision 1.11  2005/04/06 08:58:12  martijn
 * code updates needed because of TGTIssuer code restyle
 *
 * Revision 1.10  2005/04/05 15:25:08  martijn
 * TGTIssuer.issueTGT() now only needs an optional old tgt and the printwriter isn't needed anymore
 *
 * Revision 1.9  2005/04/05 13:11:49  martijn
 * variable rename to coding standard
 *
 * Revision 1.8  2005/04/01 14:26:19  peter
 * cross aselect redesign
 *
 * Revision 1.7  2005/04/01 14:06:06  erwin
 * Added result_code check in handleError()
 *
 * Revision 1.6  2005/03/17 15:27:58  tom
 * Fixed javadoc
 *
 * Revision 1.5  2005/03/17 15:18:00  tom
 * Organized imports
 *
 * Revision 1.4  2005/03/17 15:16:48  tom
 * Removed redundant code,
 * A-Select-Server ID is checked in higher function
 *
 * Revision 1.3  2005/03/17 07:58:43  erwin
 * The A-Select server ID is now set with the constructor,
 * instead of reading it from the configuration.
 *
 * Revision 1.2  2005/03/15 10:51:16  tom
 * - Added new Abstract class functionality
 * - Added Javadoc
 *
 * Revision 1.1  2005/03/15 08:21:58  tom
 * - Redesign of request handling
 *
 */
package org.aselect.server.request.handler.aselect.authentication;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.utils.TimerSensor;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * This class handles cross-authentication requests coming from a remote A-Select Server, except for the
 * <code>cross_login</code> request. It must be used as follows: <br>
 * For each new incoming request, create a new <code>CrossASelectHandler</code> object and call either the
 * <code>handleCrossAuthenticateRequest()</code> or the <code>handleCrossAuthenticateResponse()</code>, as appropriate.
 * <code>CrossASelectHandler</code> objects cannot be reused due to concurrency issues. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - Transfer PKI attributes Subject DN and Issuer DN to the context
 * @author Bauke Hiemstra - www.anoigo.nl Copyright UMC Nijmegen (http://www.umcn.nl)
 */
public class AuthSPBrowserHandler extends AbstractBrowserRequestHandler
{
	/**
	 * Constructor for AuthSPBrowserHandler. <br>
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
	public AuthSPBrowserHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		super(servletRequest, servletResponse, sMyServerId, sMyOrg);
		_sModule = "AuthSPBrowserHandler";
	}

	/**
	 * process authsp browser requests <br>
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
	 * @see org.aselect.server.request.handler.aselect.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	@Override
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRequest = (String) htServiceRequest.get("request");
		if (sRequest == null && _servletRequest.getParameter("authsp") != null) {
			handleAuthSPResponse(htServiceRequest, pwOut);
		}
		else if (sRequest.equals("error")) {
			handleError(htServiceRequest);
		}
		else {
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * This function handles the AuthSP response and calls the correct AuthSP handler. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to the user
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleAuthSPResponse(HashMap htServiceRequest, PrintWriter pwOut)
	throws ASelectException
	{
		String sMethod = "handleAuthSPResponse";
		String sHandlerName = null;
		long now = System.currentTimeMillis();
		
		try {
			String sAuthSp = (String) htServiceRequest.get("authsp");
			Object authSPsection = getAuthspParametersFromConfig(sAuthSp);

			try {
				sHandlerName = _configManager.getParam(authSPsection, "handler");
			}
			catch (ASelectException eA) {  // Invalid AuthSP received
				StringBuffer sbError = new StringBuffer("No handler configured for AuthSP '");
				sbError.append(sAuthSp).append("'");
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbError.toString(), eA);
				throw eA;
			}
			String sAuthspLevel = Utils.getSimpleParam(_configManager, _systemLogger, authSPsection, "level", true);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AUTHSP authSPsection=" + authSPsection
					+ ", sHandlerName=" + sHandlerName + " id="+sAuthSp+" AuthspLevel="+sAuthspLevel);

			IAuthSPProtocolHandler oProtocolHandler = null;
			try {
				Class oClass = Class.forName(sHandlerName);
				oProtocolHandler = (IAuthSPProtocolHandler) oClass.newInstance();

				// get authsps config and retrieve active resource from SAMAgent
				String sResourceGroup = _configManager.getParam(authSPsection, "resourcegroup");
				SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourceGroup);
				Object objAuthSPResource = mySAMResource.getAttributes();
				oProtocolHandler.init(authSPsection, objAuthSPResource);
			}
			catch (Exception e) {
				StringBuffer sbMessage = new StringBuffer("could not instantiate ");
				sbMessage.append(sHandlerName);
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbMessage.toString(), e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}

			// 20120403, Bauke: get local rid name from handler, and read session first
			String sRid = (String) htServiceRequest.get(oProtocolHandler.getLocalRidName());  // "rid" or "local_rid" for DigiD
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "AuthSP response does not contain our RID");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Bad AuthSP response: Session could not be retrieved");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
			}
			// A session is available.
			
			// User interaction is finished, resume the stopwatch
			String sPause = (String)_htSessionContext.get("pause_contact"); // Was set by pauseSensorData()
			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  // throws away "pause_contact"

			if (_configManager.isTimerSensorConfigured()) {
				String sUsi = (String)_htSessionContext.get("usi");
				String sAppId = (String)_htSessionContext.get("app_id");					// RH, 20150608, n

				// Report time spent by the user
				if (Utils.hasValue(sPause)) {
					// User was busy from "sPause" to "now"
					long lPause = Long.parseLong(sPause);
					TimerSensor userTs = new TimerSensor(_systemLogger, "srv_pbh");
					userTs.timerSensorStart(lPause, 1/*level used*/, 5/*type=remote*/, _lMyThreadId);
					if (Utils.hasValue(sUsi))
						userTs.setTimerSensorId(sUsi);
					// RH, 20150608, sn
					if (Utils.hasValue(sAppId))
						userTs.setTimerSensorAppId(sAppId);
					// RH, 20150608, en
					userTs.timerSensorFinish(now, true);
					SendQueue.getHandle().addEntry(userTs.timerSensorPack());
				}

				// 20120611, Bauke: added "usi" handling
				_timerSensor.setTimerSensorLevel(1);  // enable measuring
				if (Utils.hasValue(sUsi))
					_timerSensor.setTimerSensorId(sUsi);
//				String sAppId = (String)_htSessionContext.get("app_id");					// RH, 20150608, o
				if (Utils.hasValue(sAppId))
					_timerSensor.setTimerSensorAppId(sAppId);
			}
						
			// Let the AuthSP protocol handler verify the response from the AuthSP
			// htAuthResponse will contain the result data
			// 20120403, Bauke: added _htSessionContext:
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AuthSP verify, Request=" + Auxiliary.obfuscate(htServiceRequest));
			HashMap htAuthspResponse = oProtocolHandler.verifyAuthenticationResponse(htServiceRequest, _htSessionContext);
			_systemLogger.log(Level.INFO, _sModule, sMethod, "AuthSP verify, Response=" + Auxiliary.obfuscate(htAuthspResponse));

			String sResultCode = (String)htAuthspResponse.get("result");
			_systemLogger.log(Level.INFO, _sModule, sMethod, "VA result=" + sResultCode);
			// Result values: ERROR_ASELECT_SUCCESS, ERROR_ASELECT_AUTHSP_INVALID_DATA (only SMS)

			// Saml20: Any errors must be reported back to the SP (so no Exception throwing in that case)
			if (sResultCode.equals(Errors.ERROR_ASELECT_AUTHSP_INVALID_PHONE)) {
				handleInvalidPhone(_servletResponse, sRid, _htSessionContext);
				return;
			}
		
			String sIssuer = (String) _htSessionContext.get("sp_issuer");
			if (sIssuer == null && !sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				// Session can be killed. The user could not be authenticated.
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error in authsp response: " + sResultCode+" issuer="+sIssuer);
				Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_pbh", sRid, _htSessionContext, null, false);
				_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
				throw new ASelectException(sResultCode);
			}

			// The user was authenticated successfully, or sp_issuer was present
			if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
				_htSessionContext.put("result_code", sResultCode); // must be used by the tgt issuer
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action
			}

			// Additional attributes can be provided by the AuthSP and will be transferred to the TgT
			HashMap htAdditional = new HashMap();

			// 20160418, Bauke: copy anything from htAuthspResponse that is not used specifically
			Set<String> sKeys = htAuthspResponse.keySet();
			for (Iterator i=sKeys.iterator(); i.hasNext(); ) {
				String sKey = (String)i.next();
				if (sKey.equals("result") || sKey.equals("rid") || sKey.equals("ser_attrs") ||
						sKey.equals("uid") || sKey.equals("betrouwbaarheidsniveau"))
					continue;
				Utils.copyHashmapValue(sKey, htAdditional, htAuthspResponse);
			}
			Utils.copyHashmapValue("authsp_type", htAdditional, _htSessionContext);  // will overwrite value from htAuthspResponse
			
			// Specific attributes that deserve their own handling
			// The NullAuthSP (so far the only one) can pass a set of attributes
			String sSerAttrs = (String)htAuthspResponse.get("ser_attrs");
			if (Utils.hasValue(sSerAttrs)) {  // inject the attributes
				htAdditional = org.aselect.server.utils.Utils.deserializeAttributes(sSerAttrs);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Attributes="+htAdditional);
			}
			
			// Some AuthSP's will return the authenticated userid as well (e.g. DigiD)
			// If they do, we'll have to copy it to our own Context
			String sUid = (String) htAuthspResponse.get("uid");
			if (sUid != null) { // For all AuthSP's that can set the user id
				// (and thereby replace the 'siam_user' value)
				_htSessionContext.put("user_id", sUid);  // This value will be used in the TgT
				_htSessionContext.put("sel_uid", sUid);  // 20140427, Bauke added for 'nextauthsp' mechanism, we don't want 'siam_user' any more
				_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

				Utils.copyHashmapValue("betrouwbaarheidsniveau", htAdditional, htAuthspResponse);
				Utils.copyHashmapValue("sp_assert_url", htAdditional, _htSessionContext);
				Utils.copyHashmapValue("sp_rid", htAdditional, _htSessionContext); // saml20 addition
			}

			/* 20160418: Replaced by the iterator loop above
			Utils.copyHashmapValue("sel_level", htAdditional, htAuthspResponse);  // user chose a different level
			// Bauke: transfer PKI attributes to the Context
			Utils.copyHashmapValue("pki_subject_dn", htAdditional, htAuthspResponse);
			Utils.copyHashmapValue("pki_issuer_dn", htAdditional, htAuthspResponse);
			Utils.copyHashmapValue("pki_subject_id", htAdditional, htAuthspResponse);
			Utils.copyHashmapValue("sms_phone", htAdditional, htAuthspResponse);
			// 20091118, Bauke: new functionality: copy attributes from AuthSP
			Utils.copyHashmapValue("attributes", htAdditional, htAuthspResponse);
			// 20090811, Bauke: save authsp_type for use by the Saml20 session sync
			Utils.copyHashmapValue("authsp_type", htAdditional, htAuthspResponse);
			*/

			// RH, 201109, sn
			// For non-direct_authsp sequential authsp implementation insert code here to handle any "next" authsps
			// get these from (optional) parameter in authsp resource section "applications.....next_authsp"
			// e.g.	String next_authsp = _authSPHandlerManager.getNextAuthSP(sAuthSPId, app_id);;
			String app_id = (String) _htSessionContext.get("app_id");
			String next_authsp = null;
			String next_authsp_server_id = null;
			String next_authsp_entry_level = null;
			if (sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			try {
				// get authsps config and retrieve active resource from SAMAgent
				String sResourceGroup = _configManager.getParam(authSPsection, "resourcegroup");
				SAMResource mySAMResource = ASelectSAMAgent.getHandle().getActiveResource(sResourceGroup);
				Object objAuthSPResource = mySAMResource.getAttributes();
				Object objAuthSPResourceAppls = _configManager.getSection(objAuthSPResource, "applications");
				Object objAppl = _configManager.getSection(objAuthSPResourceAppls, "application", "id=" + app_id);
				next_authsp = _configManager.getParam(objAppl, "next_authsp");
				// RH, 20150526, sn
				try {
					next_authsp_server_id = _configManager.getParam(objAppl, "next_authsp_server_id");
				}
				catch (ASelectConfigException ace) {
					_systemLogger.log(Level.FINER, _sModule, sMethod, "No next_authsp_server_id defined for app_id: "+app_id + ", using server_id from previous request");
				}
				// RH, 20150526, en				
				// RH, 20150914, sn
				try {
					next_authsp_entry_level = _configManager.getParam(objAppl, "next_authsp_entry_level");
				}
				catch (ASelectConfigException ace) {
					_systemLogger.log(Level.FINER, _sModule, sMethod, "No next_authsp_entry_level defined for app_id: "+app_id + ", continuing");
				}
				// RH, 20150914, en				
				
			}
			catch (ASelectConfigException ace) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "No next_authsp defined for app_id: "+app_id + ", continuing");
			}
			catch (ASelectSAMException ase) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "No next_authsp defined for app_id: "+app_id+ ", continuing");
			}
			}
			HandlerTools.setRequestorFriendlyCookie(_servletResponse, _htSessionContext, _systemLogger);  // 20130825
			
//			if (next_authsp != null ) {// RH, 20150914, o
			// RH, 20150914, sn
			if (sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS) && next_authsp != null) {
				
				if ( next_authsp_entry_level != null) {
					// Set tgt authsp level back so in case of falure of next_authsp authentication the remaining level will be low
					_htSessionContext.put("forced_level", next_authsp_entry_level);
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "Setting forced_level in  _htSessionContext: " + _htSessionContext);
				}
			}
			else {
				String forced_level = (String)_htSessionContext.get("forced_level");
				if ( forced_level != null) {	// found forced_level but no next_authsp, so remove "old" forced_level
					_htSessionContext.remove("forced_level");
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "Found forced_level in _htSessionContext but no next_authsp, removed forced_level, _htSessionContext:" + _htSessionContext);
				}
			}
			// RH, 20150914, en				
			
			// 20111020, Bauke: split redirection from issueTGTandRedirect, so next_authsp variant will also set the TGT
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
			String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
			String sTgt = tgtIssuer.issueTGTandRedirect(sRid, _htSessionContext, sAuthSp, htAdditional, _servletRequest, _servletResponse, sOldTGT, false /* no redirect */, oProtocolHandler);
			// sTgt could be null
			// Cookie was set on the 'servletResponse'

			// If there is a next_authsp, "present" form to user (auto post) and do not set tgt 
			if (sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS) && next_authsp != null ) {
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Found next_authsp: "+ next_authsp + " defined for app_id: "+app_id);
				if (_servletResponse != null) {					// Direct user to next_authsp with form
					String sNextauthspForm = _configManager.getHTMLForm("nextauthsp", _sUserLanguage, _sUserCountry);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[rid]", sRid);
					// RH, 20150526, sn
					if (next_authsp_server_id == null) {
						next_authsp_server_id = (String)htServiceRequest.get("a-select-server");	// backwards compatibility
					}
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[a-select-server]", next_authsp_server_id);	// RH, 20150526, o
					// RH, 20150526, en
//					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[a-select-server]", (String)htServiceRequest.get("a-select-server"));	// RH, 20150526, o
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[user_id]", sUid);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[authsp]", next_authsp);
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[aselect_url]", (String)htServiceRequest.get("my_url"));
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[request]", "login3");
					String sLanguage = (String) htServiceRequest.get("language");
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[language]", sLanguage);
					String sCountry = (String) htServiceRequest.get("country");
					sNextauthspForm = Utils.replaceString(sNextauthspForm, "[country]", sCountry);
					sNextauthspForm = _configManager.updateTemplate(sNextauthspForm, _htSessionContext, _servletRequest);

					_htSessionContext.put("user_state", "state_nextauthsp");
					_sessionManager.setUpdateSession(_htSessionContext, _systemLogger);
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
					pwOut.println(sNextauthspForm);
				}
				return;
			}
			// RH, 201109, en
			
			// Continue with regular processing
			Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_pbh", sRid, _htSessionContext, sTgt, true);
//			_sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action	// RH, 20140924, o
			if (sTgt != null && sTgt.length() > 0) _sessionManager.setDeleteSession(_htSessionContext, _systemLogger);  // RH, 20140924, n, if user has no tgt (yet) keep the session
			// 20111020, Bauke: redirect is done below

			if (oProtocolHandler.isOutputAvailable()) {
				String sAppUrl = (String) _htSessionContext.get("app_url");
				if (_htSessionContext.get("remote_session") != null)
					sAppUrl = (String) _htSessionContext.get("local_as_url");
				String sLang = (String)_htSessionContext.get("language");
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Redirect to " + sAppUrl);
				tgtIssuer.sendTgtRedirect(sAppUrl, sTgt, sRid, _servletResponse, sLang);		
			}
			else {
				_systemLogger.log(Level.FINER, _sModule, sMethod, "No outputstream available to redirect to so just return");
				return;
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Abort an authentication attempt and redirect the user back to the application. The application will receive the
	 * error code specified in the API call. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            HashMap containing request parameters
	 * @param servletResponse
	 *            Used to send (HTTP) information back to the user
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleError(HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "handleError";
		AuthenticationLogger authenticationLogger = ASelectAuthenticationLogger.getHandle();

		try {
			// Get parameter "rid"
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request: parameter 'rid' is missing.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Get parameter "result_code"
			String sResultCode = (String) htServiceRequest.get("result_code");
			if (sResultCode == null) // result_code missing
			{
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request: Parameter 'result_code' is missing.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			if (sResultCode.length() != 4) // result_code invalid
			{
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request: Parameter 'result_code' is not valid.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			try {
				Integer.parseInt(sResultCode);
			}
			catch (NumberFormatException eNF) // result_code not a number
			{
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request: Parameter 'result_code' is not a number.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Get session context
			_htSessionContext = _sessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request: invalid or unknown session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}
			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  // 20111102

			// Log cancel request
			String sAppId = (String) _htSessionContext.get("app_id");
			String sUserId = (String) _htSessionContext.get("user_id");
			authenticationLogger.log(new Object[] {
				"Login", Auxiliary.obfuscate(sUserId), (String) htServiceRequest.get("client_ip"), _sMyOrg, sAppId, "denied", sResultCode
			});

			// Issue error TGT
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
			tgtIssuer.issueErrorTGTandRedirect(sRid, _htSessionContext, sResultCode, _servletResponse);
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Internal error.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
