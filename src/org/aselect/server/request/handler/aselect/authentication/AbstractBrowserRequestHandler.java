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
 * $Id: AbstractBrowserRequestHandler.java,v 1.9 2006/05/03 10:10:18 tom Exp $ 
 * 
 * Changelog:
 * $Log: AbstractBrowserRequestHandler.java,v $
 * Revision 1.9  2006/05/03 10:10:18  tom
 * Removed Javadoc version
 *
 * Revision 1.8  2006/04/12 09:23:53  martijn
 * added optional application config items in error page
 *
 * Revision 1.7  2006/04/06 11:07:48  leon
 * removed function which was commented out.
 *
 * Revision 1.6  2006/03/20 11:16:50  martijn
 * updateTemplate() method is moved to ConfigManager
 *
 * Revision 1.5  2006/03/17 13:17:21  martijn
 * updateTemplate now replaces tags starting with 'requestor_' instead of 'application_'
 *
 * Revision 1.4  2006/03/17 07:43:05  martijn
 * isShowAppUrl() has been changed to isShowUrl()
 *
 * Revision 1.3  2006/03/16 14:48:30  martijn
 * fixed updateTemplate(): now empy strings are placed in templates when no session context is available
 *
 * Revision 1.2  2006/03/16 10:34:46  martijn
 * added support for showwing optional application info in html templates
 *
 * Revision 1.1  2006/02/10 13:36:52  martijn
 * old request handlers moved to subpackage: authentication
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
 * Revision 1.10  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.9  2005/04/27 12:16:58  erwin
 * Fixed problem with '"' surrounded cookies.
 *
 * Revision 1.8  2005/04/26 15:13:18  erwin
 * IF -> ID in error
 *
 * Revision 1.7  2005/04/05 07:48:24  martijn
 * variable rename to coding standard
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
 * Revision 1.3  2005/03/17 07:57:04  erwin
 * Added Javadoc for protected method/variables.
 *
 * Revision 1.2  2005/03/16 12:52:10  tom
 * - Fixed javadoc
 *
 * Revision 1.1  2005/03/15 10:50:42  tom
 * Initial version
 *
 */

package org.aselect.server.request.handler.aselect.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.BasicRequestHandler;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.storagemanager.SendQueue;
import org.aselect.system.utils.TimerSensor;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * Abstract browser request handler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class can be used as a base class for request handlers which handle browser requests. The
 * <code>AbstractBrowserRequestHandler</code> also contains the helper functions used by the different request handlers <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * Use one <code>AbstractBrowserRequestHandler</code> implementation for a single request. <br>
 * 
 * @author Alfa & Ariss 14-11-2007 - Changes: - DigiD Gateway update - Cookie handling update
 * @author Bauke Hiemstra - www.anoigo.nl Copyright Gemeente Den Haag (http://www.denhaag.nl) and UMC Nijmegen
 *         (http://www.umcn.nl)
 */
public abstract class AbstractBrowserRequestHandler extends BasicRequestHandler implements IAuthnRequestHandler
{
	/** The module name. Can be overwritten in sub classes */
	protected String _sModule = "AbstractBrowserRequestHandler";

	/** The system logger is in BasicRequestHandler */
	/** The configuration Manager is in BasicRequestManager */

	/** The session manager. */
	protected SessionManager _sessionManager;

	/** The TGT manager. */
	protected TGTManager _tgtManager;

	/** The request. */
	protected HttpServletRequest _servletRequest;
	/** The response. */
	protected HttpServletResponse _servletResponse;

	// The local version of the session,
	// it functions as a local cache. Updates are done in the local cache,
	// and saved to storage at the end of the handler's life time
	// The entry "status" in the session maintains the action to be taken.
	// Also the "rid" value is stored in the session, while locally cached.
	// Both values will be removed before storing the session.
	protected HashMap _htSessionContext = null;
	// We can do the same for the TGT, so the BrowserHandlers need not read it:
	protected HashMap _htTGTContext = null;

	/** The server ID */
	protected String _sMyServerId;

	/** The origanisation */
	protected String _sMyOrg;

	protected String _sUserLanguage = "";
	protected String _sUserCountry = "";

	// For the needy
	protected TimerSensor _timerSensor;	
	long _lMyThreadId;

	protected String _sCorrectionFacility = null, _sCookiePrefix = "", _sCookieDomain = null;

	/**
	 * Construct an instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles are obtained to relevant managers. <br>
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
	public AbstractBrowserRequestHandler(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String sMyServerId, String sMyOrg)
	{
		String sMethod = "AbstractBrowserRequestHandler";

		_systemLogger = ASelectSystemLogger.getHandle();
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_tgtManager = TGTManager.getHandle();

		_sMyServerId = sMyServerId;
		_sMyOrg = sMyOrg;

		_servletRequest = servletRequest;
		_servletResponse = servletResponse;
		_htSessionContext = null;

		_lMyThreadId = Thread.currentThread().getId();
		_timerSensor = new TimerSensor(_systemLogger, "srv_abh");

		// Localization
		Locale loc = servletRequest.getLocale();
		_sUserLanguage = loc.getLanguage();
		_sUserCountry = loc.getCountry();
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "Locale: _" + _sUserLanguage + "_" + _sUserCountry);
	}

	/**
	 * This function processes browser requests <br>
	 * <br>
	 * .
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.aselect.authentication.IAuthnRequestHandler#processRequest()
	 */
	public void processRequest()
	throws ASelectException
	{
		String sMethod = "processRequest";
		PrintWriter pwOut = null;
		HashMap htServiceRequest = null;
		boolean bSuccess = false;
		
		try {
			_timerSensor.timerSensorStart(-1/*level unused*/, 3/*type=server*/, _lMyThreadId);  // unused by default

			pwOut = Utils.prepareForHtmlOutput(_servletRequest, _servletResponse);
			
			// Also reads TGT into _htTGTContext if available
			htServiceRequest = createServiceRequest(_servletRequest);
			String sRequest = (String) htServiceRequest.get("request");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "AbstBrowREQ "+_servletRequest.getMethod()+" htServiceRequest=" + Auxiliary.obfuscate(htServiceRequest));
			String sUsi = null;
			try {
				sUsi = (String)htServiceRequest.get("usi");  // unique sensor id
			}
			catch (Exception e) {  // Generate our own usi here
				sUsi = Tools.generateUniqueSensorId();
			}
			if (Utils.hasValue(sUsi))
				_timerSensor.setTimerSensorId(sUsi);

			// only check a-select-server if request != null
			if (sRequest != null && !sRequest.equals("alive")) {
				String sServerId = (String) htServiceRequest.get("a-select-server");
				_systemLogger.log(Level.FINEST, _sModule, sMethod, "AbstBrowREQ _sMyServerId=" + _sMyServerId
						+ ", sServerId=" + sServerId);
				if (sServerId == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameter \"a-select-server\"");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				else if (!sServerId.equals(_sMyServerId)) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid 'a-select-server' parameter: "+sServerId);
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_ID_MISMATCH);
				}
				// 20180517, sn
				else if (_bCheckClientIP) {
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "Checking client_ip against sAselect_credentials_client_ip");
					String sClient_ip = (String)htServiceRequest.get("client_ip");
					String sAselect_credentials_client_ip = (String)htServiceRequest.get("aselect_credentials_client_ip");
					
					if ( sAselect_credentials_client_ip != null && 
							!( sAselect_credentials_client_ip.equals(sClient_ip) ) ) {
								_systemLogger.log(Level.WARNING, _sModule, sMethod, "sClient_ip:" + sClient_ip + " != " + "sAselect_credentials_client_ip:" + sAselect_credentials_client_ip);
								throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					} else {
						_systemLogger.log(Level.FINEST, _sModule, sMethod, "IP's match");
					}
				}
				// 20180517, en
			}
			// Specifics for the individual BrowserHandler,
			// TGT has been read if available, htServiceRequest has been filled with parameters (GET or POST)
			processBrowserRequest(htServiceRequest, _servletResponse, pwOut);
			
			bSuccess = true;  // no exceptions thrown
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "AbstBrowREQ Done");
		}
		catch (ASelectException ae) {
			_timerSensor.setTimerSensorType(0);
			showErrorPage(ae.getMessage(), htServiceRequest, pwOut);
		}
		catch (IOException ioe) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "IO Exception", ioe);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, ioe);
		}
		catch (Exception e) {
			// produces a stack trace on FINEST level, when 'e' is given as a separate argument to log()
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Internal error: "+e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
			try {
				if (_timerSensor.getTimerSensorLevel() >= 1) {  // used
					_timerSensor.timerSensorFinish(bSuccess);
					SendQueue.getHandle().addEntry(_timerSensor.timerSensorPack());
				}
			}
			catch (Exception e) { }

			// 20120330: Decide what to do with the locally cached session
			_sessionManager.finalSessionProcessing(_htSessionContext, true/*update*/);
		}
		// don't close pwOut, so the caller can still inform the user of an error
	}

	/**
	 * Prosesses the API request. <br>
	 * <br>
	 * 
	 * @param htServiceRequest
	 *            Hashttable containing request parameters
	 * @param servletResponse
	 *            Used to send information (HTTP) back to the user
	 * @param pwOut
	 *            Used to send information back to the user (HTML)
	 * @throws ASelectException
	 *             If processing fails and no response is send to the client.
	 */
	abstract protected void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut)
	throws ASelectException;

	/**
	 * Shows the main A-Select Error page with the appropriate errors. <br>
	 * <br>
	 * 
	 * @param sErrorCode
	 *            the s error code
	 * @param htServiceRequest
	 *            the ht service request
	 * @param pwOut
	 *            the pw out
	 */
	protected void showErrorPage(String sErrorCode, HashMap htServiceRequest, PrintWriter pwOut)
	{
		String sMethod = "showErrorPage";

		String sErrorMessage = _configManager.getErrorMessage(MODULE, sErrorCode, _sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, _sModule, sMethod, "FORM[error] " + sErrorCode + ":" + sErrorMessage);
		try {
			String sErrorForm = _configManager.getHTMLForm("error", _sUserLanguage, _sUserCountry);
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);

			/* 20120328, Bauke: we already have the session in _htSessionContext
			HashMap htSessionContext = null;
			String sRid = (String) htServiceRequest.get("rid");
			if (sRid != null) {
				htSessionContext = _sessionManager.getSessionContext(sRid);
			}*/
			if (_htSessionContext != null) {
				//_systemLogger.log(Level.INFO, _sModule, sMethod, "session="+_htSessionContext);
				String sSpecials = Utils.getAselectSpecials(_htSessionContext, true/*decode too*/, _systemLogger);
				sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);
				String sAppUrl = (String)_htSessionContext.get("app_url");
				sErrorForm = Utils.replaceString(sErrorForm, "[app_url]", sAppUrl);
			}
			sErrorForm = _configManager.updateTemplate(sErrorForm, _htSessionContext, _servletRequest);  // accepts a null Session!
			//_systemLogger.log(Level.INFO, _sModule, sMethod, "FORM="+sErrorForm);
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102
			
			pwOut.println(sErrorForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, _sModule, sMethod, "Could not show error page with error: " + sErrorCode, e);
		}
	}

	/**
	 * Retrieve A-Select credentials. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Reads the A-Select credentials from a Cookie and put them into a <code>HashMap</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>servletRequest != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param servletRequest
	 *            The Request which should contain the Cookie.
	 * @return The A-Slect credentials in a <code>HashMap</code>.
	 */
	protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
	{
		String sMethod = "getASelectCredentials";

		// check for credentials that might be present
		// Bauke 20080618, we only store the tgt value from now on
		String sTgt = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
		if (sTgt == null) {
			return null;
		}

		_systemLogger.log(Level.FINEST, _sModule, sMethod, "Read TGT");
		_htTGTContext = _tgtManager.getTGT(sTgt);
		if (_htTGTContext == null) {
			return null;
		}
		/*
		 * if (!sUserId.equals(htTGTContext.get("uid"))) { return null; }
		 */
		String sUserId = (String) _htTGTContext.get("uid");
		if (sUserId == null)
			return null;

		HashMap htCredentials = new HashMap();
		htCredentials.put("aselect_credentials_tgt", sTgt);
		htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_server_id", _sMyServerId); // Bauke 20080618 was: sServerId);
		//
		htCredentials.put("aselect_credentials_client_ip", (String) _htTGTContext.get("client_ip"));
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "TGT client_ip: " + (String) _htTGTContext.get("client_ip"));
		//
		return htCredentials;
	}

	/**
	 * This function converts a <code>servletRequest</code> to a <code>HashMap</code> by extracting the parameters from
	 * the <code>servletRequest</code> and inserting them into a <code>HashMap</code>. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            Contains request parameters
	 * @return HashMap containing request parameters.
	 */
	private HashMap createServiceRequest(HttpServletRequest servletRequest)
	{
		String sMethod = "createServiceRequest";
		// Extract parameters into htServiceRequest
		HashMap htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {


			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString(), false);
			// Optionally activate selective url decoding
			// Find query parameter and app_id in config and request. If a match is found then do urldecode
			HashMap<String, Vector<String>> parameters2decode = _configManager.getParameters2decode();
			if ( parameters2decode != null && !parameters2decode.isEmpty() ) {
				Iterator<String> iparm = parameters2decode.keySet().iterator();
				while ( iparm.hasNext()) {
					String parmnname = iparm.next();
					Vector<String> appl = parameters2decode.get(parmnname);
					if ( htServiceRequest.containsKey(parmnname) && ( appl == null || appl.contains(htServiceRequest.get("app_id"))) ) {
						String xValue = (String) htServiceRequest.get(parmnname);
						try {
							xValue = URLDecoder.decode(xValue, "UTF-8");
							htServiceRequest.put(parmnname, xValue);	// replace with decoded version
						} catch (UnsupportedEncodingException e) {
							// should not happen, if it does, ignore, old value remains
							_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unsupported encoding exception for UTF-8, ignored");
						}
					}
				}
			}
		}
		else {
			htServiceRequest = new HashMap();
			String sParameter, sValue;
			Enumeration eParameters = servletRequest.getParameterNames();
			while (eParameters.hasMoreElements()) {
				sParameter = (String) eParameters.nextElement();
				sValue = servletRequest.getParameter(sParameter);
				if (sValue != null) {
					htServiceRequest.put(sParameter, sValue);
				}
			}
		}

		htServiceRequest.put("my_url", servletRequest.getRequestURL().toString());
		String sClientIp = servletRequest.getRemoteAddr();

		_systemLogger.log(Level.FINER, _sModule, sMethod, "client_ip:" + sClientIp);
		if (sClientIp != null)
			htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		String sAgent = servletRequest.getHeader("User-Agent");
		if (sAgent != null)
			htServiceRequest.put("user_agent", sAgent);
		
		String aselect_credentials_client_ip = null;
				
		// Also reads TGT into _htTGTContext if available
		HashMap htCredentials = getASelectCredentials(servletRequest);
		if (htCredentials != null) {
//			aselect_credentials_client_ip = (String) htServiceRequest.get("aselect_credentials_client_ip");	// RH, 20180517, o
			aselect_credentials_client_ip = (String) htCredentials.get("aselect_credentials_client_ip");	// RH, 20180517, n
			htServiceRequest.put("aselect_credentials_client_ip", aselect_credentials_client_ip);	// RH, 20180517, n

			htServiceRequest.put("aselect_credentials_tgt", htCredentials.get("aselect_credentials_tgt"));
			htServiceRequest.put("aselect_credentials_uid", htCredentials.get("aselect_credentials_uid"));
			htServiceRequest.put("aselect_credentials_server_id", _sMyServerId);
		}
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "aselect_credentials_client_ip:" + aselect_credentials_client_ip);
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "remote ip and tgt ip do match: " + ( sClientIp != null && sClientIp.equals(aselect_credentials_client_ip ) ));
		return htServiceRequest;
	}


	/**
	 * Gets the _servlet request.
	 * 
	 * @return the _servlet request
	 */
	public synchronized HttpServletRequest get_servletRequest()
	{
		return _servletRequest;
	}

	/**
	 * Gets the authsp parameters from the config file.
	 * 
	 * @param sAuthSp -	the authsp id that identifies the <authsp> section
	 * @return - the authsp section object
	 * @throws ASelectException
	 */
	protected Object getAuthspParametersFromConfig(String sAuthSp)
	throws ASelectException
	{
		String sMethod = "getAuthspParametersFromConfig";
		_systemLogger.log(Level.FINE, _sModule, sMethod, "AuthSp="+sAuthSp);
		
		Object authSPsection = null;
		try {
			authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp", "id="+sAuthSp);
		}
		catch (ASelectException eA) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"authsp\" received: " + sAuthSp, eA);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eA);
		}
		
		_sCorrectionFacility = Utils.getSimpleParam(_configManager, _systemLogger, authSPsection, "sms_correction_facility", false);
		_sCookiePrefix = Utils.getSimpleParam(_configManager, _systemLogger, authSPsection, "cookie_prefix", false);
		if (_sCookiePrefix == null)
			_sCookiePrefix = "";
		_sCookieDomain = Utils.getSimpleParam(_configManager, _systemLogger, authSPsection, "cookie_domain", false);
		if (!Utils.hasValue(_sCookieDomain)) {
			_sCookieDomain = _configManager.getCookieDomain();
		}
		_systemLogger.log(Level.FINE, _sModule, sMethod, "sms_correction_facility="+_sCorrectionFacility);
		return authSPsection;
	}

	/**
	 * Handle invalid phone.
	 * 
	 * @param servletResponse - the servlet response
	 * @param sCorrectionFacility - the correction facility URL
	 * @param sCookiePrefix - the cookie prefix
	 * @param sCookieDomain - the cookie domain
	 * @param sResultCode -  the result code
	 * @param sRid - the rid
	 * @param htSessionContext -  session context
	 * @throws ASelectException
	 * @throws IOException
	 */
	public void handleInvalidPhone(HttpServletResponse servletResponse, String sRid, HashMap htSessionContext)
	throws ASelectException, IOException
	{
		String sMethod = "handleInvalidPhone";
		
		_systemLogger.log(Level.INFO, _sModule, sMethod, "INVALID_PHONE from authsp");	
		// Redirect or exception
		if (!Utils.hasValue(_sCorrectionFacility))
			throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_INVALID_PHONE);
		
		// 20111101, Bauke: added Sensor
		Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_abh", sRid, htSessionContext, null, false);
		_sessionManager.setDeleteSession(htSessionContext, _systemLogger);  // 20120401, Bauke: postpone session action

		// User can possibly correct his phone number and retry
		_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to (sms_correction_facility): " + _sCorrectionFacility);
		String sAppUrl = (String) htSessionContext.get("app_url");
		HandlerTools.putCookieValue(servletResponse, _sCookiePrefix/*e.g. U1NP*/+"ApplicationUrl", sAppUrl,
									_sCookieDomain, "/",  600/*seconds*/, 1/*httpOnly*/, _systemLogger);
		servletResponse.sendRedirect(_sCorrectionFacility);
	}
}
