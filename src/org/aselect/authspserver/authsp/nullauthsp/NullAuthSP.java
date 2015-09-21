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
 * $Id: NullAuthSP.java,v 1.24 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: NullAuthSP.java,v $
 * Revision 1.24  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.23  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.22.2.1  2006/03/22 09:18:53  martijn
 * changed version to 1.5
 *
 * Revision 1.22  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.21  2005/04/01 14:18:40  martijn
 * added support for the optional attributes country and language
 *
 * Revision 1.20  2005/03/29 10:59:19  erwin
 * Removed redundant code; now extends ASelectHttpServlet and uses AuthSP configmanager functionality.
 *
 * Revision 1.19  2005/03/23 11:34:35  erwin
 * Fixed problem with nullpointer if errors are handled by A-Select.
 *
 * Revision 1.18  2005/03/23 09:51:10  erwin
 * Fixed problem with error handling missing config_id
 *
 * Revision 1.17  2005/03/18 15:31:07  martijn
 * logs if invalid request was sent
 *
 * Revision 1.16  2005/03/18 15:22:18  martijn
 * if invalid request, then show error page
 *
 * Revision 1.15  2005/03/16 11:18:05  martijn
 * version is set to default
 *
 * Revision 1.14  2005/03/14 09:58:02  martijn
 * config section renamed, new config used an init-param from web.xml to retrieve the config section
 *
 * Revision 1.13  2005/03/14 07:22:03  tom
 * Minor code style changes
 *
 * Revision 1.12  2005/03/11 15:28:18  erwin
 * Renamed loggers.
 *
 * Revision 1.11  2005/03/11 13:48:33  erwin
 * Improved error handling.
 *
 * Revision 1.10  2005/03/11 07:46:31  martijn
 * If succesfully loaded a Level.WARNING was logged. Now a Level.INFO will be logged.
 *
 * Revision 1.9  2005/03/10 16:17:10  tom
 * Added new Authentication Logger
 *
 * Revision 1.8  2005/03/10 08:16:02  tom
 * Added new Logger functionality
 *
 * Revision 1.7  2005/03/09 14:05:53  erwin
 * INFO -> SEVERE
 *
 * Revision 1.6  2005/03/09 14:02:14  tom
 * Added new logging and error handling
 *
 * Revision 1.5  2005/03/03 12:50:09  martijn
 * added javadoc / made compatible with A-Select 1.4.1
 *
 * Revision 1.4  2005/03/03 08:37:23  leon
 * exception x renamed to exception e
 *
 * Revision 1.3  2005/02/09 09:17:44  leon
 * added License
 * code restyle
 *
 */

package org.aselect.authspserver.authsp.nullauthsp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * . <br>
 * Null AuthSP is an AuthSP used for testing <br>
 * <b>Description: </b> <br>
 * The Null AuthSP is a test AuthSP that uses his configuration tosend an access denied or access granted. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class NullAuthSP extends AbstractAuthSP
{
	private static final long serialVersionUID = 1L;
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static String MODULE = "NullAuthSP";
	/**
	 * The Null AuthSP version string
	 */
	private static String VERSION = "A-Select Null AuthSP 2.0";
	/**
	 * The authentication mode that is configured
	 */
	private String _sAuthMode;
	
	// 20150909, Bauke: added form to allow the user to enter attributes
	private boolean _bDataEntry = false;
	
	/**
	 * Initialization of the Null AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * The Null AuthSP uses the following components from the A-Select AuthSP Server<br>
	 * - the config manager<br>
	 * - the crypto engine<br>
	 * - the user friendly name<br>
	 * - the working directory<br>
	 * <br>
	 * Initialization includes:<br>
	 * - It loads the AuthSP components from the servlet context.<br>
	 * - It loads the error messages from the errors.conf file.<br>
	 * - It loads the error.html file.<br>
	 * - Sets the configured authentication_mode (default = grant all users)<br>
	 * <br>
	 * <br>
	 * <b>Preconditions:</b><br>
	 * - the AuthSPServer must be succesfully started<br>
	 * - an error config file must exist:<br>
	 * <i>workingdir/conf/nullauthsp/errors/errors.conf</i><br>
	 * - an error template file must exist:<br>
	 * <i>workingdir/conf/nullauthsp/html/error.html</i><br>
	 * - needs an 'authsp' config section with name='nullauthsp' in the configuration of the AuthSP Server <br>
	 * <br>
	 * 
	 * @param oServletConfig
	 *            the servlet config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig oServletConfig)
	throws ServletException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, false, "");

			StringBuffer sbInfo = new StringBuffer("Starting : ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");

			// _oAuthSPConfig can be null
			String sAuthMode = null;
			try {
				sAuthMode = _configManager.getParam(_oAuthSpConfig, "authentication_mode");
			}
			catch (Exception e) {
				sAuthMode = null;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No valid 'authentication_mode' config item found, using default: authentication mode = granted.");
			}
			if (sAuthMode == null)
				sAuthMode = "";

			if (sAuthMode.equalsIgnoreCase("denied"))
				_sAuthMode = Errors.ERROR_NULL_ACCESS_DENIED;
			else
				_sAuthMode = Errors.ERROR_NULL_SUCCESS;

			_bDataEntry = sAuthMode.equalsIgnoreCase("data_entry");  // show the data entry form
			if (_bDataEntry) {
				Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "data_entry.html", null, _sFriendlyName, VERSION);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'data_entry.html' template.");
			}
			
			sbInfo = new StringBuffer("Successfully started: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString()+" authentication_mode="+sAuthMode);
		}
		catch (ASelectException ase) {
			throw new ServletException(ase);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			StringBuffer sbError = new StringBuffer("Could not initialize ");
			sbError.append(MODULE).append(" : ").append(e.getMessage());
			throw new ServletException(sbError.toString(), e);
		}
	}

	/**
	 * Processes requests for HTTP <code>GET</code>. <br>
	 * <br>
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF">name</td>
	 * <td style="" bgcolor="#EEEEFF">value</td>
	 * <td style="" bgcolor="#EEEEFF">encoded</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>A-Select Server request id</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>as_url</td>
	 * <td>A-Select Server URL</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>uid</td>
	 * <td>A-Select User ID</td>
	 * <td>yes</td>
	 * </tr>
	 * <tr>
	 * <td>a-select-server</td>
	 * <td>A-Select Server ID</td>
	 * <td>no</td>
	 * </tr>
	 * <tr>
	 * <td>signature</td>
	 * <td>signature of all paramaters in the above sequence</td>
	 * <td>yes</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doGet";
		String sQueryString = "";
		String sLanguage = null;
		
		PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

		sQueryString = servletRequest.getQueryString();
		HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, true);  // URL decoded result

		try {
			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;			
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;
			
			String sMyUrl = servletRequest.getRequestURL().toString();
			htServiceRequest.put("my_url", sMyUrl);

			String sRid = (String) htServiceRequest.get("rid");
			String sAsUrl = (String) htServiceRequest.get("as_url");
			String sAsId = (String) htServiceRequest.get("a-select-server");
			String sUid = (String) htServiceRequest.get("uid");
			String sSignature = (String) htServiceRequest.get("signature");

			if (sRid == null || sAsUrl == null || sUid == null || sAsId == null || sSignature == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid request, at least one mandatory parameter is missing.");
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "GET begin { "+sMethod+": "+sQueryString);

			StringBuffer sbSignature = new StringBuffer(sRid).append(sAsUrl).append(sUid).append(sAsId);
			// optional country and language code
			if (sCountry != null) sbSignature.append(sCountry);
			if (sLanguage != null) sbSignature.append(sLanguage);

			if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
				throw new ASelectException(Errors.ERROR_NULL_INVALID_REQUEST);
			}
			
			if (_bDataEntry) {
				// Store data we will need later on
				HashMap sessionContext = new HashMap();
				sessionContext.put("rid", sRid);
				sessionContext.put("as_url", sAsUrl);
				sessionContext.put("a-select-server", sAsId);
				sessionContext.put("uid", sUid);
				_sessionManager.updateSession(sRid, sessionContext);

				// Display the data entry form, result will be handled in the POST
				// Sign the rid for the form
				String sFormSignature = _cryptoEngine.generateSignature(sRid);
				if (sFormSignature == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to generate signature");
					throw new ASelectException(Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER);
				}
				//sFormSignature = URLEncoder.encode(sFormSignature, "UTF-8");
				htServiceRequest.put("signature", sFormSignature);  // replaces server signature
				showDataEntryForm(pwOut, ""/*no error*/, htServiceRequest);
				return;
			}
			
			if (_sAuthMode.equals(Errors.ERROR_NULL_SUCCESS)) {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "granted"
				});
			}
			else {
				_authenticationLogger.log(new Object[] {
					MODULE, sUid, servletRequest.getRemoteAddr(), sAsId, "denied", _sAuthMode
				});
			}
			handleResult(htServiceRequest, servletResponse, null, _sAuthMode, sLanguage, pwOut);
		}
		catch (ASelectException e) {
			handleResult(htServiceRequest, servletResponse, null, e.getMessage(), sLanguage, pwOut);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			handleResult(htServiceRequest, servletResponse, null, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, sLanguage, pwOut);
		}
		finally {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "} GET end");			
		}
	}
	/**
	 * Show an HTML authentication page. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Shows a authentication form with, if applicable, an error or warning message.
	 * 
	 * @param pwOut
	 *            the <code>PrintWriter</code> that is the target for displaying the html page.
	 * @param sError
	 *            The error that should be shown in the page. Can be null (no errors)
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 * @throws ASelectException 
	 */
	private void showDataEntryForm(PrintWriter pwOut, String sError, HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "showDataEntryForm";

		String sRid = (String) htServiceRequest.get("rid");
		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sSignature = (String) htServiceRequest.get("signature");
		String sLanguage = (String)htServiceRequest.get("language");  // optional language code
		String sDataEntryForm = Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
				"data_entry.html", sLanguage, _sFriendlyName, VERSION);
		
		String sErrorMessage = null;
		if (Utils.hasValue(sError)) {  // translate error code
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", sLanguage);
			sErrorMessage = _configManager.getErrorMessage(MODULE, sError, propErrorMessages);
		}
		
		// NOTE: friendly name is taken from the request, not the value produced by init()
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		if (sFriendlyName != null) {
			try {
				sDataEntryForm = Utils.replaceString(sDataEntryForm, "[requestor_friendly_name]", URLDecoder.decode(sFriendlyName, "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 encoding not supported, using undecoded", e);
				sDataEntryForm = Utils.replaceString(sDataEntryForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "error_code="+sError+" message="+sErrorMessage);
		sDataEntryForm = Utils.replaceString(sDataEntryForm, "[rid]", sRid);
		sDataEntryForm = Utils.replaceString(sDataEntryForm, "[signature]", sSignature);
		sDataEntryForm = Utils.replaceString(sDataEntryForm, "[authsp_server]", sMyUrl);
		if (sError != null) {
			sDataEntryForm = Utils.replaceString(sDataEntryForm, "[error_code]", sError);
		}
		sDataEntryForm = Utils.replaceString(sDataEntryForm, "[error_message]", sErrorMessage);
		
		// Bauke 20110721: Extract if_cond=... from the application URL
		String sSpecials = Utils.getAselectSpecials(htServiceRequest, true/*decode too*/, _systemLogger);
		sDataEntryForm = Utils.handleAllConditionals(sDataEntryForm, Utils.hasValue(sErrorMessage), sSpecials, _systemLogger);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Show Form: "+"data_entry.html");
		pwOut.println(sDataEntryForm);
	}

	/**
	 * POST entry point of the Null AuthSP.
	 * Used to process data entry from the user.<br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doPost";
		String sResult = Errors.ERROR_NULL_INVALID_REQUEST;

		PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "POST begin { "+sMethod+", qry=" + servletRequest.getQueryString());		
		String sRid = (String)servletRequest.getParameter("rid");
		String sSignature = (String)servletRequest.getParameter("signature");

		try {
			// Get the session
			HashMap sessionContext = _sessionManager.getSessionContext(sRid);
			HashMap<String,String> hmAttributes = new HashMap<String, String>();
			String sLanguage = (String)sessionContext.get("language");

			if (!_cryptoEngine.verifyMySignature(sRid, sSignature)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature from POST form");
			}
			else {
				for (int i=1; ; i++) {
					String sName = "attr_name"+i;
					String sValue = "attr_value"+i;
					String sNameValue = (String)servletRequest.getParameter(sName);
					String sValueValue = (String)servletRequest.getParameter(sValue);
					if (!Utils.hasValue(sNameValue) || !Utils.hasValue(sValueValue))
						break;
					hmAttributes.put(sNameValue, sValueValue);
				}
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Attributes="+hmAttributes);
				sResult = Errors.ERROR_NULL_SUCCESS;
			}
			handleResult(sessionContext, servletResponse, hmAttributes, sResult, sLanguage, pwOut);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
			throw new ServletException(Errors.ERROR_NULL_INTERNAL);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "} POST end");
		}
	}

	/**
	 * Determines whether or not the NULL AuthSP is restartable. <br>
	 * <br>
	 * 
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		// RM_17_01
		return false;
	}

	/**
	 * Creates a redirect url and redirects the user back to the A-Select Server. <br>
	 * <br>
	 * 
	 * @param servletRequest
	 *            The servlet request
	 * @param servletResponse
	 *            The servlet response
	 * @param sResultCode
	 *            The error code that should be sent to the A-Select Server
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private void handleResult(HashMap servletRequest, HttpServletResponse servletResponse, HashMap<String,String> hmAttributes,
				String sResultCode, String sLanguage, PrintWriter pwOut)
	throws IOException
	{
		String sMethod = "handleResult";

		try {
			if (sResultCode.equals(Errors.ERROR_NULL_SUCCESS)) {
				String sRid = (String)servletRequest.get("rid");
				String sAsUrl = (String)servletRequest.get("as_url");
				String sAsId = (String)servletRequest.get("a-select-server");
				if (sRid != null && sAsUrl != null && sAsId != null) {
					String sSerializedAttrs = null;
					if (hmAttributes != null) {  // pass the attributes too
						sSerializedAttrs = Utils.serializeAttributes(hmAttributes);	// creates base64
					}
					StringBuffer sbSignature = new StringBuffer(sRid);
					sbSignature.append(sAsUrl);
					sbSignature.append(sResultCode);
					sbSignature.append(sAsId);
					if (sSerializedAttrs != null)
						sbSignature.append(sSerializedAttrs);

					String sSignature = _cryptoEngine.generateSignature(sbSignature.toString());
					sSignature = URLEncoder.encode(sSignature, "UTF-8");
					StringBuffer sbRedirect = new StringBuffer(sAsUrl);
					sbRedirect.append("&rid=").append(sRid);
					sbRedirect.append("&result_code=").append(sResultCode);
					sbRedirect.append("&a-select-server=").append(sAsId);
					sbRedirect.append("&ser_attrs=").append(sSerializedAttrs);
					sbRedirect.append("&signature=").append(sSignature);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIR " + sbRedirect);
					servletResponse.sendRedirect(sbRedirect.toString());
					return;
				}
			}
			getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
		}
		catch (ASelectException eAS) {  // could not generate signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate NULL AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) {  // could not encode signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode NULL AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_NULL_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (IOException eIO) { // Could not write output
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "IO error while handling authentication result", eIO);
			throw eIO;
		}
	}
}