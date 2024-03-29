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
package org.aselect.authspserver.authsp.openid;

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
import org.aselect.authspserver.authsp.openid.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;

/**
 * An A-Select AuthSP that uses a openid Provider as back-end. <br>
 * <br>
 * <b>Description:</b><br>
 * The A-Select OpenID AuthSP uses an OpenID Provider back-end to validate user/password combinations. 
 * The AuthSP retrieves the
 * following components and attributes from the A-Select AuthSP Server:
 * <ul>
 * <li>The configmanager</li>
 * <li>The crypto engine</li>
 * <li>The system logger</li>
 * <li>The authentication logger</li>
 * <li><code>friendly_name</code></li>
 * <li><code>working_dir</code></li>
 * </ul>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author RH, Anoigo
 */
public class OpenIDAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	/**	 */
	private static final long serialVersionUID = 8572776954706719972L;

	/** The status parameter name for API calls. */
	private final String RESULT_CODE = "status";

	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "OpenIDAuthSP";

	/** The version. */
	public static final String VERSION = "OpenID AuthSP";

	public static final String RID_POSTFIX = "_OpenID";

	/** HTML error templates */
	//private String _sErrorHtmlTemplate;

	/** HTML authenticate templates */
	//private String _sAuthenticateHtmlTemplate;

	// OpenID properties
	private String _sUrl;
	
	/**
	 * Initialization of the OpenID AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Performs the following steps to initialise the <code>AuthSP</code>:
	 * <ul>
	 * <li>Retrieve handles to managers and loggers</li>
	 * <li>Retrieve crypto engine from servlet context</li>
	 * <li>Retrieve friendly name from servlet context</li>
	 * <li>Load error properties</li>
	 * <li>Load HTML templates</li>
	 * <li>Get allowed retries from configuration</li>
	 * <li>Get failure handling from configuration</li>
	 * <li>Get openid properties, such as .....</li>
	 * </ul>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The AuthSPServer must be successfully started</li>
	 * <li>An error config file must exist</li>
	 * <li>An error template file must exist</li>
	 * <li>An authentication template file must exist</li>
	 * <li>An OopenID 'authsp' config section must be available in the configuration of the AuthSP Server. The id of this
	 * section must be available as 'config_id' servlet init paramater.</li>
	 * </ul>
	 * 
	 * @param oConfig
	 *            the o config
	 * @throws ServletException
	 *             the servlet exception
	 * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig)
	throws ServletException
	{
		String sMethod = "init";
		try {
			// super init
			super.init(oConfig, true, Errors.ERROR_DB_INTERNAL_ERROR);

			// log start
			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Load HTML templates.
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "authenticate.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'authenticate.html' template.");

			// Get allowed retries
			_iAllowedRetries = Utils.getSimpleIntParam(_configManager, _systemLogger, _oAuthSpConfig, "allowed_retries", true);

			// Get return url
//			_sUrl = Utils.getSimpleParam(_configManager, _systemLogger, oConfig, "url", true);
			_sUrl = Utils.getSimpleParam(_configManager, _systemLogger, _oAuthSpConfig, "url", true);

			sbInfo = new StringBuffer("Successfully started ").append(VERSION).append(".");
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	protected boolean isRestartableServlet()
	{
		return false;
	}

	/**
	 * Process requests for the HTTP <code>GET</code> method. <br>
	 * <br>
	 * This could be a API call, otherwise the authentication screen is displayed.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws java.io.IOException
	{
		String sMethod = "doGet";
		PrintWriter pwOut = null;
		String sLanguage = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "doGet");

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			String sQueryString = servletRequest.getQueryString();
			HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, false);
			HashMap htServiceRequestAsMap = (HashMap) servletRequest.getParameterMap();
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "htServiceRequest:" + htServiceRequest);

			sLanguage = (String) htServiceRequest.get("language");  // optional language code
			if (sLanguage == null || sLanguage.trim().length() < 1)
				sLanguage = null;
			String sCountry = (String) htServiceRequest.get("country");  // optional country code
			if (sCountry == null || sCountry.trim().length() < 1)
				sCountry = null;

			// check if the request is an API call
			String sRequestName = (String) htServiceRequest.get("request");
			if (sRequestName != null) { // API request
				_systemLogger.log(Level.INFO, MODULE, sMethod, "API call");
				// Maybe implement something which supports OpenID call without requesting user for OpenID identifier
				handleApiRequest(htServiceRequest, servletRequest, pwOut, servletResponse);
			}
			else {  // Browser request
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Browser request");		
				String sIsReturn = (String) htServiceRequest.get("is_return");
				
				// RM_18_03
				boolean isReturn = Boolean.parseBoolean(sIsReturn);
				if (!isReturn) {	// handle inital request from aselectserver
					
					// get info from QueryString
					String sRid = (String) htServiceRequest.get("rid");
					String sAsUrl = (String) htServiceRequest.get("as_url");
					String sUid = (String) htServiceRequest.get("uid");
					String sAsId = (String) htServiceRequest.get("a-select-server");
					String sSignature = (String) htServiceRequest.get("signature");
					String sRetryCounter = "0";
					
					String sMyUrl = servletRequest.getRequestURL().toString();
					htServiceRequest.put("my_url", sMyUrl);

					// RM_18_04
					if ((sRid == null) || (sAsUrl == null) || (sUid == null) || (sAsId == null) || (sSignature == null)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Invalid request received: one or more mandatory parameters missing.");
						throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
					}
	
					// URL decode values
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "URL decode values");
					sAsUrl = URLDecoder.decode(sAsUrl, "UTF-8");
					sUid = URLDecoder.decode(sUid, "UTF-8");
					sSignature = URLDecoder.decode(sSignature, "UTF-8");
	
					// validate signature
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "validate signature from A-Select Server ");
					StringBuffer sbSignature = new StringBuffer(sRid);
					sbSignature.append(sAsUrl);
					sbSignature.append(sUid);
					sbSignature.append(sAsId);
					if (sCountry != null) sbSignature.append(sCountry);
					if (sLanguage != null) sbSignature.append(sLanguage);

					if (!_cryptoEngine.verifySignature(sAsId, sbSignature.toString(), sSignature)) {
						StringBuffer sbWarning = new StringBuffer("Invalid signature from A-Select Server '");
						sbWarning.append(sAsId);
						sbWarning.append("' for user: ").append(Auxiliary.obfuscate(sUid));
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
						throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
					}
					htServiceRequest.put("as_url", sAsUrl);
					htServiceRequest.put("uid", sUid);
					htServiceRequest.put("retry_counter", sRetryCounter);
	
					if (sCountry != null) htServiceRequest.put("country", sCountry);
					if (sLanguage != null) htServiceRequest.put("language", sLanguage);	
					
					sbSignature = new StringBuffer(sRid);
					sbSignature.append(sAsUrl);
					sbSignature.append(sAsId);
					sbSignature.append(sRetryCounter);
					// optional country
					if (sCountry != null)
						sbSignature.append(sCountry);
					// optional language code
					if (sLanguage != null)
						sbSignature.append(sLanguage);

					sSignature = _cryptoEngine.generateSignature(sbSignature.toString());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "signature:" + sSignature);

					htServiceRequest.put("signature", sSignature);
					showAuthenticateForm(pwOut, ""/*no error*/, htServiceRequest);
				}
				else {	// handle return from openid					
					// get info from QueryString
					String sRid = URLDecoder.decode((String) htServiceRequest.get("rid"), "UTF-8");
			        HashMap<String , Object> htSessionContext = _sessionManager.getSessionContext(sRid + RID_POSTFIX);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved sessionContext:" + Auxiliary.obfuscate(htSessionContext));
			        
					// get info from sessionContext
					DiscoveryInformation discoveryinfo = (DiscoveryInformation) htSessionContext.get("discoveryinfo");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved discoveryinfo:" + discoveryinfo);
					
					String sReturnURL = (String) htSessionContext.get("siam_url");					
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved ReturnURL:" + sReturnURL);
					
					String sAsUrl = URLDecoder.decode((String) htServiceRequest.get("as_url"), "UTF-8");
					String sUid = URLDecoder.decode((String) htServiceRequest.get("uid"), "UTF-8");
					String sAsId = URLDecoder.decode((String) htServiceRequest.get("a-select-server"), "UTF-8");
					String sSignature = URLDecoder.decode((String) htServiceRequest.get("signature"), "UTF-8");
					
					String sRetryCounter = (String) htServiceRequest.get("retry_counter");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRetryCounter:" + sRetryCounter);
					sCountry = (String) htSessionContext.get("country");
					sLanguage = (String) htSessionContext.get("language");
					String sMyUrl = servletRequest.getRequestURL().toString();

					StringBuffer sbTemp = new StringBuffer(sRid);
					// RM_18_05
					sbTemp.append(sAsUrl);
					sbTemp.append(sAsId);
					sbTemp.append(sRetryCounter);
					if (sCountry != null)
						sbTemp.append(sCountry);
					if (sLanguage != null)
						sbTemp.append(sLanguage);
					
					if (!_cryptoEngine.verifyMySignature(sbTemp.toString(), sSignature)) {
						StringBuffer sbWarning = new StringBuffer("Invalid signature from OpenID Server '");
						sbWarning.append(sAsId);
						sbWarning.append("' for user: ");
						sbWarning.append(Auxiliary.obfuscate(sUid));
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
						throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
					}

					boolean matches = false;
					// handle openidresponse and find out if the user is authentic
			        RegistrationModel registrationModel = RegistrationService.processReturn(discoveryinfo, htServiceRequestAsMap, sReturnURL, _systemLogger);
			        if (registrationModel != null) {
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved OpenID:" + registrationModel.getOpenId());
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved OpenID:");
			        	matches = true;
			        }
					if (matches) {
						sUid = URLEncoder.encode(registrationModel.getOpenId(), "UTF-8");
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Authenticate success, returning to aselect OpenID:" + Auxiliary.obfuscate(sUid));
						_authenticationLogger.log(new Object[] {
							MODULE, Auxiliary.obfuscate(sUid), servletRequest.getRemoteAddr(), sAsId, "granted"
						});
						handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_SUCCESS, sLanguage, sUid);
					}
					else {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Authenticate failure");
						int iRetriesDone = Integer.parseInt(sRetryCounter);
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Authenticate failure#:" + iRetriesDone);

						if (iRetriesDone < _iAllowedRetries) {  // try again
							sRetryCounter = String.valueOf(++iRetriesDone); 
							htServiceRequest.put("my_url", sMyUrl);
							htServiceRequest.put("as_url", sAsUrl);
							htServiceRequest.put("uid", sUid);
							htServiceRequest.put("rid", sRid);
							htServiceRequest.put("a-select-server", sAsId);
							htServiceRequest.put("retry_counter",sRetryCounter);
							htServiceRequest.put("signature", sSignature);
							if (sCountry != null)
								htServiceRequest.put("country", sCountry);
							if (sLanguage != null)
								htServiceRequest.put("language", sLanguage);
							// show authentication form once again with warning message
							StringBuffer sbSignature = new StringBuffer(sRid);
							sbSignature.append(sAsUrl);
							sbSignature.append(sAsId);
							sbSignature.append(sRetryCounter);
							// optional country
							if (sCountry != null)
								sbSignature.append(sCountry);
							// optional language code
							if (sLanguage != null)
								sbSignature.append(sLanguage);

							sSignature = _cryptoEngine.generateSignature(sbSignature.toString());
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "signature:" + sSignature);
							htServiceRequest.put("signature", sSignature);
							
							showAuthenticateForm(pwOut, Errors.ERROR_DB_INVALID_PASSWORD, htServiceRequest);
						}
						else {
							// authenticate failed
							_authenticationLogger.log(new Object[] {
								MODULE, Auxiliary.obfuscate(sUid), servletRequest.getRemoteAddr(), sAsId, "denied", Errors.ERROR_DB_INVALID_PASSWORD
							});
							// RM_18_07
							handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_INVALID_PASSWORD, sLanguage, sUid);
						}
					}
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage);
		}
		catch (IOException eIO) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}

	/**
	 * Process requests for the HTTP <code>POST</code> method. <br>
	 * <br>
	 * This should be the submitted authentication form.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws java.io.IOException
	{
		String sMethod = "doPost";
		PrintWriter pwOut = null;
		String sUid = null;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "doPost");
		String sLanguage = servletRequest.getParameter("language");  // optional language code
		if (sLanguage == null || sLanguage.trim().length() < 1)
			sLanguage = null;
		String sCountry = servletRequest.getParameter("country");  // optional country code
		if (sCountry == null || sCountry.trim().length() < 1)
			sCountry = null;

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Starting openid stuff");		
		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			String sMyUrl = servletRequest.getRequestURL().toString();
			String sRid = servletRequest.getParameter("rid");
			String sAsUrl = servletRequest.getParameter("as_url");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "as_url:" + sAsUrl);
			sUid = servletRequest.getParameter("uid");
			String sAsId = servletRequest.getParameter("a-select-server");
//			sPassword = servletRequest.getParameter("password");
//			sOpenID = servletRequest.getParameter("openid");
			String sSignature = servletRequest.getParameter("signature");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "signature:" + sSignature);
			String sRetryCounter = servletRequest.getParameter("retry_counter");
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "User entered OpenID: " + Auxiliary.obfuscate(sUid));

			// RM_18_08
			if ((sRid == null) || (sAsUrl == null) || (sUid == null)  || (sAsId == null)
					|| (sRetryCounter == null) || (sSignature == null)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Invalid request received: one or more mandatory parameters missing.");
				throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
			}
			
			// RM_18_09
			if (sUid.trim().length() < 1) {  // invalid OpenID
				HashMap htServiceRequest = new HashMap();
				htServiceRequest.put("my_url", sMyUrl);
				htServiceRequest.put("as_url", sAsUrl);
				htServiceRequest.put("uid", sUid);
				htServiceRequest.put("rid", sRid);
				htServiceRequest.put("a-select-server", sAsId);
				htServiceRequest.put("retry_counter", sRetryCounter);
				htServiceRequest.put("signature", sSignature);
				if (sCountry != null)
					htServiceRequest.put("country", sCountry);
				if (sLanguage != null)
					htServiceRequest.put("language", sLanguage);
				// show authentication form once again with warning message
				// RM_18_10
				showAuthenticateForm(pwOut, Errors.ERROR_DB_INVALID_PASSWORD, htServiceRequest);
			}
			else { // Decent user id found, verify signature
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Start verify signature");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "URL decode values");
				
				StringBuffer sbSignature = new StringBuffer(sRid);
				sbSignature.append(sAsUrl);
				sbSignature.append(sAsId);
				sbSignature.append(sRetryCounter);	// sUid for now empty for signature calculation
				if (sCountry != null)
					sbSignature.append(sCountry);
				if (sLanguage != null)
					sbSignature.append(sLanguage);
				if ( !_cryptoEngine.verifyMySignature(sbSignature.toString(), sSignature) ) {
					StringBuffer sbWarning = new StringBuffer("Invalid signature from User form '");
					sbWarning.append(sAsId);
					sbWarning.append("' for user: ");
					sbWarning.append(Auxiliary.obfuscate(sUid));
					_systemLogger.log(Level.WARNING, MODULE, sMethod, sbWarning.toString());
					throw new ASelectException(Errors.ERROR_DB_INVALID_REQUEST);
				}
				// Signing is OK
				{
			        // Delegate to Open ID code
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Delegate to Open ID code");
			        String userSuppliedIdentifier = sUid;
			        DiscoveryInformation discoveryInformation = RegistrationService.performDiscoveryOnUserSuppliedIdentifier(userSuppliedIdentifier.trim(), _systemLogger);
			        // Store the discovery results in session.
			        HashMap<String, Object> hDiscovery = new HashMap<String, Object>();
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Stored discoveryInformation:" + discoveryInformation);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Stored discoveryInformation");

			        hDiscovery.put("discoveryinfo", discoveryInformation);
			        hDiscovery.put("my_url", sMyUrl);
			        hDiscovery.put("as_url", sAsUrl);
			        hDiscovery.put("uid", sUid);
					hDiscovery.put("rid", sRid);
					hDiscovery.put("a-select-server", sAsId);
					hDiscovery.put("retry_counter", sRetryCounter);

					StringBuffer sbTemp = new StringBuffer(sRid);
					sbTemp.append(sAsUrl); // resultcode still empty
					sbTemp.append(sAsId);
					sbTemp.append(sRetryCounter);
					if (sCountry != null)
						sbTemp.append(sCountry);
					if (sLanguage != null)
						sbTemp.append(sLanguage);
					sSignature = _cryptoEngine.generateSignature(sbTemp.toString());

					hDiscovery.put("signature", sSignature);
					if (sCountry != null)
						hDiscovery.put("country", sCountry);
					if (sLanguage != null)
						hDiscovery.put("language", sLanguage);
					String returnURL = servletRequest.getRequestURL().toString() + "?is_return=true&rid="+URLEncoder.encode(sRid, "UTF-8") +
						"&as_url=" + URLEncoder.encode(sAsUrl, "UTF-8") + "&a-select-server=" + URLEncoder.encode(sAsId, "UTF-8") +
						"&uid=" + URLEncoder.encode(sUid, "UTF-8") + "&signature=" + URLEncoder.encode(sSignature, "UTF-8") +
						"&retry_counter=" + URLEncoder.encode(sRetryCounter, "UTF-8");
					
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Stored returnURL:" + returnURL);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Stored returnURL");
					hDiscovery.put("siam_url", returnURL);
					
			        // We must NOT overwrite our aselectsession, therefore the RID_POSTFIX construction will store a separate session					
					// 20120401, Bauke: rewritten to clear up usage of updateSession()
					HashMap htSessionContext = null;
					String sFabricatedRid = sRid + RID_POSTFIX;
					try {
						htSessionContext = _sessionManager.getSessionContext(sFabricatedRid);
					}
					catch (ASelectException ae) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Not found: "+sFabricatedRid);
					}
					if (htSessionContext != null) {
						htSessionContext.putAll(hDiscovery);
						_sessionManager.updateSession(sFabricatedRid, htSessionContext);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Updated session for storing discoveryinfo with id:" + sFabricatedRid);
					}
					else {
				        _sessionManager.createSession(sFabricatedRid, hDiscovery);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created session for storing discoveryinfo with id:" + sFabricatedRid);
					}
			        // Create the AuthRequest
			        AuthRequest authRequest = RegistrationService.createOpenIdAuthRequest(discoveryInformation, returnURL);
			        // Now take the AuthRequest and forward it on to the OP
			        
			        // maybe implement new handler or special request parameter in doGet
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Starting redirect with redirectURL:" + authRequest.getDestinationUrl(true));			        
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Starting redirect");			        
			        servletResponse.sendRedirect(authRequest.getDestinationUrl(true));
				}
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client", eAS);
			handleResult(servletRequest, servletResponse, pwOut, eAS.getMessage(), sLanguage, sUid);
		}
		catch (IOException eIO) // could not send response
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error sending response", eIO);
			if (!servletResponse.isCommitted()) {
				// send response if no headers have been written
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}
		}
		catch (NumberFormatException eNF) // error parsing retry_counter
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Invalid request received: The retry counter parameter is invalid.");
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_INVALID_REQUEST, sLanguage, sUid);
		}
		catch (Exception e) // internal error
		{
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error", e);
			handleResult(servletRequest, servletResponse, pwOut, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage, sUid);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
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
	 *            The error that should be shown in the page.
	 * @param sErrorMessage
	 *            The error message that should be shown in the page.
	 * @param htServiceRequest
	 *            The request parameters.
	 * @throws ASelectException 
	 */
	private void showAuthenticateForm(PrintWriter pwOut, String sError, HashMap htServiceRequest)
	throws ASelectException
	{
		String sMethod = "showAuthenticateForm";

		String sMyUrl = (String) htServiceRequest.get("my_url");
		String sRid = (String) htServiceRequest.get("rid");
		String sAsUrl = (String) htServiceRequest.get("as_url");
		String sUid = (String) htServiceRequest.get("uid");
		String sAsId = (String) htServiceRequest.get("a-select-server");
		String sSignature = (String) htServiceRequest.get("signature");
		String sRetryCounter = (String) htServiceRequest.get("retry_counter");
		String sCountry = (String) htServiceRequest.get("country");
		String sLanguage = (String) htServiceRequest.get("language");
		
		String sAuthenticateForm = Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID,
				"authenticate.html", sLanguage, _sFriendlyName, VERSION);

		String sErrorMessage = null;
		if (Utils.hasValue(sError)) {  // translate error code
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, _sConfigID, "errors.conf", sLanguage);
			sErrorMessage = _configManager.getErrorMessage(MODULE, sError, propErrorMessages);
		}
		
		// RH, 20100907, sn
		// NOTE: friendly name is taken from the request, not the value produced by init()
		String sFriendlyName = (String) htServiceRequest.get("requestorfriendlyname");
		if (sFriendlyName != null) {
			try {
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", URLDecoder.decode(sFriendlyName, "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 dencoding not supported, using undecoded", e);
				sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[requestor_friendly_name]", sFriendlyName);
			}
		}
		// RH, 20100907, en

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[rid]", sRid);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[as_url]", sAsUrl);
		try {
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", URLDecoder.decode(sUid, "UTF-8"));
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "UTF-8 dencoding not supported, using undecoded", e);
			sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[uid]", sUid);
		}

		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[openid_server]", sMyUrl);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[a-select-server]", sAsId);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error]", sError);  // obsoleted 20100817
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_code]", sError);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[error_message]", sErrorMessage);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[language]", (sLanguage == null) ? "" : sLanguage);	// This "" is important for verification of signature
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[country]", (sCountry == null) ? "" :  sCountry);	// This "" is important for verification of signature
		sAuthenticateForm = Utils.replaceConditional(sAuthenticateForm, "[if_error,", ",", "]", sErrorMessage != null && !sErrorMessage.equals(""), _systemLogger);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[signature]", sSignature);
		sAuthenticateForm = Utils.replaceString(sAuthenticateForm, "[retry_counter]", sRetryCounter);

		pwOut.println(sAuthenticateForm);
	}

	/**
	 * Handle result, compatibility method
	 * 
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage)
	{
		handleResult(servletRequest, servletResponse, pwOut, sResultCode, sLanguage, null);
	}
	
	/**
	 * Handle result.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sResultCode
	 *            the s result code
	 * @param sResultCode
	 *            the uid retrieved user identity
	 */
	private void handleResult(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage, String sUid)
	{
		String sMethod = "handleResult";
		StringBuffer sbTemp = null;

		try {
			if (_sFailureHandling.equalsIgnoreCase(DEFAULT_FAILUREHANDLING) || sResultCode.equals(Errors.ERROR_DB_SUCCESS))
			// A-Select handles error or success
			{
				String sRid = servletRequest.getParameter("rid");
				String sAsUrl = servletRequest.getParameter("as_url");
				String sAsId = servletRequest.getParameter("a-select-server");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sRid:" + sRid);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sAsUrl:" + sAsUrl);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sAsId:" + sAsId);

				if (sRid == null || sAsUrl == null || sAsId == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
				}
				else {
					sbTemp = new StringBuffer(sRid);
					sbTemp.append(sAsUrl).append(sResultCode);
					sbTemp.append(sAsId);
					String sSignature = _cryptoEngine.generateSignature(sbTemp.toString());

					sSignature = URLEncoder.encode(sSignature, "UTF-8");

					sbTemp = new StringBuffer(sAsUrl);
					sbTemp.append("&rid=").append(sRid);
					sbTemp.append("&result_code=").append(sResultCode);
					sbTemp.append("&a-select-server=").append(sAsId);
					sbTemp.append("&signature=").append(sSignature);
					if (sUid != null) {
						sbTemp.append("&uid=").append(sUid);
					}

					try {
						servletResponse.sendRedirect(sbTemp.toString());
					}
					catch (IOException eIO) // could not send redirect
					{
						StringBuffer sbError = new StringBuffer("Could not send redirect");
//						sbError.append(sbTemp.toString()).append("\"");
						_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eIO);
					}
				}
			}
			else {  // Local error handling
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate DB AuthSP signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) {  // could not encode signature
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode DB AuthSP signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_DB_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}

	/**
	 * Processes an API request to this DB AuthSP.
	 * 
	 * @param htServiceRequest
	 *            a <code>HashMap</code> containing request parameters.
	 * @param servletRequest
	 *            The request.
	 * @param servletResponse
	 *            The response.
	 * @param pwOut
	 *            The output.
	 */
	private void handleApiRequest(HashMap htServiceRequest, HttpServletRequest servletRequest, PrintWriter pwOut,
			HttpServletResponse servletResponse)
	{
		// API Request not implemented!!
		// Maybe implement something which supports OpenID call without requesting user for OpenID identifier
		
		String sMethod = "handleApiRequest";
		_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received, API not supported");
		
		String sRid = (String) htServiceRequest.get("rid");
		// create response HashTable
		StringBuffer sbResponse = new StringBuffer("&rid=");
		// add rid to response
		sbResponse.append(sRid);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "sbResponse so far:" + sbResponse );

		try {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid request received, API request not supported (yet).");
			throw new ASelectException("Invalid request received, API not supported.");
			
		}
		catch (ASelectException eAS) {
			// Allready logged
			sbResponse.append("&").append(RESULT_CODE);
			sbResponse.append("=").append(eAS.getMessage());
		}
		// set reponse headers
		// Overwrite prepareForHtmlOutput() settings
		servletResponse.setContentType("application/x-www-form-urlencoded");
		servletResponse.setContentLength(sbResponse.length());
		// respond
		pwOut.write(sbResponse.toString());
	}

	 /**
	   * Generates the returnToUrl parameter that is passed to the OP. The
	   * User Agent (i.e., the browser) will be directed to this page following
	   * authentication.
	   * 
	   *  
	   * @return String - the returnToUrl to be used for the authentication request.
	   */
	  public String getReturnToUrl() {
		  String returnURL = _sUrl;
	    return returnURL;
	  }
}