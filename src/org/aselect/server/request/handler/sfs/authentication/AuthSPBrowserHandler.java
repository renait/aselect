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
 * $Id: AuthSPBrowserHandler.java,v 1.1.2.1 2007/03/05 11:35:04 maarten Exp $
 * 
 * Changelog: 
 * $Log: AuthSPBrowserHandler.java,v $
 * Revision 1.1.2.1  2007/03/05 11:35:04  maarten
 * SFS Request Handlers
 *
 * Revision 1.1.2.1  2006/09/04 08:52:26  leon
 * SFS Handlers
 *
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

package org.aselect.server.request.handler.sfs.authentication;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.AuthenticationLogger;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.crypto.Auxiliary;


/**
 * This class handles cross-authentication requests coming from a remote A-Select Server, except for the
 * <code>cross_login</code> request. It must be used as follows: <br>
 * For each new incoming request, create a new <code>CrossASelectHandler</code> object and call either the
 * <code>handleCrossAuthenticateRequest()</code> or the <code>handleCrossAuthenticateResponse()</code>, as appropriate.
 * <code>CrossASelectHandler</code> objects cannot be reused due to concurrency issues. <br>
 * 
 * @author Alfa & Ariss
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
			String sMyServerId, String sMyOrg) {
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
	 * @see org.aselect.server.request.handler.sfs.authentication.AbstractBrowserRequestHandler#processBrowserRequest(java.util.HashMap,
	 *      javax.servlet.http.HttpServletResponse, java.io.PrintWriter)
	 */
	@Override
	public void processBrowserRequest(HashMap htServiceRequest, HttpServletResponse servletResponse, PrintWriter pwOut)
	throws ASelectException
	{
		String sRequest = (String) htServiceRequest.get("request");

		if (sRequest == null && _servletRequest.getParameter("authsp") != null) {
			handleAuthSPResponse(htServiceRequest, _servletResponse);
		}
		else if (sRequest.equals("error")) {
			handleError(htServiceRequest, _servletResponse);
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
	private void handleAuthSPResponse(HashMap htServiceRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleAuthSPResponse";
		String sHandlerName = null;
		Object authSPsection = null;
		try {
			String sAsp = (String) htServiceRequest.get("authsp");
			IAuthSPProtocolHandler oProtocolHandler = null;

			try {
				authSPsection = _configManager.getSection(_configManager.getSection(null, "authsps"), "authsp", "id="+sAsp);
			}
			catch (ASelectException eA) {
				// Invalid AuthSP received
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid \"authsp\" received: " + sAsp, eA);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST, eA);
			}

			try {
				sHandlerName = _configManager.getParam(authSPsection, "handler");
			}
			catch (ASelectException eA) {
				// Invalid AuthSP received
				StringBuffer sbError = new StringBuffer("No handler configured for AuthSP '");
				sbError.append(sAsp);
				sbError.append("'");
				_systemLogger.log(Level.SEVERE, _sModule, sMethod, sbError.toString(), eA);
				throw eA;
			}

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

			// let the AuthSP protocol handler verify the response from the AuthSP
			// 20120403, Bauke: added htSessionContext:
			HashMap htSessionContext = new HashMap();
			HashMap htAuthspResponse = oProtocolHandler.verifyAuthenticationResponse(htServiceRequest, htSessionContext);

			String sResultCode = (String) htAuthspResponse.get("result");
			if (!(sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS))) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Error in response from authsp: " + sResultCode);

				// session can be killed. The user could not be authenticated.
				String sRid = (String) htServiceRequest.get("rid");
				_sessionManager.deleteSession(sRid, htSessionContext);

				throw new ASelectException(sResultCode);
			}

			// user was authenticated successfully!!!
			String sRid = (String) htAuthspResponse.get("rid");
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);

			String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
			tgtIssuer.issueTGTandRedirect(sRid, htSessionContext, sAsp, null, _servletRequest, servletResponse, sOldTGT, true);
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
	private void handleError(HashMap htServiceRequest, HttpServletResponse servletResponse)
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
				_systemLogger.log(Level.WARNING, _sModule, sMethod,
						"Invalid request: Parameter 'result_code' is missing.");
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
			HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Invalid request: invalid or unknown session.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// Log cancel request
			String sAppId = (String) htSessionContext.get("app_id");
			String sUserId = (String) htSessionContext.get("user_id");
			authenticationLogger.log(new Object[] {
				"Login", Auxiliary.obfuscate(sUserId), (String) htServiceRequest.get("client_ip"), _sMyOrg, sAppId, "denied", sResultCode
			});

			// Issue TGT
			TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
			tgtIssuer.issueErrorTGTandRedirect(sRid, htSessionContext, sResultCode, servletResponse);
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
