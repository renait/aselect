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
package org.aselect.server.request.handler.xsaml20.sp;

import java.util.HashMap;
import java.util.Locale;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

// TODO: Auto-generated Javadoc
public class Xsaml20_Logout extends Saml20_BaseHandler
{
	private final static String _sModule = "Xsaml20_Logout";

	// The managers and engine
	private TGTManager _oTGTManager;
	public String _sRedirectUrl;

	/**
	 * Init for class Xsaml20_Logout. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
		throws ASelectException
	{
		String sMethod = "init";

		super.init(oServletConfig, oConfig);
		_oTGTManager = TGTManager.getHandle();

		Object aselect = _configManager.getSection(null, "aselect");
		// 20091207 _sFederationUrl = _configManager.getParam(aselect, "federation_url");
		_sRedirectUrl = _configManager.getParam(aselect, "redirect_url");

		// _sFriendlyName = _configManager.getParam(aselect, "organization_friendly_name");
		// _sLogoutResultPage = _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult.html");
		// _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage, "[version]",
		// Version.getVersion());
		// // Was: [organization_friendly_name], replaced 20081104
		// _sLogoutResultPage = org.aselect.system.utils.Utils.replaceString(_sLogoutResultPage,
		// "[organization_friendly]", _sFriendlyName);
	}

	/**
	 * Process the user's Logout request (received by the SP). Also send a "LogoutRequest" to the IdP. <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @return the request state
	 * @throws ASelectException
	 *             If processing logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process";

		String paramRequest = request.getParameter("request");
		_systemLogger.log(Level.INFO, _sModule, sMethod, "request=" + paramRequest);
		// Localization
		Locale loc = request.getLocale();
		_sUserLanguage = loc.getLanguage();
		_sUserCountry = loc.getCountry();
		_systemLogger.log(Level.INFO, _sModule, sMethod, "Locale: _" + _sUserLanguage + "_" + _sUserCountry);

		if ("kill_tgt".equals(paramRequest)) {
			handleKillTGTRequest(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "kill_tgt request expected");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return null;
	}

	/**
	 * This function handles the <code>request=kill_tgt</code> request. <br>
	 * 
	 * @param request
	 *            - The input message.
	 * @param response
	 *            - The output message.
	 * @throws ASelectException
	 *             - If proccessing fails.
	 */
	private void handleKillTGTRequest(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "handleKillTGTRequest";

		// get mandatory parameters
		String sEncTGT = request.getParameter("tgt_blob");
		String sASelectServer = request.getParameter("a-select-server");

		if (sEncTGT == null || sEncTGT.equals("") || sASelectServer == null || sASelectServer.equals("")) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Missing required parameters");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sTGT = null;
		try {
			byte[] baTgtBlobBytes = CryptoEngine.getHandle().decryptTGT(sEncTGT);
			sTGT = Utils.byteArrayToHexString(baTgtBlobBytes);
		}
		catch (ASelectException eAC) { // decrypt failed
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (IllegalArgumentException eIA) { // HEX conversion fails
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not decrypt TGT", eIA);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eIA);
		}

		// TODO: Is signing needed?
		// _systemLogger.log(Level.INFO, _sModule, sMethod, "NOTE SIGNING CHECK DISABLED");
		/*
		 * if (_applicationManager.isSigningRequired()) { // Note: we should do this earlier, but we don't have an
		 * app_id until now String sAppId = (String) htTGTContext.get("app_id"); StringBuffer sbData = new
		 * StringBuffer(sASelectServer).append(sEncTGT); verifyApplicationSignature(request, sbData.toString(), sAppId);
		 * }
		 */

		// First get rid of the client cookie (if still present)
		String sCookieDomain = _configManager.getCookieDomain();
		HandlerTools.delCookieValue(response, "aselect_credentials", sCookieDomain, _systemLogger);

		// 20090627, Bauke: added option to supply return URL
		// can be done here, because this is a browser request
		String sLogoutReturnUrl = request.getParameter("logout_return_url");

		// Check if the TGT exists
		HashMap htTGTContext = _oTGTManager.getTGT(sTGT);

		if (htTGTContext != null) {
			// For Saml20, will also send word to the IdP
			String sAuthspType = (String) htTGTContext.get("authsp_type");
			if (sAuthspType != null && sAuthspType.equals("saml20")) {
				htTGTContext.put("RelayState", sLogoutReturnUrl);
				_oTGTManager.update(sTGT, htTGTContext);
				sendLogoutToIdP(request, response, sTGT, htTGTContext, _sRedirectUrl, sLogoutReturnUrl);
				return;
			}
			// Kill the ticket granting ticket
			_oTGTManager.remove(sTGT);
		}
		else
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Unknown TGT / Already logged out");

		// TgT is gone now
		String sResultCode = ((htTGTContext == null) ? Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT
				: Errors.ERROR_ASELECT_SUCCESS);
		finishLogoutActions(response, sResultCode, sLogoutReturnUrl);

		/*
		 * if (sLogoutReturnUrl != null && !"".equals(sLogoutReturnUrl)) { // Redirect to the url in sRelayState String
		 * sAmpQuest = (sLogoutReturnUrl.indexOf('?') >= 0) ? "&": "?"; String url = sLogoutReturnUrl + sAmpQuest +
		 * "result_code=" + ((htTGTContext==null)? Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT:
		 * Errors.ERROR_ASELECT_SUCCESS); try { _systemLogger.log(Level.INFO, _sModule, sMethod, "Redirect to "+url);
		 * response.sendRedirect(url); } catch (IOException e) { _systemLogger.log(Level.WARNING, _sModule, sMethod,
		 * e.getMessage(), e); } } else { PrintWriter pwOut = null; try { _sLogoutResultPage =
		 * _configManager.loadHTMLTemplate(_configManager.getWorkingdir(), "logoutresult", _sUserLanguage,
		 * _sUserCountry); _sLogoutResultPage = Utils.replaceString(_sLogoutResultPage, "[version]",
		 * Version.getVersion()); _sLogoutResultPage = Utils.replaceString(_sLogoutResultPage,
		 * "[organization_friendly]", _sFriendlyName); String sHtmlPage = Utils.replaceString(_sLogoutResultPage,
		 * "[result_code]", Errors.ERROR_ASELECT_SERVER_UNKNOWN_TGT); pwOut = response.getWriter();
		 * response.setContentType("text/html"); pwOut.println(sHtmlPage); return; } catch (IOException e) {
		 * _systemLogger.log(Level.WARNING, _sModule, sMethod, e.getMessage(), e); throw new
		 * ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e); } finally { if (pwOut != null) { pwOut.close(); } }
		 * }
		 */
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}
}