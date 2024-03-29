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

import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.LogoutResponseSender;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectDecoder;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.sp.MetaDataManagerSp;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.util.XMLHelper;


//
// SP Soap Logout Request Handler
// Handles IdP requests using HTTP redirect
//
public class Xsaml20_SLO_Redirect extends Saml20_BaseHandler
{
	private final static String MODULE = "sp.Xsaml20_SLO_Redirect";
	private static final String LOGOUTREQUEST = "LogoutRequest";

	/**
	 * Init for class Saml20_BaseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig
	 * @param oHandlerConfig
	 *            Object
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		super.init(oServletConfig, oHandlerConfig);
	}

	/**
	 * Dit is stap 7 van SLO. We hebben zojuist een saml LogoutRequest ontvangen en gaan deze nu verwerken. Dit houdt
	 * in: We loggen de gebruiker hier uit en maken hier melding van naar de federatie idp.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the request state
	 * @throws ASelectException
	 *             the a select exception
	 */
	/**
	 * Process logout request. <br>
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @param response
	 *            HttpServletResponse
	 * @throws ASelectException
	 *             If processing of logout request fails.
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		if (request.getParameter("SAMLRequest") != null) {
			handleSAMLRequest(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()
					+ " not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		return null;
	}

	/**
	 * Handle saml request.
	 * 
	 * @param servletRequest
	 *            the http request
	 * @param servletResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSAMLRequest(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleSAMLRequest";
		PrintWriter pwOut = null;

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(servletRequest));

			Saml20_RedirectDecoder decoder = new Saml20_RedirectDecoder();
			decoder.decode(messageContext);

			SignableSAMLObject samlMessage = (SignableSAMLObject) messageContext.getInboundSAMLMessage();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, Auxiliary.obfuscate(XMLHelper.prettyPrintXML(samlMessage.getDOM()), 
					Auxiliary.REGEX_PATTERNS));

			String elementName = samlMessage.getElementQName().getLocalPart();

			// get the issuer
			Issuer issuer;
			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				issuer = logoutRequest.getIssuer();
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ XMLHelper.prettyPrintXML(samlMessage.getDOM()) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sEntityId = issuer.getValue();

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Do logoutRequest signature verification="
					+ is_bVerifySignature());
			if (is_bVerifySignature()) {
				// The SAMLRequest must be signed, if not the message can't be trusted
				// and a responsemessage is send to the browser
				if (!SamlTools.isSigned(servletRequest)) {
					String errorMessage = "SAML message must be signed.";
					// RM_59_01
					// exception in all other cases?
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML message IS signed.");
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
//				List<PublicKey> publicKeys = metadataManager.getSigningKeyFromMetadata(sEntityId);	// RH, 20181119, n	// RH, 20190322, o
				List<PublicKey> publicKeys = metadataManager.getSigningKeyFromMetadata(_sResourceGroup, sEntityId);	// RH, 20181119, n	// RH, 20190322, n
				if (publicKeys == null || publicKeys.isEmpty()) {	// RH, 20181119, n
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "PublicKey for entityId: " + sEntityId
							+ " not found.");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Found PublicKey for entityId: " + sEntityId);
				if (!SamlTools.verifySignature(publicKeys, servletRequest)) {	// RH, 20181119, n
					String errorMessage = "Signing of SAML message is not correct.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					pwOut.write(errorMessage);
					return;
				}
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signature is correct.");
			}

			// The signature is OK and the message can be processed
			if (elementName.equals(LOGOUTREQUEST)) {
				LogoutRequest logoutRequest = (LogoutRequest) samlMessage;
				// now check the validity of the supplied time interval (if present)
				if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(logoutRequest)) {
					String errorMessage = "Time interval of SAML message is not valid.";
					_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
					pwOut.write(errorMessage);
					return;
				}
				handleLogoutRequest(servletRequest, servletResponse, logoutRequest);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "SAMLMessage: "
						+ Auxiliary.obfuscate(XMLHelper.prettyPrintXML(samlMessage.getDOM()), Auxiliary.REGEX_PATTERNS) + " is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);

			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}

	/**
	 * TO: De aangesproken SP vernietigt de lokale serversessie en clientcookie.De SP redirect de gebruiker naar de
	 * federatie-idp logoutservice met een LogoutResponse
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @param logoutRequest
	 *            the logout request
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleLogoutRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			LogoutRequest logoutRequest)
	throws ASelectException
	{
		String sMethod = "handleLogoutRequest";

		// Destroy the local session
		String sNameID = logoutRequest.getNameID().getValue();
//		int found = removeTgtByNameID(sNameID);	// RH, 20161215, o
		HashMap found = removeTgtByNameID(sNameID);// RH, 20161215, o
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "TGT found="+found);	// RH, 20161215, o
		_systemLogger.log(Level.INFO, MODULE, sMethod, "TGT removed="+Auxiliary.obfuscate(found));	// RH, 20161215, n

		// Delete the client cookie
		String sCookieDomain = _configManager.getCookieDomain();
		HandlerTools.delCookieValue(httpResponse, "aselect_credentials", sCookieDomain, null, _systemLogger);
		// path=/ so applications can access it
		HandlerTools.delCookieValue(httpResponse, "ssoname", sCookieDomain, "/", _systemLogger);

		// RH, 20161215, sn
		// send logoutrequest to audience
		String statusCode = StatusCode.SUCCESS_URI;	// assume success

		if (audiencelogout_required && found != null && found.get("sp_audience") != null) {
			// Send logout to audience as well
			// Retrieve statuscode of logoutresponse from audience
			String reason = "urn:oasis:names:tc:SAML:2.0:logout:user";
//			String reason = "urn:oasis:names:tc:SAML:2.0:logout:admin";	// still to decide user or admin
			String sp_audience = (String)found.get("sp_audience");
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to audience: " + sp_audience);
//				statusCode = sendLogoutRequestToSpAudience(sNameID, sp_audience, reason);	// RH, 20190322, o
				statusCode = sendLogoutRequestToSpAudience(_sResourceGroup, sNameID, sp_audience, reason);	// RH, 20190322, o
			} catch (ASelectException e) {	// we don't want to interrupt the idp logout process
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Logout to audience failed: " + e.getMessage());
				statusCode = StatusCode.PARTIAL_LOGOUT_URI;
			}
		} else {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "No logout to audience, no audience, not requested or tgt not found");
		}
		// RH, 20161215, en
		
		// Redirect the user to the federation-idp LogoutService with a LogoutResponse
		String issuer = logoutRequest.getIssuer().getValue();
//		String statusCode = StatusCode.SUCCESS_URI;	// RH, 20161219, o
		String myEntityId = _sServerUrl;

		MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
//		String logoutResponseLocation = metadataManager.getResponseLocation(issuer,	// RH, 20190322, o
		String logoutResponseLocation = metadataManager.getResponseLocation(_sResourceGroup, issuer,	// RH, 20190322, n
				SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		if (logoutResponseLocation == null) {
			// if responselocation does not exist, use location
//			logoutResponseLocation = metadataManager.getLocation(issuer,	// RH, 20190322, o
			logoutResponseLocation = metadataManager.getLocation(_sResourceGroup, issuer,	// RH, 20190322, n
					SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		}
		// RH, 20180918, sn
		PrivateKey key = null;
		LogoutResponseSender sender = null;
//		PartnerData partnerdata = metadataManager.getPartnerDataEntry(issuer);	// RH, 20190322, o
		PartnerData partnerdata = metadataManager.getPartnerDataEntry(_sResourceGroup, issuer);	// RH, 20190322, n
		if (partnerdata != null && partnerdata.getCrypto() != null) {
			sender = new LogoutResponseSender(partnerdata.getCrypto());
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using specific private key for redirect");
		} else {
			sender = new LogoutResponseSender();
		}
		// RH, 20180918, en

//		LogoutResponseSender sender = new LogoutResponseSender();	// RH, 20180918, o
		sender.sendLogoutResponse(logoutResponseLocation, myEntityId, statusCode, logoutRequest.getID(), null,
				httpRequest, httpResponse);
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	@Override
	public void destroy()
	{
	}
}
