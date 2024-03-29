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
package org.aselect.server.request.handler.xsaml20;

import java.security.PrivateKey;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.crypto.Auxiliary;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

public class LogoutResponseSender
{
	private final static String MODULE = "LogoutResponseSender";
	private ASelectSystemLogger _systemLogger;
	private PrivateKey privateKey;

	/**
	 * Instantiates a new logout response sender.
	 */
	public LogoutResponseSender() {
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = ASelectConfigManager.getHandle().getDefaultPrivateKey();
	}

	// RH, 20180918, sn
	/**
	 * Instantiates a new logout response sender.
	 */
	public LogoutResponseSender(PartnerData.Crypto specificCrypto) {
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = specificCrypto.getPrivateKey();
	}
	// RH, 20180918, en

	/**
	 * Send Logout Response. <br>
	 * 
	 * @param logoutResponseLocation
	 *            String with location to send response .
	 * @param issuer
	 *            String with Issuer url.
	 * @param statusCode
	 *            String with ???.
	 * @param inResponseTo
	 *            String with ???.
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @param sRelayState
	 *            the s relay state
	 * @throws ASelectException
	 *             If sending fails.
	 */
	@SuppressWarnings("unchecked")
	public void sendLogoutResponse(String logoutResponseLocation, String issuer, String statusCode,
			String inResponseTo, String sRelayState, HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "sendLogoutResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send LogoutResponse to: " + logoutResponseLocation
				+ " RelayState=" + sRelayState);

		LogoutResponse logoutResponse = SamlTools.buildLogoutResponse(issuer, statusCode, inResponseTo);

		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		// Older version of saml2 lib has problem with not setting Location so we set it
		samlEndpoint.setLocation(logoutResponseLocation);
		// RH, 20150226, so
//		String sAppUrl = request.getRequestURL().toString();
//		samlEndpoint.setResponseLocation(sAppUrl)
		// RH, 20150226, eo
		// RH, 20150226, sn
		// HTTPRedirectDeflateEncoder only uses ResponseLocation when sending StatusResponseType and ResponseLocation not empty
		samlEndpoint.setResponseLocation(logoutResponseLocation);
		// RH, 20150226, en
				
		HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response,
				logoutResponseLocation);
		// RH 20081113, set appropriate headers
		outTransport.setHeader("Pragma", "no-cache");
		outTransport.setHeader("Cache-Control", "no-cache, no-store");

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setOutboundSAMLMessage(logoutResponse);
		messageContext.setPeerEntityEndpoint(samlEndpoint);

		// 20090604, Bauke: moved RelayState setting from caller to here
		if (sRelayState != null) {
			messageContext.setRelayState(sRelayState);
		}

		BasicX509Credential credential = new BasicX509Credential();
		credential.setPrivateKey(privateKey);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);

		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(messageContext.getOutboundSAMLMessage());
		Node node = null;
		try {
			node = marshaller.marshall(messageContext.getOutboundSAMLMessage());
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, "Exception in marshalling of SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String msg = XMLHelper.prettyPrintXML(node);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "About to send:\n" + Auxiliary.obfuscate(msg, Auxiliary.REGEX_PATTERNS));

		// store it in de history
		SamlHistoryManager history = SamlHistoryManager.getHandle();
		history.put(logoutResponse.getID(), logoutResponse.getDOM());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Dom stored in history" );

//		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();	// RH, 20170815, o
		Saml20_RedirectEncoder encoder = new Saml20_RedirectEncoder();	// RH, 20170815, n
		try {
			encoder.encode(messageContext);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception in encoder.encode:" + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
}
