package org.aselect.server.request.handler.saml20.common;

import java.security.PrivateKey;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutRequest;
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

public class LogoutRequestSender
{

	private final static String MODULE = "LogoutRequestSender";

	private ASelectSystemLogger _systemLogger;

	private PrivateKey privateKey;

	public LogoutRequestSender() {
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = _configManager.getDefaultPrivateKey();
	}

	/**
	 * Sends a LogoutRequest
	 * 
	 * @param serviceProviderUrl
	 * @param user
	 * @param request
	 * @param response
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	public void sendLogoutRequest(String serviceProviderUrl, String issuerUrl, String user, HttpServletRequest request,
			HttpServletResponse response, String reason)
		throws ASelectException
	{
		String sMethod = "sendLogoutRequest()";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send LogoutRequest to: " + serviceProviderUrl);

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
		LogoutRequest logoutRequest = logoutRequestBuilder.buildLogoutRequest(serviceProviderUrl, user, issuerUrl,
				reason);

		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		// samlEndpoint.setBinding(HTTPPostEncoder.BINDING_URI);
		samlEndpoint.setLocation(serviceProviderUrl);
		String sAppUrl = request.getRequestURL().toString();
		samlEndpoint.setResponseLocation(sAppUrl);

//		HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response); // RH 20080529, o
		HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, serviceProviderUrl); // RH 20080529, n

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setOutboundSAMLMessage(logoutRequest);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setRelayState("relay");

		BasicX509Credential credential = new BasicX509Credential();

		credential.setPrivateKey(privateKey);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);

		MarshallerFactory factory = Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(messageContext.getOutboundSAMLMessage());
		Node node = null;
		try {
			node = marshaller.marshall(messageContext.getOutboundSAMLMessage());
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception marshalling SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String msg = XMLHelper.prettyPrintXML(node);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "About to send: " + msg);

		// store it in de history
		SamlHistoryManager history = SamlHistoryManager.getHandle();
		history.put(logoutRequest.getID(), logoutRequest.getDOM());

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		try {
			encoder.encode(messageContext);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

	}
}
