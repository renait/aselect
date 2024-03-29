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
import java.io.StringReader;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.PolyKeyUtil;
import org.aselect.server.log.ASelectAuthProofLogger;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.request.handler.xsaml20.SecurityLevel.SecurityLevelEntry;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.utils.AttributeSetter;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import nl.logius.resource.pp.PolyPseudoException;
import nl.logius.resource.pp.util.DecryptUtil;

/**
 * SAML2.0 AssertionConsumer for A-Select (Service Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 AssertionConsumer for the A-Select Server (Service Provider side).<br/>
 * HTTP GET containing the following items in the querystring<br/>
 * <ul>
 * <li><b>SAMLart</b> - The SAML2.0 artifact</li>
 * </ul>
 * The SAML2.0 artifact is resolved by the requesters ArtifactResolver. The resolved artifact contains a SAML2.0
 * Response which is futher handled by this A-Select server. <br>
 */
public class Xsaml20_AssertionConsumer extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_AssertionConsumer";
	private XMLObjectBuilderFactory _oBuilderFactory;
	private ASelectAuthenticationLogger _authenticationLogger;
	protected TGTManager _tgtManager;
	private String _sMyServerId;
	private String _sFederationUrl;
	private String _sRedirectUrl; // We use as Issuer in the send SAML message
	//private String _sRequestIssuer; // But it can be set explicitly
	private boolean signingRequired = false;	// not used?
	// Get from aselect.xml <applications require_signing="false | true">
	private boolean localityAddressRequired = false; // Do we need to verify localityAddress in the AuthnStatement
	
	private boolean includeSessionindexes = false;
//	 should the SessionIndex(es) be included in the saml request, to be included the must be present in the tgt 
//		and therefore previously been received in the assertion
//	 if null value is not specified in aselect.xml

	private boolean useBackchannelClientcertificate = false;

	// 20120712, Bauke: Store TGT in class variable to save on reads

	private boolean verifyArtifactResponseSignature = false;

	private boolean useNameIDAsAuthID = false;

	private boolean carryAuthProof = false;
	private boolean logAuthProof = false;
	
	//
	// Example configuration:
	// <handler id="saml20_assertionconsumer"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_AssertionConsumer"
	// target="/saml20_assertion.*" >
	// </handler>
	//
	/**
	 * Initializes the request handler by reading the configuration.
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";

		super.init(oServletConfig, oHandlerConfig);

		_oBuilderFactory = Configuration.getBuilderFactory();
		_sMyServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
		_sFederationUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "federation_url", false);
		// Issuer in the send SAML message
		_sRedirectUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
		// 20100315: Specific issuer (eHerkenning) different from redirect_url
		// 20100429: removed: _sRequestIssuer = ASelectConfigManager.getSimpleParam(oHandlerConfig, "issuer", false);

		String sLocalityAddressRequired = ASelectConfigManager.getSimpleParam(oHandlerConfig, "locality_address_required", false);
		if ("true".equalsIgnoreCase(sLocalityAddressRequired)) {
			setLocalityAddressRequired(true);
		}
		// RH, 20120201, sn
		String sIncludeSessionindexes = ASelectConfigManager.getSimpleParam(oHandlerConfig, "include_sessionindexes", false);
		if ("true".equalsIgnoreCase(sIncludeSessionindexes)) {
			setIncludeSessionindexes(true);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "include_sessionindexes: " + isIncludeSessionindexes());
		// RH, 20120201, en

		// RH, 20120322, sn
		String sUseBackChannelClientCertificate = ASelectConfigManager.getSimpleParam(oHandlerConfig, "use_backchannelclientcertificate", false);
//		if ("true".equalsIgnoreCase(sIncludeSessionindexes)) {		// RH, 20130923, o
		if ("true".equalsIgnoreCase(sUseBackChannelClientCertificate)) {		// RH, 20130923, n
			setUseBackchannelClientcertificate(true);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "use_backchannelclientcertificate: " + isUseBackchannelClientcertificate());
		// RH, 20120322, en

		// RH, 20121205, sn
		String sVerifyArtifactresponseSignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_artifactresponsesignature", false);
		if ("true".equalsIgnoreCase(sVerifyArtifactresponseSignature)) {
			setVerifyArtifactResponseSignature(true);
		}
		// RH, 20121205, en

		// RH, 20130923, sn
		String sUseNameIDAsAuthID = ASelectConfigManager.getSimpleParam(oHandlerConfig, "use_nameidasauthid", false);
		if ("true".equalsIgnoreCase(sUseNameIDAsAuthID)) {
			setUseNameIDAsAuthID(true);
		}
		// RH, 20130923, en
		
		// Because carrying and/or logging the quite large auth_proof may have some impact on resources we can enable/disable
		// RH, 20140327, sn
		String sCarryAuthProof = ASelectConfigManager.getSimpleParam(oHandlerConfig, "carry_auth_proof", false);
		if ("true".equalsIgnoreCase(sCarryAuthProof)) {
			setCarryAuthProof(true);
		}
		// RH, 20140327, en

		// RH, 20140327, sn
		String sLogAuthProof = ASelectConfigManager.getSimpleParam(oHandlerConfig, "log_auth_proof", false);
		if ("true".equalsIgnoreCase(sLogAuthProof)) {
			setLogAuthProof(true);
		}
		// RH, 20140327, en
		
		_tgtManager = TGTManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
	}

	/**
	 * Assertion consumer. <br>
	 * 
	 * @param servletRequest
	 *            HttpServletRequest.
	 * @param servletResponse
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             on failure
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "process";
		boolean checkAssertionSigning = false;
		Object samlResponseObject = null;
		String auth_proof = null;
//		PrintWriter pwOut = null;

		try {
			
//			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);
			PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			String sReceivedArtifact = servletRequest.getParameter("SAMLart");
			String sReceivedResponse = servletRequest.getParameter("SAMLResponse");
			String sRelayState = servletRequest.getParameter("RelayState");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact + " RelayState="+sRelayState);
			
			String sFederationUrl = _sFederationUrl; // default, remove later on, can be null
			if (sRelayState.startsWith("idp=")) {
				sFederationUrl = sRelayState.substring(4);
			}
			else {  // Could be Base64 encoded
				sRelayState = new String(Base64Codec.decode(sRelayState));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RelayState="+sRelayState);
				sFederationUrl = Utils.getParameterValueFromUrl(sRelayState, "idp");
			}
			if (!Utils.hasValue(sFederationUrl)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No idp value found in RelayState (or in <federation_url> config)");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			if (Utils.hasValue(sReceivedArtifact)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "FederationUrl="+sFederationUrl);
				// use metadata
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
//				String sASelectServerUrl = metadataManager.getLocation(sFederationUrl,	// RH, 20190325, o
				String sASelectServerUrl = metadataManager.getLocation(_sResourceGroup, sFederationUrl,	// RH, 20190325, n
						ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML2_SOAP11_BINDING_URI);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact Resolution at " + sASelectServerUrl);
	
				if (sASelectServerUrl == null) {
//					_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact NOT found");	// RH, 20210701, o
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Artifact Resolution Location NOT found for: " + _sResourceGroup + " / " + sFederationUrl);	// RH, 20210701, n
					throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
				}
	
				SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) _oBuilderFactory
						.getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
				Artifact artifact = artifactBuilder.buildObject();
				artifact.setArtifact(sReceivedArtifact);
	
				SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder = (SAMLObjectBuilder<ArtifactResolve>) _oBuilderFactory
						.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
				ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
	
				artifactResolve.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
				artifactResolve.setVersion(SAMLVersion.VERSION_20);
				artifactResolve.setIssueInstant(new DateTime());
	
				// We decided that the other side could retrieve public key from metadata
				// by looking up the issuer as an entityID in the metadata
				// So we MUST supply an Issuer (which otherwise would be optional (by SAML standards))
				SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
						.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
				Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
				
				// 20100312, Bauke: eHerkenning, no assertion issuer format:
				// assertionIssuer.setFormat(NameIDType.ENTITY);
				// 20100311, Bauke: added for eHerkenning: Specific issuer id, independent of the Url
//				PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);	// RH, 20190325, o
				PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sFederationUrl);	// RH, 20190325, n
				String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
				if (partnerData != null && partnerData.getLocalIssuer() != null)
					assertionIssuer.setValue(partnerData.getLocalIssuer());
				else
					assertionIssuer.setValue(_sRedirectUrl);
				artifactResolve.setIssuer(assertionIssuer);
				artifactResolve.setArtifact(artifact);
				
				// Do some logging for testing
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Sign the artifactResolve >======");
				boolean useSha256 = (specialSettings != null && specialSettings.contains("sha256"));
				
				//	RH, 20180528, sn
				if (partnerData != null) {
					// RH, 20180918, sn
					PartnerData.Crypto specificCrypto = partnerData.getCrypto();
					// RH, 20180918, en
//					artifactResolve = (ArtifactResolve)SamlTools.signSamlObject(artifactResolve, useSha256? "sha256": "sha1",
//							"true".equalsIgnoreCase(partnerData.getAddkeyname()), "true".equalsIgnoreCase(partnerData.getAddcertificate()) );	// RH, 20180918, o
					artifactResolve = (ArtifactResolve)SamlTools.signSamlObject(artifactResolve, useSha256? "sha256": "sha1",
							"true".equalsIgnoreCase(partnerData.getAddkeyname()), "true".equalsIgnoreCase(partnerData.getAddcertificate()), specificCrypto);	// RH, 20180918, n
				} else {
				//	RH, 20180528, en
//					artifactResolve = (ArtifactResolve)SamlTools.signSamlObject(artifactResolve, useSha256? "sha256": "sha1");	// RH, 20180918, o
					artifactResolve = (ArtifactResolve)SamlTools.signSamlObject(artifactResolve, useSha256? "sha256": "sha1", null);	// RH, 20180918, n
				}	//	RH, 20180528, n
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Signed the artifactResolve ======<");
	
				// Build the SOAP message
				SoapManager soapManager  = null;
				if (isUseBackchannelClientcertificate()) {
					soapManager = new SoapManager(getSslSocketFactory());
				} else {
					soapManager = new SoapManager();
				}
				Envelope envelope = soapManager.buildSOAPMessage(artifactResolve);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Marshall");
				Element envelopeElem = SamlTools.marshallMessage(envelope);
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "Writing SOAP message:\n"+ XMLHelper.nodeToString(envelopeElem));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Writing SOAP message:\n"+ Auxiliary.obfuscate(XMLHelper.nodeToString(envelopeElem), Auxiliary.REGEX_PATTERNS));
				// XMLHelper.prettyPrintXML(envelopeElem));
	
				// ------------ Send/Receive the SOAP message
				String sSamlResponse = soapManager.sendSOAP(XMLHelper.nodeToString(envelopeElem), sASelectServerUrl);  // x_AssertionConsumer_x
				//byte[] sSamlResponseAsBytes = sSamlResponse.getBytes();
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received response: "+sSamlResponse+" length=" + sSamlResponse.length());
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received response: "+Auxiliary.obfuscate(sSamlResponse)+" original length=" + sSamlResponse.length());
				
				// save original, but, for (internal) transport, encode base64 
				auth_proof = new String(org.apache.commons.codec.binary.Base64.encodeBase64(sSamlResponse.getBytes("UTF-8")));
				
//				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_systemLogger);
				dbFactory.setNamespaceAware(true);
				// dbFactory.setExpandEntityReferences(false);
				// dbFactory.setIgnoringComments(true);
				dbFactory.setIgnoringComments(true);	// By default the value of this is set to false
				DocumentBuilder builder = dbFactory.newDocumentBuilder();
	
				StringReader stringReader = new StringReader(sSamlResponse);
				InputSource inputSource = new InputSource(stringReader);
				Document docReceivedSoap = builder.parse(inputSource);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "parsed="+docReceivedSoap.toString());
				Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "getdoc="+elementReceivedSoap.toString());
	
				// Remove all SOAP elements
				Node eltArtifactResponse = SamlTools.getNode(elementReceivedSoap, "ArtifactResponse");
	
				// Unmarshall to the SAMLmessage
				UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResponse);
				ArtifactResponse artifactResponse = (ArtifactResponse) unmarshaller.unmarshall((Element) eltArtifactResponse);
				
				//////////////////////////////	RH, 20160216, sn
				// Get status
				if ( artifactResponse.getStatus() != null && artifactResponse.getStatus().getStatusCode() != null &&
						StatusCode.SUCCESS_URI.equals(artifactResponse.getStatus().getStatusCode().getValue()) ) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "ArtifactResponse Status="+artifactResponse.getStatus().getStatusCode().getValue());
				} else {
					// For now we do a warning
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "ArtifactResponse Status="+artifactResponse.getStatus().getStatusCode().getValue());
				}
				///////////////////////////////	RH, 20160216, en
				
				Issuer issuer = artifactResponse.getIssuer();
				String sIssuer = (issuer == null)? null: issuer.getValue();
				// If issuer is not present in the response, use sASelectServerUrl value retrieved from metadata
				// else use value from the response
				String artifactResponseIssuer = (sIssuer == null || "".equals(sIssuer))? sASelectServerUrl: sIssuer;
	
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do Assertion signature verification="+is_bVerifySignature());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do ArtifactResponse signature verification="+isVerifyArtifactResponseSignature());
//				if (is_bVerifySignature()) {	// RH, 20121205, o
				if (is_bVerifySignature() || isVerifyArtifactResponseSignature()) {	// RH, 20121205, n
					// Check signature of artifactResolve here
					// We get the public key from the metadata
					// Therefore we need a valid Issuer to lookup the entityID in the metadata
					// We get the metadataURL from aselect.xml so we consider this safe and authentic
					if (artifactResponseIssuer == null || "".equals(artifactResponseIssuer)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod,
								"For signature verification the received message must have an Issuer");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					
//					List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(artifactResponseIssuer);	// RH, 20181119, n	// RH, 20190325, o
					List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(_sResourceGroup, artifactResponseIssuer);	// RH, 20181119, n	// RH, 20190325, n
					if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181119, n
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
	
					if (SamlTools.checkSignature(artifactResponse, pkeys)) {	// RH, 20181119, n
						_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResponse was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResponse was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				samlResponseObject = artifactResponse.getMessage();
			}	
			else if (Utils.hasValue(sReceivedResponse)) {
				// Handle http-post, can be unsolicited POST as well
				// Could be Base64 encoded
				// RelayState should contain intended application resource URL
				sRelayState = new String(Base64Codec.decode(sRelayState));
				
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Received Response=" + Utils.firstPartOf(sReceivedResponse,40));	//	RH, 20130924, n
//				sReceivedResponse = new String(Base64Codec.decode(sReceivedResponse));	//	RH, 20130924, o
				auth_proof = sReceivedResponse;	// save original

				sReceivedResponse = new String(org.apache.commons.codec.binary.Base64.decodeBase64(sReceivedResponse.getBytes("UTF-8")));	//	RH, 20130924, n
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received Response after base64 decoding=" +
						Utils.firstPartOf(sReceivedResponse,600) + " RelayState="+sRelayState);	//	RH, 20130924, n
//				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_systemLogger);
				dbFactory.setNamespaceAware(true);
				// dbFactory.setExpandEntityReferences(false);
				// dbFactory.setIgnoringComments(true);
				dbFactory.setIgnoringComments(true);	//	By default the value of this is set to false
				DocumentBuilder builder = dbFactory.newDocumentBuilder();
	
				StringReader stringReader = new StringReader(sReceivedResponse);
				InputSource inputSource = new InputSource(stringReader);
				Document docReceived = builder.parse(inputSource);
				Node eltSAMLResponse = SamlTools.getNode(docReceived, "Response");
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Found node Response: " + eltSAMLResponse +((eltSAMLResponse==null)? " NULL": " ok"));
	
				// Unmarshall to the SAMLmessage
				UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller((Element)eltSAMLResponse);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Unmarshaller"+((unmarshaller==null)? " NULL": " ok"));
				samlResponseObject = (Response)unmarshaller.unmarshall((Element)eltSAMLResponse);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Unmarshalling done, VerifySignature="+is_bVerifySignature());

				// 20120308: Bauke added signature checking
				//   saml-profiles-2.0-os: The <Assertion> element(s) in the <Response> MUST be signed,
				//   if the HTTP POST binding is used, and MAY be signed if the HTTPArtifact binding is used.
				if (is_bVerifySignature())
					checkAssertionSigning = true;
				
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No Artifact and no Response found in the message.");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			///////
			// The object can either a Response (SSO case) or a StatusResponseType (SLO case)
			///////////////////////////////////////////////////////////////////////////
			if (samlResponseObject instanceof Response) {
				// SSO
				Response samlResponse = (Response) samlResponseObject;
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Processing Response=" + Auxiliary.obfuscate(XMLHelper.prettyPrintXML(samlResponse.getDOM()),
						Auxiliary.REGEX_PATTERNS));

				// RH, 20121205, sn
				MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do Response signature verification="+isVerifyResponseSignature());
				if (isVerifyResponseSignature()) {
					Issuer issuer = samlResponse.getIssuer();
					String sIssuer = (issuer == null)? null: issuer.getValue();
					// If issuer is not present in the response, use sASelectServerUrl value retrieved from metadata
					// else use value from the response
//					String responseIssuer = (sIssuer == null || "".equals(sIssuer))? sASelectServerUrl: sIssuer;
					String responseIssuer = (sIssuer == null || "".equals(sIssuer))? null: sIssuer;	// There must be an issuer for now
					// Check signature of artifactResolve here
					// We get the public key from the metadata
					// Therefore we need a valid Issuer to lookup the entityID in the metadata
					// We get the metadataURL from aselect.xml so we consider this safe and authentic
					if (responseIssuer == null || "".equals(responseIssuer)) {
				 		_systemLogger.log(Level.SEVERE, MODULE, sMethod, "For signature verification the received response must have an Issuer");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					
//					List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(responseIssuer);	// RH, 20181119, n	// RH, 20190325, o
					List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(_sResourceGroup, responseIssuer);	// RH, 20181119, n	// RH, 20190325, n
					if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181119, n
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
	
					if (SamlTools.checkSignature(samlResponse, pkeys)) {	// RH, 20181119, n
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Response was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Response was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				// RH, 20121205, en
				
				// Detect if this is a successful or an error Response		
				String sStatusCode = samlResponse.getStatus().getStatusCode().getValue();
				String sRemoteRid = samlResponse.getID();
				
				// 20100531, Bauke: Remove added timestamp to get our local RID
				String sLocalRid = samlResponse.getInResponseTo();
				int len = sLocalRid.length();
				if (len > 9)
					sLocalRid = sLocalRid.substring(0, len-9);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "RemoteRid="+sRemoteRid +" LocalRid="+sLocalRid + " StatusCode="+sStatusCode);
				_htSessionContext = _oSessionManager.getSessionContext(sLocalRid);
				if (_htSessionContext == null) {
//					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown session in response from cross aselect server");
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown session in response from remote server");
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
				
				if (sStatusCode.equals(StatusCode.SUCCESS_URI)) {
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Response was successful " + samlResponse.toString());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Response was successful, Destination: " + samlResponse.getDestination());
					// RH, 20190225, sn
					// Try Encrypted Assertion first
					Assertion samlAssertion = null;
					Assertion samlNameIDAssertion = null;	// RH, 20200213, n
/*			
*/
/*					
					List<EncryptedAssertion> encAsses = samlResponse.getEncryptedAssertions();
					if (encAsses != null && samlResponse.getEncryptedAssertions().size() > 0) { // For now we support either Encrypted or normal Assertions, not both
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Number of EncryptedAssertions found: " +  samlResponse.getEncryptedAssertions().size());
						EncryptedAssertion encAss = samlResponse.getEncryptedAssertions().get(0);	// We only support one
						samlAssertion = (Assertion) SamlTools.decryptSamlObject(encAss);
					} else {
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Number of Assertions found: " +  samlResponse.getAssertions().size());
						samlAssertion = samlResponse.getAssertions().get(0);
					}
					if (samlAssertion == null) {	// There should be at least one
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No (readable) Assertion present in Response");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
*/					
//					List<EncryptedAssertion> encAsses = samlResponse.getEncryptedAssertions();
					// RH, 20200121, sn
					List<Assertion> asses = new ArrayList<Assertion>();
					List <Object> responseList = new ArrayList<Object>();
					responseList.add(samlResponse);
					getNestedAssertions(responseList, asses);
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Total number of Assertions found: " +  asses.size());
					if (asses.size() == 0) {	// There should be at least one
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No (readable) Assertion present in Response");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					PartnerData fedPartnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sFederationUrl);	// RH, 20190325, o	// RH, 20200120, n

					// RH, 20200121, sn
					Pattern specificIssuer = null;
					if (fedPartnerData.getAssertionIssuerPattern() != null) {
						specificIssuer = fedPartnerData.getAssertionIssuerPattern();
					}
					// RH, 20200213, sn
					Pattern nameIDIssuer = null;
					if (fedPartnerData.getNameIDIssuerPattern() != null) {
						nameIDIssuer = fedPartnerData.getNameIDIssuerPattern();					}
					// RH, 20200213, sn

					// RH, 20200213, sn
					
					for (Assertion a : asses) {
						// for testing show all Issuers
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found Assertion Issuer:" + a.getIssuer().getValue());
						if (specificIssuer != null && specificIssuer.matcher(a.getIssuer().getValue()).matches()) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found Assertion Issuer match for pattern:" + specificIssuer);
							samlAssertion = a;
						}
						// RH, 20200213, sn
						if (nameIDIssuer != null && nameIDIssuer.matcher(a.getIssuer().getValue()).matches()) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found NameID Assertion Issuer match for pattern:" + specificIssuer);
							samlNameIDAssertion = a;
						}
						// RH, 20200213, sn
					}

					if (samlAssertion == null) samlAssertion = asses.get(0);	// For now/test get first like we used to
					// RH, 20200121, en
					
					// RH, 20190225, en
					// RH, 20190225, so
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "Number of Assertions found: " +  samlResponse.getAssertions().size());
//					Assertion samlAssertion = samlResponse.getAssertions().get(0);
					// RH, 20190225, eo
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Assertion ID=" +samlAssertion.getID());
					String sAssertIssuer = samlAssertion.getIssuer().getValue();
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Issuer=" +sAssertIssuer+" checkAssertionSigning="+checkAssertionSigning);
					
					// 20120308: Bauke added signature checking
//					if (checkAssertionSigning) {	// RH, 20121205, o
					if (checkAssertionSigning || isVerifyAssertionSignature()) {	// RH, 20121205, n
						// Check signature of artifactResolve here. We get the public key from the metadata
						// Therefore we need a valid Issuer to lookup the entityID in the metadata
						// We get the metadataURL from aselect.xml so we consider this safe and authentic
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Verify assertion signature, issuer="+sAssertIssuer);
						if (!Utils.hasValue(sAssertIssuer)) {
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No Issuer present in Assertion");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						
//						MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();	// RH, 20121205, n
//						List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(sAssertIssuer);	// RH, 20181119, n	// RH, 20190325, o
						List<PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(_sResourceGroup, sAssertIssuer);	// RH, 20181119, n	// RH, 20190325, n
						if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181119, n
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						if (!SamlTools.checkSignature(samlAssertion, pkeys)) {	// RH, 20181119, n
							_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Assertion was NOT signed OK");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Assertion was signed OK");
						
						// RH, 20200213, sn
						if (samlNameIDAssertion != null) {
							_systemLogger.log(Level.FINE, MODULE, sMethod, "NameID Assertion ID=" +samlNameIDAssertion.getID());
							String sNameIDAssertIssuer = samlNameIDAssertion.getIssuer().getValue();
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Verify nameid assertion signature, issuer="+sNameIDAssertIssuer);
							if (!Utils.hasValue(sNameIDAssertIssuer)) {
								_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No Issuer present in NameID Assertion");
								throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
							}
							
							if (!SamlTools.checkSignature(samlNameIDAssertion, pkeys)) {	// RH, 20181119, n
								_systemLogger.log(Level.SEVERE, MODULE, sMethod, "NameID Assertion was NOT signed OK");
								throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
							}
							_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID Assertion was signed OK");
						} else {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "No NameID Assertion found, continuing");
						}
						// RH, 20200213, sn
					}
					// 20120308
					
					//	RH, 20160216, sn
					// Might be an encrypted NameID 
					String sNameID = null;
					String sNameIDQualifier = null;
					// RH, 20200213, sn
					Subject subject = null;
					if (samlNameIDAssertion != null) {
						subject = samlNameIDAssertion.getSubject();
					} else {
						subject = samlAssertion.getSubject();	// like we used to
					}
					// RH, 20200213, sn
//					Subject subject = samlAssertion.getSubject();	// RH, 20200213, o

					NameID nameid = null;

					// Maybe EncryptedID
					// Do decryption here
					EncryptedID encryptedid = subject.getEncryptedID();
					if (encryptedid != null) {
						String sEncryptedID = XMLHelper.nodeToString(encryptedid.getDOM());
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found EncryptedID:" + sEncryptedID);
						// Try to get the NameID
 
						
//						SAMLObject decryptedObject = SamlTools.decryptSamlObject(encryptedid);	// 20201210, RH, o
	                   	// 20201210, RH, sn
                    	// We'd like decryption with specific key for this partner here
						//If we found a samlNameIDAssertion we should also use that specific Issuer resource
						String issuer = (samlNameIDAssertion != null ? samlNameIDAssertion : samlAssertion).getIssuer().getValue();
						_systemLogger.log(Level.FINE, MODULE, sMethod, "Using (specific) Issuer resourcedata to retrieve NameID: " + _sResourceGroup + " / " + issuer);
						PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, issuer);
						SAMLObject decryptedObject = SamlTools.decryptSamlObject(encryptedid, (partnerData != null) ? partnerData.getCrypto() : null);
                    	// 20201210, RH, en
						
//						if ( decryptedObject != null ) {
//							String sDecryptedID = Auxiliary.obfuscate(XMLHelper.nodeToString(decryptedObject.getDOM()));
//							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Decrypted ID:" + sDecryptedID);
//						}
						nameid = (NameID) decryptedObject;	// Should be a NameID Element
					} else { // should contain nameid
						nameid = subject.getNameID();
					}
					
//					String sNameID = samlAssertion.getSubject().getNameID().getValue();	// RH, 20160216, o
					if  ( nameid != null ) {
						sNameID = nameid.getValue();
						_systemLogger.log(Level.FINE, MODULE, sMethod, "NameID:" + Auxiliary.obfuscate(sNameID));
						sNameIDQualifier = nameid.getNameQualifier();
						_systemLogger.log(Level.FINE, MODULE, sMethod, "NameIDQualifier:" + sNameIDQualifier);
						// RH, 20181030, sn
						if ("urn:etoegang:1.12:EntityConcernedID:BSN".equals(sNameIDQualifier)) {	// polymorf Identity
							_systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypting:" + "urn:etoegang:1.12:EntityConcernedID:BSN");
							Issuer issuer = samlResponse.getIssuer();
							String sIssuer = (issuer == null)? null: issuer.getValue();
							if (sIssuer != null) {
//								PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sIssuer);	// RH, 20190325, o
								_systemLogger.log(Level.FINE, MODULE, sMethod, "Retreiving resourcedata to retrieve Polymorf IPoint using (specific) Issuer:" + _sResourceGroup + " / " + issuer);	// RH, 20201210, n
								PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sIssuer);	// RH, 20190325, n
								if (partnerData != null) {
									PolyKeyUtil keys = new PolyKeyUtil(partnerData.getId_keylocation(), partnerData.getI_point(), null, null, null); 
									if (keys.getDecryptKey() != null) {	// loading of keys went well
										try {
											sNameID = DecryptUtil.getIdentity(sNameID,keys.getDecryptKey(), keys.getVerifiers());
										} catch (PolyPseudoException pex) {
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error polymorf decrypting: " + pex.getMessage());
										}
									} else {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no polymorf decryption done");
									}
								} else {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no partnerdata for Issuer, no polymorf decryption done");
								}
							} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no issuer in Response, no polymorf decryption done");
							}
						} else if ("urn:etoegang:1.12:EntityConcernedID:PseudoID".equals(sNameIDQualifier)) {	// polymorf Pseudonym
							_systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypting:" + "urn:etoegang:1.12:EntityConcernedID:PseudoID");
							Issuer issuer = samlResponse.getIssuer();
							String sIssuer = (issuer == null)? null: issuer.getValue();
							if (sIssuer != null) {
//								PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sIssuer);	// RH, 20190325, o
								_systemLogger.log(Level.FINE, MODULE, sMethod, "Retreiving resourcedata to retrieve Polymorf ClosingKey using (specific) Issuer:" + _sResourceGroup + " / " + issuer);	// RH, 20201210, n
								PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sIssuer);	// RH, 20190325, n
								if (partnerData != null) {
									PolyKeyUtil keys = new PolyKeyUtil(null, null, partnerData.getPd_keylocation(), partnerData.getPc_keylocation(), partnerData.getP_point()); 
									if (keys.getPDecryptKey() != null && keys.getPClosingKey() != null) {	// loading of keys went well
										try {
											sNameID = DecryptUtil.getPseudonym(sNameID, keys.getPDecryptKey(), keys.getPClosingKey(), keys.getPVerifiers());
										} catch (PolyPseudoException pex) {
											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error polymorf decrypting: " + pex.getMessage());
										}
									} else {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no polymorf decryption done");
									}
								} else {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no partnerdata for Issuer, no polymorf decryption done");
								}
							} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no issuer in Response, no polymorf decryption done");
							}
						}
						// RH, 20181030, sn
							
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "No NameID found:");
						sNameID = "";
					}
					//	RH, 20160216, en

					// Now check for time interval validation
					// We only check first object from the list
					// First the assertion itself
					if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(samlAssertion)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Assertion time interval was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					// then the AuthnStatement
					if (is_bVerifyInterval()
							&& !SamlTools.checkValidityInterval(samlAssertion.getAuthnStatements().get(0))) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnStatement time interval was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					// check subjectlocalityaddress
					// we check subjectlocalityaddress of samlAssertion not of samlNameIDAssertion	// RH, 20200213, n
					if (isLocalityAddressRequired()
							&& !SamlTools.checkLocalityAddress(samlAssertion.getAuthnStatements().get(0), servletRequest.getRemoteAddr())) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnStatement subjectlocalityaddress was NOT valid");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					
					// Get the (option) sessionindex from remote
					String sSessionindex = samlAssertion.getAuthnStatements().get(0).getSessionIndex();
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Sessionindex:" + sSessionindex);
					
					AuthnContext oAuthnContext = samlAssertion.getAuthnStatements().get(0).getAuthnContext();
					List<AuthenticatingAuthority> authAuthorities = oAuthnContext.getAuthenticatingAuthorities();
					String sAuthnAuthority = null;
					if (authAuthorities != null && authAuthorities.size() > 0)
						sAuthnAuthority = (String)authAuthorities.get(0).getURI();
					
//					String sAuthnContextClassRefURI = oAuthnContext.getAuthnContextClassRef().getAuthnContextClassRef();	// RH, 20160405, o
					// RH, 20160405, sn
//					PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);	// RH, 20190325, o
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Retreiving resourcedata using (specific) FederationUrl:" + _sResourceGroup + " / " + sFederationUrl);	// RH, 20201210, n
					PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sFederationUrl);	// RH, 20190325, o
					// RH, 20180810, sn, Moved this up a bit
					String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
					boolean useLoa = (specialSettings != null && specialSettings.contains("use_loa"));
					_systemLogger.log(Level.FINER, MODULE, sMethod, "useLoa="+useLoa);
					boolean useNewLoa = (specialSettings != null && specialSettings.contains("use_newloa"));
					_systemLogger.log(Level.FINER, MODULE, sMethod, "useNewLoa="+useNewLoa);
					// RH, 20180810, en, Moved this up a bit
					SecurityLevelEntry[] compLevels = SecurityLevel.getDefaultLevels();
					if (partnerData != null && partnerData.getSecurityLevels() != null) {
						compLevels = partnerData.getSecurityLevels();
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Using custom Security Levels: " + Arrays.deepToString(compLevels));
					} else if (useNewLoa) {
						compLevels = SecurityLevel.getNewLoaLevels();
					}
					String sAuthnContextClassRefURI = null;
					AuthnContextClassRef accr = oAuthnContext.getAuthnContextClassRef();
					if (accr != null) {
						 sAuthnContextClassRefURI =accr.getAuthnContextClassRef();
					} else {
						if ( partnerData != null && partnerData.getExtensionsdata4partner() != null && partnerData.getExtensionsdata4partner() .getQualityAuthenticationAssuranceLevel() != null) {
							String loaLevel = SecurityLevel.stork2loa(partnerData.getExtensionsdata4partner() .getQualityAuthenticationAssuranceLevel());	// use level from config
							if (useNewLoa) {
								String sLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(loaLevel, true, SecurityLevel.getNewLoaLevels(), _systemLogger);
								sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sLevel, false, SecurityLevel.getNewLoaLevels(), _systemLogger);
							} else {
								String sLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(loaLevel, true, SecurityLevel.getDefaultLevels(), _systemLogger);
								sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sLevel, false, SecurityLevel.getDefaultLevels(), _systemLogger);
							}
							_systemLogger.log(Level.FINE, MODULE, sMethod, "No AuthnContextClassRef found, using from config :" + sAuthnContextClassRefURI);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "No AuthnContextClassRef found and no default specified");
						}
					}
					// RH, 20160405, en
					
					_systemLogger.log(Level.FINE, MODULE, sMethod, "AuthnContextClassRefURI=" +sAuthnContextClassRefURI);
					
					/////////////////////////	digid4	///////////////////////////////////////////
					/// Digid4 still has to decide how to provide a "face2face" declaration 
					//	String sAuthnContextDeclRefIssueMethod = samlAssertion.getAuthnStatements().get(0).getAuthnContext().
					/////////////////////////	digid4	///////////////////////////////////////////
					
//					PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);	// RH, 20160405, o
					// RH, 20180810, so, Moved this up a bit
//					String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
//					boolean useLoa = (specialSettings != null && specialSettings.contains("use_loa"));
//					_systemLogger.log(Level.FINER, MODULE, sMethod, "useLoa="+useLoa);
//					boolean useNewLoa = (specialSettings != null && specialSettings.contains("use_newloa"));
//					_systemLogger.log(Level.FINER, MODULE, sMethod, "useNewLoa="+useNewLoa);
					// RH, 20180810, eo, Moved this up a bit
					String sSelectedLevel = null;
					sSelectedLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI, useLoa, compLevels, _systemLogger);
//	RH, 20180813, so					
//					if (useNewLoa) {	// fix for new loa levels 
//						sSelectedLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI, useLoa, SecurityLevel.getNewLoaLevels(), _systemLogger);
//					} else {
//						sSelectedLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sAuthnContextClassRefURI, useLoa, SecurityLevel.getDefaultLevels(), _systemLogger);
//					}
//	RH, 20180813, eo						
					
					// Check returned security level
					Integer intAppLevel = (Integer) _htSessionContext.get("level");
					if (Integer.parseInt(sSelectedLevel) < intAppLevel) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Security level returned ("+
										sSelectedLevel+") must be at least: "+intAppLevel);
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}

					// Retrieve the embedded attributes
					HashMap hmSamlAttributes = new HashMap();
					String sEncodedAttributes = null;
					List<AttributeStatement> lAttrStatList = samlAssertion.getAttributeStatements();
					if (lAttrStatList != null) {
						Iterator<AttributeStatement> iASList = lAttrStatList.iterator();
						while (iASList.hasNext()) {
							AttributeStatement sAttr = iASList.next();
	
							// First decrypt if there are any EncryptedAttributes
//							if (sAttr.getEncryptedAttributes() != null) {	// RH, 20180910, o
							if (sAttr.getEncryptedAttributes() != null && sAttr.getEncryptedAttributes().size() > 0) {	// RH, 20180910, n
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "Start decrypting " + sAttr.getEncryptedAttributes().size() + " attributes");
								Iterator<EncryptedAttribute> encryptAttrIt = sAttr.getEncryptedAttributes().iterator();
								while (encryptAttrIt.hasNext()) {
									final EncryptedAttribute encryptedAttribute = encryptAttrIt.next();
									// For every encrypted attribute
//									final Attribute attribute = (Attribute) SamlTools.decryptSamlObject(encryptedAttribute);	// RH, 20201210, o
	                            	// 20201210, RH, sn
	                            	// We'd like decryption with specific key for this partner here
									final Attribute attribute = (Attribute) SamlTools.decryptSamlObject(encryptedAttribute, (partnerData != null) ? partnerData.getCrypto() : null);
	                            	// 20201210, RH, en
									if ( attribute != null ) {
									// (re)Inject the Attribute in the assertion
										sAttr.getAttributes().add(attribute);
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "Decrypted attribute "+ attribute.getName());
									} else {
										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to decrypted attribute");
									}
								}
							} else {
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "No fully encrypted attribute(s) found, continuing...");
							}
							
							// Then get all attributes
							List<Attribute> lAttr = sAttr.getAttributes();
							Iterator<Attribute> iAttr = lAttr.iterator();
							while (iAttr.hasNext()) {
								Attribute attr = iAttr.next();
//								_systemLogger.log(Level.FINEST, MODULE, sMethod, "Next attr as xml:\n"  + 
//										XMLHelper.prettyPrintXML(attr.getDOM()));
								String sAttrName = attr.getName();
								
//								String sAttrValue = null;// RH, 20120124, sn	// RH, 20180910, o
								Vector sAttrValue = null;// RH, 20120124, sn	// RH, 20180910, n	// Vector for legacy
								List <XMLObject> aValues = attr.getAttributeValues();
//								if ( aValues != null && aValues.size() == 1 ) {	// For now we only allow single valued simple type xs:string attributes	// RH, 20180910, o
								// looks like if there are no values, getAttributeValues() returns empty list, not null
								if ( aValues != null ) {	// Also allow for multi-valued simple type xs:string attributes	// RH, 20180910, n
										sAttrValue = new Vector();	// at least one value
										for (XMLObject xmlObj : aValues) {	// RH, 20180910, n
		                 //           XMLObject xmlObj = aValues.get(0);	// RH, 20180910, o
	//								XSStringImpl xsString = (XSStringImpl) attr.getOrderedChildren().get(0);// RH, 20120124, so
	//								String sAttrValue = xsString.getValue();// RH, 20120124, o
	//								sAttrValue = xsString.getValue();// RH, 20120124, eo
//	    							String sValue = Auxiliary.obfuscate(XMLHelper.nodeToString(xmlObj.getDOM()));
//	    							_systemLogger.log(Level.FINEST, MODULE, sMethod, "sValue:" + sValue);
	//    							String sChild = Auxiliary.obfuscate(XMLHelper.nodeToString(xmlObj.getDOM().getFirstChild()));
	    							EncryptedID eID = null;
//	    							if (xmlObj.getOrderedChildren() != null && !xmlObj.getOrderedChildren().isEmpty()) {	// RH, 20180620, o
	    							if (xmlObj != null && xmlObj.getOrderedChildren() != null && !xmlObj.getOrderedChildren().isEmpty()) {	// RH, 20180620, n
	//        							String sChild = Auxiliary.obfuscate(XMLHelper.nodeToString(xmlObj.getOrderedChildren().get(0).getDOM()));
	//        							_systemLogger.log(Level.FINEST, MODULE, sMethod, "sChild:" + sChild);
	//        							String sLocalName = xmlObj.getDOM().getFirstChild().getLocalName();
	        							String sLocalName = xmlObj.getOrderedChildren().get(0).getDOM().getLocalName();
	        							_systemLogger.log(Level.FINEST, MODULE, sMethod, "sLocalName:" + sLocalName);
	        							if ("EncryptedID".equals(sLocalName)) {
	        								eID = (EncryptedID)xmlObj.getOrderedChildren().get(0);
	        	                            if ( eID != null) {
//	        	                            	final SAMLObject attributevalue = SamlTools.decryptSamlObject(eID);	// RH, 20201210, o
	        	                            	// 20201210, RH, sn
	        	                            	// We'd like decryption with specific key for this partner here
	        	                            	final SAMLObject attributevalue = SamlTools.decryptSamlObject(eID, (partnerData != null) ? partnerData.getCrypto() : null);
	        	                            	// 20201210, RH, en
	        	                            	// RH, 20201218, sn
	        	                            	// TESTING //
	          		                            xmlObj = attributevalue;
	          		                            String sattributevaluesNameID = null;
	           	                            	if (attributevalue != null) {
	        	                            		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Processing EncryptedID=" + Auxiliary.obfuscate(XMLHelper.prettyPrintXML(attributevalue.getDOM()),
	        	                						Auxiliary.REGEX_PATTERNS));
		        	                            	// This can be a NameID with NameQualifier object
//	        	        							String attributevaluesLocalName = attributevalue.getOrderedChildren().get(0).getDOM().getLocalName();
	        	        							String attributevaluesLocalName = attributevalue.getDOM().getLocalName();
	        	        							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found attributevalue LocalName:" + attributevaluesLocalName);
		        	                            	if ("NameID".equals(attributevaluesLocalName)) {
		        	                					NameID attributevalueameid = (NameID) attributevalue;	// Should be a NameID Element
		        	                					// start polymorf decryption
		        	                					if  ( attributevalueameid != null ) {
		        	                						sattributevaluesNameID = attributevalueameid.getValue();
		        	                						_systemLogger.log(Level.FINE, MODULE, sMethod, "attributevalue NameID:" + Auxiliary.obfuscate(sattributevaluesNameID));
		        	                						String sattributevaluesNameIDQualifier = attributevalueameid.getNameQualifier();
		        	                						_systemLogger.log(Level.FINE, MODULE, sMethod, "attributevalue NameIDQualifier:" + sattributevaluesNameIDQualifier);
		        	                						
		        	                						if ("urn:etoegang:1.12:EntityConcernedID:BSN".equals(sattributevaluesNameIDQualifier)) {	// polymorf Identity
		        	                							_systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypting:" + "urn:etoegang:1.12:EntityConcernedID:BSN");
		        	                							// we should get the Assertion issuer here, for now TESTING they're the same
		        	                							Issuer issuer = samlResponse.getIssuer();
		        	                							String sIssuer = (issuer == null)? null: issuer.getValue();
		        	                							if (sIssuer != null) {
		        	                								_systemLogger.log(Level.FINE, MODULE, sMethod, "Retreiving resourcedata to retreive Polymorf IPoint using (specific) Issuer:" + _sResourceGroup + " / " + ((issuer != null) ? issuer.getValue(): null) );	// RH, 20201210, n
		        	                								PartnerData localpartnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sIssuer);	// RH, 20190325, n
		        	                								if (localpartnerData != null) {
//		        	                									PolyKeyUtil keys = new PolyKeyUtil(localpartnerData.getId_keylocation(), localpartnerData.getI_point(), null, null, null); 
		        	                									PolyKeyUtil keys = new PolyKeyUtil(localpartnerData.getId_keylocation(), localpartnerData.getI_point(), null, null, null,
		        	                									(localpartnerData.getCrypto() != null ? localpartnerData.getCrypto().getPrivateKey() : null)); 
		        	                									if (keys.getDecryptKey() != null) {	// loading of keys went well
		        	                										try {
		        	                											sattributevaluesNameID = DecryptUtil.getIdentity(sattributevaluesNameID,keys.getDecryptKey(), keys.getVerifiers());
		        	                										} catch (PolyPseudoException pex) {
		        	                											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error polymorf decrypting: " + pex.getMessage());
		        	                										}
		        	                									} else {
		        	                										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no polymorf decryption done");
		        	                									}
		        	                								} else {
		        	                									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no partnerdata for Issuer, no polymorf decryption done");
		        	                								}
		        	                							} else {
		        	                								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no issuer in Response, no polymorf decryption done");
		        	                							}
		        	                						} else if ("urn:etoegang:1.12:EntityConcernedID:PseudoID".equals(sattributevaluesNameIDQualifier)) {	// polymorf Pseudonym
		        	                							_systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypting:" + "urn:etoegang:1.12:EntityConcernedID:PseudoID");
		        	                							Issuer issuer = samlResponse.getIssuer();
		        	                							String sIssuer = (issuer == null)? null: issuer.getValue();
		        	                							if (sIssuer != null) {
//		        	                								PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sIssuer);	// RH, 20190325, o
		        	                								_systemLogger.log(Level.FINE, MODULE, sMethod, "Retreiving resourcedata to retreive Polymorf ClosingKey using (specific) Issuer:" + _sResourceGroup + " / " + ((issuer != null) ? issuer.getValue(): null) );	// RH, 20201210, n
		        	                								PartnerData localpartnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sIssuer);	// RH, 20190325, n
		        	                								if (localpartnerData != null) {
		        	                									
//		        	                									PolyKeyUtil keys = new PolyKeyUtil(null, null, localpartnerData.getPd_keylocation(), localpartnerData.getPc_keylocation(), localpartnerData.getP_point()); 
		        	                									PolyKeyUtil keys = new PolyKeyUtil(null, null, localpartnerData.getPd_keylocation(), localpartnerData.getPc_keylocation(), localpartnerData.getP_point(), 
		        	                											(localpartnerData.getCrypto() != null ? localpartnerData.getCrypto().getPrivateKey() : null)); 
		        	                									if (keys.getPDecryptKey() != null && keys.getPClosingKey() != null) {	// loading of keys went well
		        	                										try {
		        	                											sattributevaluesNameID = DecryptUtil.getPseudonym(sattributevaluesNameID, keys.getPDecryptKey(), keys.getPClosingKey(), keys.getPVerifiers());
		        	                										} catch (PolyPseudoException pex) {
		        	                											_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error polymorf decrypting: " + pex.getMessage());
		        	                										}
		        	                									} else {
		        	                										_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no polymorf decryption done");
		        	                									}
		        	                								} else {
		        	                									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no partnerdata for Issuer, no polymorf decryption done");
		        	                								}
		        	                							} else {
		        	                								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load necessary key(s), no issuer in Response, no polymorf decryption done");
		        	                							}
		        	                						}
		        	                					}
		        	                					if (sattributevaluesNameID != null) { 
		        	                						sAttrValue.add(sattributevaluesNameID);
		        	                						xmlObj = null; 	// so we will not add it twice
		        	                					} else {
        	                								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute value null after decrypting, not added");		        	                					}
		        	                            	} else {	// like we used to
		        	        							_systemLogger.log(Level.FINEST, MODULE, sMethod, "LocalName not NameID, no polymorf decryption done");
		        	                            	}
	        	                            	} else {
		        									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decrypt EcnryptedID");
	        	                            	}
	        	                            	// RH, 20201218, en
	//        	    							_systemLogger.log(Level.FINEST, MODULE, sMethod, "attributevalue decrypted");
//	        	    							String sDecryptedValue = Auxiliary.obfuscate(XMLHelper.nodeToString(attributevalue.getDOM()));
//	        	    							_systemLogger.log(Level.FINEST, MODULE, sMethod, "sDecryptedValue:" + sDecryptedValue);
	      //  		                            xmlObj = attributevalue;	// RH, 20201218, o
	        	                            } else {
	        									_systemLogger.log(Level.WARNING, MODULE, sMethod, "AtrributeValue not an instance of EncryptedElementType");
	        	                            }
	        							}
	    							}
	    							if (xmlObj != null && xmlObj.getDOM().getFirstChild() != null) {
//	    								sAttrValue = xmlObj.getDOM().getFirstChild().getTextContent();	// RH, 20180910, o
	    								sAttrValue.add(xmlObj.getDOM().getFirstChild().getTextContent());	// RH, 20180910, n
	//									_systemLogger.log(Level.INFO, MODULE, sMethod, "Name=" + sAttrName + " Value=" + sAttrValue);
	    								_systemLogger.log(Level.INFO, MODULE, sMethod, "Name=" + sAttrName + " Value=" + Auxiliary.obfuscate(xmlObj.getDOM().getFirstChild().getTextContent()));	// RH, 20180910, n
	    							}
//    								_systemLogger.log(Level.INFO, MODULE, sMethod, "Name=" + sAttrName + " Value=" + Auxiliary.obfuscate(sAttrValue));	// RH, 20180910, o
										}
								}
								else {
//									_systemLogger.log(Level.INFO, MODULE, sMethod, "Only single valued attributes allowed, skipped attribute Name=" + sAttrName);	// RH, 20180910, o
									// maybe allow for empty valued attributes
									_systemLogger.log(Level.INFO, MODULE, sMethod, "No values found for attribute Name=" + sAttrName);	// RH, 20180910, n
								}	// RH, 20120124, en
								if ("attributes".equals(sAttrName))
//									sEncodedAttributes = sAttrValue;	// RH, 20180910, o
									sEncodedAttributes = (String)sAttrValue.firstElement();	// RH, 20180910, n	// should be single-valued string
								else {
//									hmSamlAttributes.put(sAttrName, sAttrValue);	// RH, 20180910, o
									// RH, 20180910, sn
									// For legacy reasons we do not want all attributes to be Vectors
									if (sAttrValue != null && sAttrValue.size() == 1) {
										hmSamlAttributes.put(sAttrName, sAttrValue.firstElement());	// Single valued used to be String 
									} else {
										hmSamlAttributes.put(sAttrName, sAttrValue);
									}
									// RH, 20180910, en
								}
							}
						}
					}
					
					// Since the "attributes" Attribute is used for gathering, add the Saml Attributes to it
//					HashMap<String, String> hmAttributes;	// RH,20180910, o
					HashMap<String, Object> hmAttributes;	// RH,20180910, n // deserializing might contain Vector
					if (sEncodedAttributes != null) {
						hmAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sEncodedAttributes);
					}
					else {
//						hmAttributes = new HashMap<String, String>();	// RH,20180910, o
						hmAttributes = new HashMap<String, Object>();	// RH,20180910, n
					}
					// Add the serialized attributes and a few specials
					hmSamlAttributes.putAll(hmAttributes);
					hmSamlAttributes.put("name_id", sNameID);  // "sel_level" was already set by the IdP
					if (sAuthnAuthority != null)
						hmSamlAttributes.put("authority", sAuthnAuthority);

					// eHerkenning addition: OrgID = KvKnummer+Vestigingsnummer
					// If EntityConcernedID = 00000003123456780000 and EntityConcernedSubID = ...0001,
					// then orgid = 1234567800000001
//					String sEntityId = (String)hmSamlAttributes.get("urn:nl:eherkenning:0.8def:EntityConcernedID");
					// RH, 20110523, add support for other versions of eHerk
					String sEntityId = null;

					Pattern p = Pattern.compile("urn:nl:eherkenning:(.*):EntityConcernedID");

					Set<String> keys = hmSamlAttributes.keySet();
					Iterator keyIter = keys.iterator();
					String eHerkversion = null;
					while (keyIter.hasNext()) {
						Matcher m = p.matcher((String)keyIter.next());
						if (m.find())  {
							sEntityId = (String)hmSamlAttributes.get(m.group());
							eHerkversion = m.group(1);
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found sEntityId=" + sEntityId + " eHerkversion=" + eHerkversion);
							break;	// just take the first we find
						}
					}
						
					if (sEntityId != null) {
						int idx = sEntityId.length()-12;  // last 12 characters
						if (idx > 0) sEntityId = sEntityId.substring(idx);
						
//						String sEntitySubId = (String)hmSamlAttributes.get("urn:nl:eherkenning:0.8def:EntityConcernedSubID");
						String sEntitySubId = (String)hmSamlAttributes.get("urn:nl:eherkenning:" + eHerkversion + ":EntityConcernedSubID");
						if (sEntitySubId != null) {
							_systemLogger.log(Level.INFO, MODULE, sMethod, "Found sEntitySubId=" + sEntitySubId);							
							idx = sEntitySubId.length()-12;  // last 12 characters to be on the safe side
							if (idx > 0) sEntitySubId = sEntitySubId.substring(idx);
							sEntityId = sEntitySubId;
						}
						else {  // ditch the last 4 zeroes
							idx = sEntityId.length()-4;
							if (idx > 0)
								sEntityId = sEntityId.substring(0, idx);
						}
						hmSamlAttributes.put("orgid", sEntityId);
					}
					
					// eHerkenning: AuthID = Unique Persistent Identifier
					if ( isUseNameIDAsAuthID() ) {		// RH, 20130923, sn
						hmSamlAttributes.put("authid", sNameID);
					} else {	// RH, 20130923, en
					// Use the fifth word from sAuthnAuthority (split using :) and add sNameID
						if (sNameIDQualifier != null) {
							String sAuthID = "", sAuthSubID = "";
							String[] tokens = sNameIDQualifier.split(":");
							if (tokens.length > 4)
								sAuthID = tokens[4];
	
	//						if (tokens.length > 5)
	//							sAuthSubID = tokens[5];
							// Test  new layout of eherkenning
							// Maybe do something with pattern search here
							if (tokens.length > 6)
								sAuthSubID = tokens[6];
							
							sAuthID += "_"+sAuthSubID+"_"+sNameID;  // add separator
							hmSamlAttributes.put("authid", sAuthID);
						}
					}	// RH, 20130923, n
					
					if ( isCarryAuthProof() ) { // Put the original authentication proof in hmSamlAttributes before serialization in attributes
															// so they will be available for gatherer
						hmSamlAttributes.put("auth_proof", auth_proof); // original response, still base64 encoded
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "auth_proof=" + auth_proof);
					}

					//	RH, 20160301, sn
					// Do attribute processing
					if (attributeSetters != null && attributeSetters.size() > 0) {
						Map newAttr = AttributeSetter.attributeProcessing(new HashMap(), hmSamlAttributes, attributeSetters, _systemLogger);
						hmSamlAttributes.putAll(newAttr);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "htRemoteAttributes after attributesetting=" + Auxiliary.obfuscate(hmSamlAttributes));
					}
					//	RH, 20160301, en
					
					// And serialize them back to where they came from
					sEncodedAttributes = org.aselect.server.utils.Utils.serializeAttributes(hmSamlAttributes);
					hmSamlAttributes.put("attributes", sEncodedAttributes);
					
					if ( !isCarryAuthProof() && isLogAuthProof() ) { // Put the original authentication proof in hmSamlAttributes only temporarily to be removed later
													// if isCarryAuthProof() true they were already there
						hmSamlAttributes.put("auth_proof", auth_proof); // original response, still base64 encoded
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "auth_proof=" + auth_proof);
					}
					// This is the quickest way to get "name_id" into the Context
					hmSamlAttributes.put("name_id", sNameID);  // also as plain attribute
					
					///////////// Digid4	//////////////////////////////
					// must be made configurable and parameterized, still looking for some reference to identify the service (maybe issuer) 
					String[] splittedNameId = sNameID.split(":");
					if ( splittedNameId.length == 2 && splittedNameId[0].toUpperCase().startsWith("S") && splittedNameId[0].length() == 9 )	{		// for now this identifies as digid4
						hmSamlAttributes.put("uid", splittedNameId[1]);
						// add special attributes for digid4
						if ( "S00000000".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("bsn", splittedNameId[1]);
							
						} else if ( "S00000001".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("sofi", splittedNameId[1]);
							
						} else if ( "S00000002".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("anummer", splittedNameId[1]);

						} else if ( "S00000100".equalsIgnoreCase(splittedNameId[0]) ) {
							hmSamlAttributes.put("oeb", splittedNameId[1]);
						}
					}
					/////////////////////////////////////////////////////
					
					// 20100422, Bauke: no uid, then use NameID
					String sUid = (String)hmSamlAttributes.get("uid");
					if (sUid == null || sUid.equals(""))
						hmSamlAttributes.put("uid", sNameID);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID=" + Auxiliary.obfuscate(sNameID) + " remote_rid=" + sRemoteRid
							+ " local_rid=" + sLocalRid + " sel_level=" + sSelectedLevel + " organization/authsp="
							+ sAssertIssuer);

					// htRemoteAttributes.put("attributes", HandlerTools.serializeAttributes(htAttributes));
					hmSamlAttributes.put("remote_rid", sRemoteRid);
					hmSamlAttributes.put("local_rid", sLocalRid);

					hmSamlAttributes.put("sel_level", sSelectedLevel);
					hmSamlAttributes.put("authsp_level", sSelectedLevel);  // default value, issueTGT will correct this
					hmSamlAttributes.put("organization", sAssertIssuer);
					hmSamlAttributes.put("authsp", sAssertIssuer);
					
					// RH, 20120201, sn
					// also save the provided session if present, saml2 specs say there might be more than one session to track
					if (  isIncludeSessionindexes() && sSessionindex != null && sSessionindex.length() > 0 ) {
						Vector sessionindexes = new Vector<String>();
						sessionindexes.add(sSessionindex);
						hmSamlAttributes.put("remote_sessionlist", sessionindexes);
					}
					// RH, 20120201, en

					// Bauke, 20081204: If we want to send the IdP token as an attribute
					// to the application, we will need the following code:
					/*
					 * String sAssertion = XMLHelper.nodeToString(samlAssertion.getDOM());
					 * _systemLogger.log(Level.INFO, MODULE, sMethod, "sAssertion="+sAssertion);
					 * BASE64Encoder b64Enc = new BASE64Encoder();
					 * sAssertion = b64Enc.encode(sAssertion.getBytes("UTF-8"));
					 * htRemoteAttributes.put("saml_remote_token", sAssertion);
					 */
					// End of IdP token

					_systemLogger.log(Level.FINER, MODULE, sMethod, "htRemoteAttributes=" + Auxiliary.obfuscate(hmSamlAttributes));

					handleSSOResponse(_htSessionContext, hmSamlAttributes, servletRequest, servletResponse);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Response was not successful: " + sStatusCode);
					// Handle various error conditions here
					String sErrorCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;	// default
					String sErrorSubCode = null;
					if ( samlResponse.getStatus().getStatusCode().getStatusCode() != null) {	// Get the subcode
						sErrorSubCode = SamlTools.mapStatus(samlResponse.getStatus().getStatusCode().getStatusCode().getValue());
						_systemLogger.log(Level.FINER, MODULE, sMethod, "ErrorSubcode: " + sErrorSubCode);
					}
					StatusMessage statMsg = samlResponse.getStatus().getStatusMessage();
					if (statMsg != null) {
						sErrorCode = statMsg.getMessage();
						_systemLogger.log(Level.FINER, MODULE, sMethod, "StatusMessage found: " + sErrorCode);
					}
					else {
						if (sErrorSubCode != null && !"".equals(sErrorSubCode)) {
							sErrorCode = sErrorSubCode;
						}
					}
					_systemLogger.log(Level.INFO, MODULE, sMethod, "ErrorCode=" + sErrorCode);
					//else if (samlResponse.getStatus().getStatusCode().getStatusCode().getValue().equals(StatusCode.AUTHN_FAILED_URI))
					//	sErrorCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
					// Expect these codes: Errors.ERROR_ASELECT_SERVER_CANCEL,
					// Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;

					//HashMap htRemoteAttributes = new HashMap();
					//htRemoteAttributes.put("remote_rid", sRemoteRid);
					//htRemoteAttributes.put("local_rid", sLocalRid);
					//htRemoteAttributes.put("result_code", sErrorCode);

					// Choose your response (3rd is implemented below)
					// 1. handleSSOResponse(htRemoteAttributes, request, response); // Lets application display error
					// 2. throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED); // Standard server error
					// 3. Show error page:
					showErrorPage(sErrorCode, _htSessionContext, pwOut, servletRequest);
				}
			}
			else {  // SLO
//				_systemLogger.log(Level.WARNING, "Unexpected SAMLObject type: " + samlResponseObject.getClass());
				_systemLogger.log(Level.WARNING, "Unexpected SAMLObject type: " + (samlResponseObject == null ? "null" : samlResponseObject.getClass()));
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			// all has been handled. We'll just flush data and let the container handle the close. Exceptions will close the stream themselves
			if (pwOut != null)
				pwOut.flush();
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			// This will close the output stream before exception handling has been able to send an error page
			// we'll let the container close the stream
//			if (pwOut != null)
//				pwOut.close();
			
			// 20130821, Bauke: save friendly name after session is gone
			if (_htSessionContext != null) {
				String sStatus = (String)_htSessionContext.get("status");
				String sAppId = (String)_htSessionContext.get("app_id");
				if ("del".equals(sStatus) && Utils.hasValue(sAppId)) {
					String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
					HandlerTools.setEncryptedCookie(servletResponse, "requestor_friendly_name", sUF, _configManager.getCookieDomain(), -1/*age*/, _systemLogger);
				}
			}
			_oSessionManager.finalSessionProcessing(_htSessionContext, true/*really do it*/);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#destroy()
	 */
	public void destroy()
	{
		String sMethod = "destroy";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "<--");
	}

	/**
	 * Handle sso response.
	 * 
	 * @param htRemoteAttributes
	 *            the ht remote attributes
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void handleSSOResponse(HashMap htSessionContext, HashMap htRemoteAttributes,
						HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleSSOResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "<--");

		try {
			// 20120712, Bauke: Stores TGT in class variable to save on reads:
			HashMap htServiceRequest = createServiceRequest(servletRequest);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htServiceRequest=" + htServiceRequest);

			String sLocalRid = (String) htRemoteAttributes.get("local_rid");
			if (sLocalRid == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Missing remote attribute: 'local_rid'");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// for authentication logging
			String sRemoteOrg = (String) htSessionContext.get("remote_organization");
			String sOrg = (String) htRemoteAttributes.get("organization");
			if (sRemoteOrg != null && sOrg != null && !sRemoteOrg.equals(sOrg))
				sRemoteOrg = sOrg + "@" + sRemoteOrg;

			String sResultCode = (String) htRemoteAttributes.get("result_code");
			String sUID = (String) htRemoteAttributes.get("uid");
			String sFederationId = (String) htSessionContext.get("federation_url");
			if (sResultCode != null) {
				if (sResultCode.equals(Errors.ERROR_ASELECT_SERVER_CANCEL)
						|| sResultCode.equals(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cancel");
					// RH, 20180924, so
//					_authenticationLogger.log(new Object[] {
//						"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
//						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode
//					});
					// RH, 20180924, eo
					// RH, 20180924, sn
					_authenticationLogger.log(new Object[] {
						"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode, htRemoteAttributes.get("authority")
					});
					// RH, 20180924, en
					// Issue 'CANCEL' TGT
					TGTIssuer tgtIssuer = new TGTIssuer(_sMyServerId);
					tgtIssuer.issueErrorTGTandRedirect(sLocalRid, htSessionContext, sResultCode, servletResponse);
				}
				else { // remote server returned error
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error");
					// RH, 20180924, so
//					_authenticationLogger.log(new Object[] {
//						"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
//						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode
//					});
					// RH, 20180924, eo
					// RH, 20180924, so
					_authenticationLogger.log(new Object[] {
						"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
						htSessionContext.get("app_id"), "denied", sFederationId, sResultCode, htRemoteAttributes.get("authority")
					});
					throw new ASelectException(Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED);
				}
			}
			else { // No result_code set, log successful authentication
				// RH, 20180924, so
//				_authenticationLogger.log(new Object[] {
//					"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
//					htSessionContext.get("app_id"), "granted", sFederationId
//				});
				// RH, 20180924, eo
				// RH, 20180924, sn
				_authenticationLogger.log(new Object[] {
					"Saml", Auxiliary.obfuscate(sUID), (String) htServiceRequest.get("client_ip"), sRemoteOrg,
					htSessionContext.get("app_id"), "granted", sFederationId, sResultCode, htRemoteAttributes.get("authority")
				});
				// RH, 20180924, en

				if ( isLogAuthProof() ) {	// Log auth_proof here if enabled
					ASelectAuthProofLogger.getHandle().log( sUID, (String) htRemoteAttributes.get("client_ip"), (String)htSessionContext.get("app_id"), (String)null, (String)htRemoteAttributes.get("auth_proof") );
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "auth_proof logged after successful authentication=" + 
//							htRemoteAttributes.get("auth_proof"));
					if ( !isCarryAuthProof() ) {	// We do not want to carry the auth_proof any  further
						Object removed_auth_proof = htRemoteAttributes.remove("auth_proof");
						if ( removed_auth_proof != null ) {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Successfully removed auth_proof from htRemoteAttributes" );
						} else {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Could not remove auth_proof from htRemoteAttributes" );
						}
					}
				}
				
				HandlerTools.setRequestorFriendlyCookie(servletResponse, htSessionContext, _systemLogger);  // 20130825

				// Issue a cross TGT since we do not know the AuthSP
				// and we might have received remote attributes.
				TGTIssuer oTGTIssuer = new TGTIssuer(_sMyServerId);
				String sOldTGT = (String) htServiceRequest.get("aselect_credentials_tgt");
				// Will also redirect the user, this call can update/delete the session in the local cache
				// Final session updates will be done by finalSessionProcessing()

				// RH, 20190208, sn
				// Temporary hack for Solera
				String forced_level =  (String)htSessionContext.get("forced_level");
				if (forced_level != null) {
					String sel_level =  (String)htSessionContext.get("sel_level");
//					htSessionContext.remove("forced_level")	;				
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Authentication successful, removing forced_level: " + forced_level);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Authentication successful, forcing forced_level to sel_level: " + forced_level + ", sel_level:" + sel_level);
					htSessionContext.put("forced_level", sel_level)	;				
				}
				// RH, 20190208, en
				oTGTIssuer.issueTGTandRedirect(sLocalRid, htSessionContext, null, htRemoteAttributes, servletRequest, servletResponse, sOldTGT, true);
				// 20090909: oTGTIssuer.issueCrossTGT(sLocalRid, null, htRemoteAttributes, servletResponse, sOldTGT);
			}
		}
		catch (ASelectException ae) {
			throw ae;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
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
	@SuppressWarnings("unchecked")
	private HashMap createServiceRequest(HttpServletRequest servletRequest)
	{
		// Extract parameters into htServiceRequest
		HashMap htServiceRequest = null;
		if (servletRequest.getMethod().equalsIgnoreCase("GET")) {
			htServiceRequest = Utils.convertCGIMessage(servletRequest.getQueryString(), false);
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
		// Bauke 20081217: client_ip and user_agent should already be set
		// htServiceRequest.put("client_ip", servletRequest.getRemoteAddr());
		// String sAgent = servletRequest.getHeader("User-Agent");
		// if (sAgent != null) htServiceRequest.put("user_agent", sAgent);
		HashMap htCredentials = getASelectCredentials(servletRequest);
		if (htCredentials != null) {
			htServiceRequest.put("aselect_credentials_tgt", htCredentials.get("aselect_credentials_tgt"));
			htServiceRequest.put("aselect_credentials_uid", htCredentials.get("aselect_credentials_uid"));
			htServiceRequest.put("aselect_credentials_server_id", _sMyServerId);
		}

		return htServiceRequest;
	}

	/**
	 * Retrieve A-Select credentials. Reads TGT in _htTGTContext.<br>
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
	 * @return The A-Select credentials in a <code>HashMap</code>.
	 */
	@SuppressWarnings("unchecked")
	protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
	{
		// This method overrides the default from ProtoRequestHandler.java
		String sMethod = "getASelectCredentials";
		HashMap htCredentials = new HashMap();

		// Check for credentials that might be present
		// Bauke 20080618, we only store the tgt value from now on
		String sTgt = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
		if (sTgt == null)
			return null;

		HashMap	_htTGTContext = _tgtManager.getTGT(sTgt);
		if (_htTGTContext == null)
			return null;

		String sUserId = (String) _htTGTContext.get("uid");
		if (sUserId != null)
			htCredentials.put("aselect_credentials_uid", sUserId);
		htCredentials.put("aselect_credentials_tgt", sTgt);
		htCredentials.put("aselect_credentials_server_id", _sMyServerId); // Bauke 200806128 was: sServerId);
		return htCredentials;
	}

	/**
	 * 
	 * @param samlObjects
	 * @param assertions
	 */
	public <T> void getNestedAssertions(List<T> samlObjects, final List<Assertion> assertions) {	// maybe use Collection for List
		String sMethod = "getNestedAssertions";
		if (samlObjects != null) {
			for (T samlObject : samlObjects) {
				if (samlObject instanceof EncryptedAssertion) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found samlObjects of type EncryptedAssertion");
					Assertion assertion = (Assertion) SamlTools.decryptSamlObject((EncryptedAssertion)samlObject);
					ArrayList<Assertion> l = new ArrayList<Assertion>();
					l.add(assertion);
					getNestedAssertions(l, assertions);
				} else if (samlObject instanceof Assertion) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found samlObjects of type Assertion");
						assertions.add((Assertion)samlObject);
						if (((Assertion)samlObject).getAdvice() != null) {
							getNestedAssertions(((Assertion)samlObject).getAdvice().getEncryptedAssertions(), assertions);
							getNestedAssertions(((Assertion)samlObject).getAdvice().getAssertions(), assertions);
						}
				} else if (samlObject instanceof Response) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found samlObjects of type Response");
					getNestedAssertions(((Response)samlObject).getEncryptedAssertions(), assertions);
					getNestedAssertions(((Response)samlObject).getAssertions(), assertions);
				}
			}
		} else {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "samlObjects list null, exiting recursion level");
		}
		return;
	}
	/**
	 * Checks if is signing required.
	 * 
	 * @return true, if is signing required
	 */
	public synchronized boolean isSigningRequired()
	{
		return signingRequired;
	}

	/**
	 * Sets the signing required.
	 * 
	 * @param signingRequired
	 *            the new signing required
	 */
	public synchronized void setSigningRequired(boolean signingRequired)
	{
		this.signingRequired = signingRequired;
	}

	/**
	 * Checks if is locality address required.
	 * 
	 * @return true, if is locality address required
	 */
	public synchronized boolean isLocalityAddressRequired()
	{
		return localityAddressRequired;
	}

	/**
	 * Sets the locality address required.
	 * 
	 * @param localityAddressRequired
	 *            the new locality address required
	 */
	public synchronized void setLocalityAddressRequired(boolean localityAddressRequired)
	{
		this.localityAddressRequired = localityAddressRequired;
	}

	/**
	 * @return the includeSessionindexes
	 */
	public synchronized boolean isIncludeSessionindexes()
	{
		return includeSessionindexes;
	}

	/**
	 * @param includeSessionindexes the includeSessionindexes to set
	 */
	public synchronized void setIncludeSessionindexes(boolean includeSessionindexes)
	{
		this.includeSessionindexes = includeSessionindexes;
	}

	/**
	 * @return the useBackchannelClientcertificate
	 */
	public boolean isUseBackchannelClientcertificate()
	{
		return useBackchannelClientcertificate;
	}

	/**
	 * @param useBackchannelClientcertificate the useBackchannelClientcertificate to set
	 */
	public void setUseBackchannelClientcertificate(boolean useBackchannelClientcertificate)
	{
		this.useBackchannelClientcertificate = useBackchannelClientcertificate;
	}

	public synchronized boolean isVerifyArtifactResponseSignature()
	{
		return verifyArtifactResponseSignature;
	}

	public synchronized void setVerifyArtifactResponseSignature(boolean verifyArtifactResponseSignature)
	{
		this.verifyArtifactResponseSignature = verifyArtifactResponseSignature;
	}

	public synchronized boolean isUseNameIDAsAuthID()
	{
		return useNameIDAsAuthID;
	}

	public synchronized void setUseNameIDAsAuthID(boolean useNameIDAsAuthID)
	{
		this.useNameIDAsAuthID = useNameIDAsAuthID;
	}

	public boolean isCarryAuthProof() {
		return carryAuthProof;
	}

	public void setCarryAuthProof(boolean carryAuthProof) {
		this.carryAuthProof = carryAuthProof;
	}

	public boolean isLogAuthProof() {
		return logAuthProof;
	}

	public void setLogAuthProof(boolean logAuthProof) {
		this.logAuthProof = logAuthProof;
	}
}
