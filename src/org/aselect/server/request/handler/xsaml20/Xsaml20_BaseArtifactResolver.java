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

import java.io.StringReader;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.request.RequestState;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public abstract class Xsaml20_BaseArtifactResolver extends Saml20_BaseHandler {

	private static final String MODULE = "Xsaml20_BaseArtifactResolver";
	private XMLObjectBuilderFactory _oBuilderFactory;
	private String _sEntityId;
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	private boolean signingRequired = false;

	public Xsaml20_BaseArtifactResolver() {
		super();
	}

	/**
	 * Init for class SAML20ArtifactResolver. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oHandlerConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig) throws ASelectException {
		String sMethod = "init";
	
		super.init(oServletConfig, oHandlerConfig);
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		_sEntityId = _configManager.getRedirectURL();
	}

	/**
	 * Resolve Artifact. <br>
	 * 
	 * @param request
	 *            HttpServletRequest.
	 * @param response
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If resolving off artifact fails.
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest request, HttpServletResponse response) throws ASelectException {
			String sMethod = "process";
			_systemLogger.log(Level.INFO, MODULE, sMethod, request.getContentType());
	
			try {
	//			MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();	// RH, 20200218, o
				AbstractMetaDataManager metadataManager = getMetadataManager();	// RH, 20200218, n
	
				String sReceivedSoap = Tools.stream2string(request.getInputStream());  // x_AssertionConsumer_x
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received SOAP message:\n" + sReceivedSoap);
	
	//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_systemLogger);
				dbFactory.setNamespaceAware(true);
				dbFactory.setIgnoringComments(true);	// By default the value of this is set to false
	
				DocumentBuilder builder = dbFactory.newDocumentBuilder();
	
				StringReader stringReader = new StringReader(sReceivedSoap);
				InputSource inputSource = new InputSource(stringReader);
				Document docReceivedSoap = builder.parse(inputSource);
				Element elementReceivedSoap = docReceivedSoap.getDocumentElement();
	
				// Remove all SOAP elements
				Node eltArtifactResolve = getNode(elementReceivedSoap, "ArtifactResolve");
	
				// Unmarshall to the SAMLmessage
				UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
	
				ArtifactResolve artifactResolve = (ArtifactResolve) unmarshaller.unmarshall((Element) eltArtifactResolve);
				String sReceivedArtifact = artifactResolve.getArtifact().getArtifact();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Received artifact: " + sReceivedArtifact);
	
				String artifactResolveIssuer = (artifactResolve.getIssuer() == null || // avoid nullpointers
						artifactResolve.getIssuer().getValue() == null || "".equals(artifactResolve.getIssuer().getValue())) ? null
						: artifactResolve.getIssuer().getValue(); // else value from message
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Do artifactResolve signature verification="
						+ is_bVerifySignature());
				if (is_bVerifySignature()) {
					// Check signature of artifactResolve here.
					// We get the public key from the metadata.
					// Therefore we need a valid Issuer to lookup the entityID in the metadata
					// We get the metadataURL from aselect.xml so we consider this safe and authentic
					if (artifactResolveIssuer == null || "".equals(artifactResolveIssuer)) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod,
								"For signature verification the received message must have an Issuer");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
	//				PublicKey pkey = metadataManager.getSigningKeyFromMetadata(artifactResolveIssuer);	// RH, 20181116, o
	//				List <PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(artifactResolveIssuer);	// RH, 20181116, n	// RH, 20190325, o
					List <PublicKey> pkeys = metadataManager.getSigningKeyFromMetadata(_sResourceGroup, artifactResolveIssuer);	// RH, 20181116, n	// RH, 20190325, o
					if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181116, n
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No public valid key in metadata");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
					if (checkSignature(artifactResolve, pkeys)) {	// RH, 20181116, n
						_systemLogger.log(Level.INFO, MODULE, sMethod, "artifactResolve was signed OK");
					}
					else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "artifactResolve was NOT signed OK");
						throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
					}
				}
				String sInResponseTo = artifactResolve.getID(); // Is required in SAMLsyntax
	
				// 20090409, Bauke: If back-channel communication is used Destination is optional
				// If we ever want to set it, look for the Recipient attribute contained in the subject confirmation
				// (tgt:"sp_assert_url" equals the location where the artifact was sent to).
				// The issuer (artifactResolve.getIssuer()) cannot be used for this purpose!
				//
				String sDestination = null;
	
				ArtifactResponse artifactResponse = null;
				// RH, 20160112, sn
				String _sAddedPatching = null;
				if (artifactResolveIssuer != null) {	// application level overrules handler level configuration
					_sAddedPatching = ApplicationManager.getHandle().getAddedPatching(artifactResolveIssuer);
				}
				if (_sAddedPatching == null) {	// backward compatibility, get it from handler configuration
					_sAddedPatching = _configManager.getAddedPatching();
				}
				boolean bSignAssertion = _sAddedPatching.contains("sign_assertion"); 
				_systemLogger.log(Level.FINER, MODULE, sMethod, "ArtifactResponse >====== SignAssertion="+bSignAssertion);
				boolean bSignArtifactResponse = _sAddedPatching.contains("sign_artifactresponse"); 
				_systemLogger.log(Level.FINER, MODULE, sMethod, "ArtifactResponse >====== SignArtifactResponse="+bSignArtifactResponse);
				boolean bKeepOriginalTimestampAssertion = _sAddedPatching.contains("keeporiginaltimestamp_assertion"); 
				_systemLogger.log(Level.FINER, MODULE, sMethod, "ArtifactResponse >====== KeepOriginalTimestampAssertion="+bKeepOriginalTimestampAssertion);
				// RH, 20160112, en
	
				if (sReceivedArtifact == null || "".equals(sReceivedArtifact)) {
					String sStatusCode = StatusCode.INVALID_ATTR_NAME_VALUE_URI;
					String sStatusMessage = "No 'artifact' found in element 'ArtifactResolve' of SAMLMessage.";
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sStatusMessage);
					artifactResponse = errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
				}
				else {
					
					Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
	//				Response samlResponse = (Response) artifactManager.getArtifactFromStorage(sReceivedArtifact);	// RH, 20200218, o
					// may contain Response or LogoutRequest
					SignableSAMLObject samlResponse = (SignableSAMLObject) artifactManager.getArtifactFromStorage(sReceivedArtifact);	// RH, 20200218, o
					
					//_systemLogger.log(Level.INFO, MODULE, sMethod, "samlResponse retrieved from storage:\n"
					//		+ XMLHelper.nodeToString(samlResponse.getDOM()));
	
					// RH, 20160112, sn
					DateTime now = new DateTime();
					// RH, 20160112, en
					
					// We will not allow to use the artifact again
					artifactManager.remove(sReceivedArtifact); // RH, 20081113, n
					
					SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) _oBuilderFactory
							.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
					StatusCode statusCode = statusCodeBuilder.buildObject();
					statusCode.setValue(StatusCode.SUCCESS_URI);
	
					SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) _oBuilderFactory
							.getBuilder(Status.DEFAULT_ELEMENT_NAME);
					Status status = statusBuilder.buildObject();
					status.setStatusCode(statusCode);
	
					SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
							.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
					Issuer issuer = issuerBuilder.buildObject();
					issuer.setFormat(NameIDType.ENTITY);
					issuer.setValue(_sEntityId);
	
					SAMLObjectBuilder<ArtifactResponse> artifactResponseBuilder = (SAMLObjectBuilder<ArtifactResponse>) _oBuilderFactory
							.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
					artifactResponse = artifactResponseBuilder.buildObject();
	
					// nvl_patch, Novell: add xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
					artifactResponse.addNamespace(new Namespace(SAMLConstants.SAML20_NS, "saml"));
	
					artifactResponse.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
					artifactResponse.setInResponseTo(sInResponseTo);
					artifactResponse.setVersion(SAMLVersion.VERSION_20);
	//				artifactResponse.setIssueInstant(new DateTime());		// RH, 20160112, o
					artifactResponse.setIssueInstant(now);	// RH, 20160112, n
					if (sDestination != null)
						artifactResponse.setDestination(sDestination);
					artifactResponse.setStatus(status);
					artifactResponse.setIssuer(issuer);
					updateTimeStamps(sMethod, bSignAssertion, bKeepOriginalTimestampAssertion, samlResponse, now);
					artifactResponse.setMessage(samlResponse);
				}
	
				// Also check out Xsaml20_SSO for signing issues
				// RH, 20160112, so
	//			String _sAddedPatching = null;
	//			if (artifactResolveIssuer != null) {	// application level overrules handler level configuration
	//				_sAddedPatching = ApplicationManager.getHandle().getAddedPatching(artifactResolveIssuer);
	//			}
	//			if (_sAddedPatching == null) {	// backward compatibility, get it from handler configuration
	//				_sAddedPatching = _configManager.getAddedPatching();
	//			}
	//			boolean bSignAssertion = _sAddedPatching.contains("sign_assertion"); 
	//			_systemLogger.log(Level.FINER, MODULE, sMethod, "ArtifactResponse >====== SignAssertion="+bSignAssertion);
	//			boolean bSignArtifactResponse = _sAddedPatching.contains("sign_artifactresponse"); 
	//			_systemLogger.log(Level.FINER, MODULE, sMethod, "ArtifactResponse >====== SignArtifactResponse="+bSignArtifactResponse);
				// RH, 20160112, eo
				// IMPROV get the sha1/sha256 from configuration or metadata
				if (bSignAssertion) {
					// only the assertion, was signed previously and/or already in Saml20_SSO
					if (bSignArtifactResponse) {	// sign the ArtifactResponse anyway
	//					artifactResponse = (ArtifactResponse)SamlTools.signSamlObject(artifactResponse, 
	//							(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
	//									(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
	//											(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate));	// RH, 20180918, o
						artifactResponse = (ArtifactResponse)SamlTools.signSamlObject(artifactResponse, 
								(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
										(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
												(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate), null);	// RH, 20180918, n
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the artifactResponse ======<");
					} else {
					try {
						// don't forget to marshall the response when no signing will be done here
						org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(artifactResponse).marshall(artifactResponse);
					}
					catch (MarshallingException e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot marshall object", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
					}
					}
				}
				else {  // No assertion signing, sign the complete response
	//				artifactResponse = (ArtifactResponse)SamlTools.signSamlObject(artifactResponse, "sha1", false, false);
	//				artifactResponse = (ArtifactResponse)SamlTools.signSamlObject(artifactResponse,  (_sReqSigning != null) ?_sReqSigning: _sDefaultSigning, 
	//						(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname), 
	//								(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate));	// RH, 20180918, o
					artifactResponse = (ArtifactResponse)SamlTools.signSamlObject(artifactResponse,  (_sReqSigning != null) ?_sReqSigning: _sDefaultSigning, 
							(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname), 
									(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate), null);	// RH, 20180918, n
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the artifactResponse =====<");
				}
				Envelope envelope = new SoapManager().buildSOAPMessage(artifactResponse);
				Element envelopeElem = SamlTools.marshallMessage(envelope);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Writing SOAP message:\n" + Auxiliary.obfuscate(XMLHelper.nodeToString(envelopeElem), Auxiliary.REGEX_PATTERNS));
	
				// Bauke: added, it's considered polite to tell the other side what we are sending
				SamlTools.sendSOAPResponse(request, response, XMLHelper.nodeToString(envelopeElem));  // x_AssertionConsumer_x
			}
			catch (Exception e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Internal error", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			return null;
		}

//	/**
//	 * @param sMethod
//	 * @param bSignAssertion
//	 * @param bKeepOriginalTimestampAssertion
//	 * @param samlResponse
//	 * @param now
//	 * @throws ASelectException
//	 */
//	protected void updateTimeStamps(String sMethod, boolean bSignAssertion, boolean bKeepOriginalTimestampAssertion, SignableSAMLObject samlResponse, DateTime now)
//			throws ASelectException {
//					// RH, 20160108, sn
//					//. We'll have to update the timestamp IssueInstant, NotBefore and NotOnOrAfter of the samlResponse here
//					// RH, 20200218, so
//			//				if ( !bKeepOriginalTimestampAssertion && samlResponse.getAssertions()!= null && samlResponse.getAssertions().size()>0) {
//			//					samlResponse.setIssueInstant(now);
//			//					Assertion a = samlResponse.getAssertions().get(0); // There can be only one
//					// RH, 20200218, so
//					// RH, 20200218, sn
//					if ( !bKeepOriginalTimestampAssertion && ((Response)samlResponse).getAssertions()!= null && ((Response)samlResponse).getAssertions().size()>0) {
//						((Response)samlResponse).setIssueInstant(now);
//						Assertion a = ((Response)samlResponse).getAssertions().get(0); // There can be only one
//					// RH, 20200218, en
//						if (a != null) {
//							a.setIssueInstant(now);
//							SamlTools.setValidityInterval(a, now, getMaxNotBefore(), getMaxNotOnOrAfter() );	// sets NotBefore and NotOnOrAfter on Conditions
//							if (a.getSubject() != null) {
//								List<SubjectConfirmation> subjconfs = a.getSubject().getSubjectConfirmations() ;
//								if (subjconfs != null) {
//									for (SubjectConfirmation s : subjconfs) {
//										org.opensaml.saml2.core.SubjectConfirmationData sdata = s.getSubjectConfirmationData();
//										if (sdata != null) {
//											SamlTools.setValidityInterval(sdata, now, getMaxNotBefore(), getMaxNotOnOrAfter() );
//										}
//									}
//								}
//							}
//							List<AuthnStatement> authnList = a.getAuthnStatements();
//							if (authnList != null) {
//								for (AuthnStatement as : authnList) {
//									as.setAuthnInstant(now);
//								}
//							}
//							if (a.isSigned() || bSignAssertion) {
//			//							a = (Assertion)SamlTools.signSamlObject(a, 
//			//									(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
//			//											(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
//			//													(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate));	// RH, 20180918, o
//								a = (Assertion)SamlTools.signSamlObject(a, 
//										(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
//												(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
//														(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate), null);	// RH, 20180918, n
//								_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the assertion ======<");
//							}
//						}
//					}
//					// RH, 20160108, en
//				}
//				// RH, 20200218, nn

	
	/**
	 * @param sMethod
	 * @param bSignAssertion
	 * @param bKeepOriginalTimestampAssertion
	 * @param samlResponse
	 * @param now
	 * @throws ASelectException
	 */
	protected abstract void updateTimeStamps(String sMethod, boolean bSignAssertion, boolean bKeepOriginalTimestampAssertion, SignableSAMLObject samlResponse, DateTime now)
			throws ASelectException;

//	/**
//	 * @return
//	 * @throws ASelectException
//	 */
//	protected AbstractMetaDataManager getMetadataManager() throws ASelectException {
//		AbstractMetaDataManager metadataManager = MetaDataManagerIdp.getHandle();
//		return metadataManager;
//	}
//	// RH, 20200218, en

	protected abstract AbstractMetaDataManager getMetadataManager() throws ASelectException;

	/**
	 * Gets the node.
	 * 
	 * @param node
	 *            the node
	 * @param sSearch
	 *            the s search
	 * @return the node
	 */
	private Node getNode(Node node, String sSearch) {
		Node nResult = null;
		NodeList nodeList = node.getChildNodes();
		for (int i = 0; i < nodeList.getLength() && nResult == null; i++) {
			if (sSearch.equals(nodeList.item(i).getLocalName()))
				nResult = nodeList.item(i);
			else
				nResult = getNode(nodeList.item(i), sSearch);
		}
		return nResult;
	}

	/**
	 * /** Contructs an errorResponse:
	 * 
	 * <pre>
	 * &lt;ArtifactResponse
	 * ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot;
	 * InResponseTo=&quot;&quot;
	 * Version=&quot;2.0&quot;
	 * IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 * Destination=&quot;&quot;&gt;
	 * &lt;Status&gt;
	 * &lt;StatusCode
	 * Value=&quot;urn:oasis:names:tc:SAML:2.0:status:Requester&quot;&gt;
	 * &lt;StatusCode
	 * Value=&quot;urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue&quot;/&gt;
	 * &lt;/StatusCode&gt;
	 * &lt;StatusMessage&gt;No ProviderName attribute found in element AuthnRequest of SAML message&lt;/StatusMessage&gt;
	 * &lt;/Status&gt;
	 * &lt;/ArtifactResponse&gt;
	 * </pre>
	 * 
	 * @param sInResponseTo
	 *            the s in response to
	 * @param sDestination
	 *            the s destination
	 * @param sSecLevelstatusCode
	 *            the s sec levelstatus code
	 * @param sStatusMessage
	 *            the s status message
	 * @return the artifact response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private ArtifactResponse errorResponse(String sInResponseTo, String sDestination, String sSecLevelstatusCode, String sStatusMessage) throws ASelectException {
		String sMethod = "errorResponse";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
	
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) _oBuilderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode secLevelStatusCode = statusCodeBuilder.buildObject();
		secLevelStatusCode.setValue(sSecLevelstatusCode);
	
		StatusCode topLevelstatusCode = statusCodeBuilder.buildObject();
		topLevelstatusCode.setValue(StatusCode.REQUESTER_URI);
		topLevelstatusCode.setStatusCode(secLevelStatusCode);
	
		SAMLObjectBuilder<StatusMessage> statusMessagebuilder = (SAMLObjectBuilder<StatusMessage>) _oBuilderFactory
				.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
		StatusMessage statusMessage = statusMessagebuilder.buildObject();
		statusMessage.setMessage(sStatusMessage);
	
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) _oBuilderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		status.setStatusCode(topLevelstatusCode);
		status.setStatusMessage(statusMessage);
	
		SAMLObjectBuilder<ArtifactResponse> artifactResponseBuilder = (SAMLObjectBuilder<ArtifactResponse>) _oBuilderFactory
				.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
		ArtifactResponse artifactResponse = artifactResponseBuilder.buildObject();
	
		artifactResponse.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
		artifactResponse.setInResponseTo(sInResponseTo);
		artifactResponse.setVersion(SAMLVersion.VERSION_20);
		artifactResponse.setIssueInstant(new DateTime());
		if (sDestination != null)
			artifactResponse.setDestination(sDestination);
		artifactResponse.setMessage(status);
		return null;
	}

	@Override
	public void destroy() {
		String sMethod = "destroy";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
	}

	/**
	 * Checks if is signing required.
	 * 
	 * @return true, if is signing required
	 */
	public synchronized boolean isSigningRequired() {
		return signingRequired;
	}

	/**
	 * Sets the signing required.
	 * 
	 * @param signingRequired
	 *            the new signing required
	 */
	public synchronized void setSigningRequired(boolean signingRequired) {
		this.signingRequired = signingRequired;
	}

}