package org.aselect.server.request.handler.xsaml20.idp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.request.handler.xsaml20.Saml20_ArtifactManager;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;

// Example configuration
// <handler id="saml20_sso"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_SSO"
//    target="/saml20_sso.*" >
// </handler>
//
public class Xsaml20_SSO extends Saml20_BrowserHandler
{
    private final static String MODULE = "Xsaml20_SSO";
	private final static String RETURN_SUFFIX = "_return";
    private final String AUTHNREQUEST = "AuthnRequest";
    
    public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
    {
	    if (elementName.equals(AUTHNREQUEST)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			return authnRequest.getIssuer();
		}
		return null;
    }

	/**
	 * Overrides the default
	 * 
	 * @param request - HttpServletRequest
	 * @param response - HttpServletResponse
	 * @return RequestState
	 */	
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
		throws ASelectException
	{
		String sMethod = "process()";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path="+sPathInfo+" RequestQuery: " + request.getQueryString());
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path="+sPathInfo);

		if (sPathInfo.endsWith(RETURN_SUFFIX)) {
			processReturn(request, response);
		}
		else if (request.getParameter("SAMLRequest") != null) {
			handleSAMLMessage(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: "+request.getQueryString()+" is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled ");
		return new RequestState(null);
	}

	/**
	 * @param httpRequest
	 * @param httpResponse
	 * @param samlMessage
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request "+Thread.currentThread().getId();
		AuthnRequest authnRequest = (AuthnRequest)samlMessage;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		try {
			String sRelayState = (String)httpRequest.getParameter("RelayState");
			Response errorResponse = validateAuthnRequest(authnRequest, httpRequest);
			if (errorResponse != null) {
				_systemLogger.log(Audit.SEVERE, MODULE, sMethod, "validateAuthnRequest failed");
				sendErrorArtifact(errorResponse, authnRequest, httpResponse, sRelayState);
				return;
			}
			// The message is OK
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest received");
			String sAppId = authnRequest.getIssuer().getValue();  // authnRequest.getProviderName();
			String sSPRid = authnRequest.getID();
			String sIssuer = authnRequest.getIssuer().getValue();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "==== SPRid="+sSPRid+" RelayState="+sRelayState);

			boolean bForcedAuthn = authnRequest.isForceAuthn();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ForceAuthn = " + bForcedAuthn);

			String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(samlMessage);
			if (sAssertionConsumerServiceURL == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "AssertionConsumerServiceURL not found");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST);
			}
			
			// Start an authenticate request
			_systemLogger.log(Level.INFO, MODULE, sMethod, "performAuthenticateRequest AppId=" + sAppId);
			HashMap htResponse = performAuthenticateRequest(_sASelectServerUrl, 
					httpRequest.getPathInfo(), RETURN_SUFFIX, sAppId, true /*check sig*/, _oClientCommunicator);

			String sASelectServerUrl = (String) htResponse.get("as_url");
			String sIDPRid = (String) htResponse.get("rid");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Supplied rid="+sIDPRid+" response="+htResponse);

			// The new sessionhttpRequest
			HashMap htSession = _oSessionManager.getSessionContext(sIDPRid);
			if (sRelayState != null)
				htSession.put("RelayState", sRelayState);
			htSession.put("sp_rid", sSPRid);
			htSession.put("sp_issuer", sIssuer);
			htSession.put("sp_assert_url", sAssertionConsumerServiceURL);
			htSession.put("forced_uid", "saml20_user");
			
			// RH, 20081117, strictly speaking forced_logon != forced_authenticate
			// 20090613, Bauke: 'forced_login' is used as API parameter (a String value)
			//           'forced_authenticate' is used in the Session (a Boolean value),
			//           the meaning of both is the identical
			if (bForcedAuthn) {
				htSession.put("forced_authenticate", new Boolean(bForcedAuthn));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "'forced_authenticate' in htSession set to: " + bForcedAuthn);
			}

			// The betrouwbaarheidsniveau is stored in the session context
			RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
			String sBetrouwbaarheidsNiveau = SecurityLevel.getBetrouwbaarheidsNiveau(requestedAuthnContext, _systemLogger);
			if (sBetrouwbaarheidsNiveau.equals(SecurityLevel.BN_NOT_FOUND)) {
				// We've got a security level but is not known
				String sStatusMessage = "The requested AuthnContext isn't present in the configuration";
				errorResponse = errorResponse(sSPRid, sAssertionConsumerServiceURL,
								StatusCode.NO_AUTHN_CONTEXT_URI, sStatusMessage);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
				sendErrorArtifact(errorResponse, authnRequest, httpResponse, sRelayState);
				return;
			}
			// debug
			/*org.opensaml.saml2.core.Subject mySubj = authnRequest.getSubject();
			if (mySubj != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Subject.BaseID="+mySubj.getBaseID()+
						" Subject.NameID="+mySubj.getNameID());
			}*/

			// 20090110, Bauke changed requested_betrouwbaarheidsniveau  to required_level
			htSession.put("required_level", sBetrouwbaarheidsNiveau);
			htSession.put("level", Integer.parseInt(sBetrouwbaarheidsNiveau));  // 20090111, Bauke added
			_oSessionManager.updateSession(sIDPRid, htSession);

			// redirect with A-Select request=login1
			StringBuffer sbURL = new StringBuffer(sASelectServerUrl);
			sbURL.append("&rid=").append(sIDPRid);
			sbURL.append("&a-select-server=").append(_sASelectServerID);
			if (bForcedAuthn) sbURL.append("&forced_logon=").append(bForcedAuthn);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + sbURL.toString());
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Challenge for credentials, redirect to:"  + sbURL.toString());
			httpResponse.sendRedirect(sbURL.toString());
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, XMLHelper.prettyPrintXML(samlMessage.getDOM()));
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest handled");
	}

	private String getAssertionConsumerServiceURL(SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "getAssertionConsumerServiceURL "+Thread.currentThread().getId();
		
		String elementName = samlMessage.getElementQName().getLocalPart();
		Issuer issuer = retrieveIssuer(elementName, samlMessage);
		if (issuer == null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAMLMessage: "+elementName+" was not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		String sAssertionConsumerServiceURL = null;
		String sEntityId = issuer.getValue();
		String sElementName = AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME;
		String sBindingName = SAMLConstants.SAML2_ARTIFACT_BINDING_URI;

		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Meta");
		MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
		try {  // TEST
			sAssertionConsumerServiceURL = metadataManager.getLocation("https://www.sp.com:9443/sps/IBM-Overheid/saml20",
					"AssertionConsumerService", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Location="+sAssertionConsumerServiceURL);
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: "+e.getMessage());
		}
		try {  // TEST
			sAssertionConsumerServiceURL = metadataManager.getLocation("https://portal.sunlabs.nl:444/opensso",
					"AssertionConsumerService", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Location="+sAssertionConsumerServiceURL);
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: "+e.getMessage());
		}
		try {  // TEST
			sAssertionConsumerServiceURL = metadataManager.getLocation("https://siam.s-hertogenbosch.nl/aselectserver/server",
					"AssertionConsumerService", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Location="+sAssertionConsumerServiceURL);
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: "+e.getMessage());
		}
		try {  // TEST
			sAssertionConsumerServiceURL = metadataManager.getLocation("http://fed.amsterdamlaan.net/fed/sp",
					"AssertionConsumerService", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Location="+sAssertionConsumerServiceURL);
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: "+e.getMessage());
		}
		
		try {
			sAssertionConsumerServiceURL = metadataManager.getLocation(sEntityId, sElementName, sBindingName);
		}
		catch (ASelectException e) {
			// Metadata retrieval failed so get it from the message
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: "+e.getMessage());
		}

		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Meta1 OK "+sAssertionConsumerServiceURL);
		if (sAssertionConsumerServiceURL == null) {
			if (elementName.equals(AUTHNREQUEST)) {
				AuthnRequest authnRequest = (AuthnRequest) samlMessage;
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Location from AuthnRequest");
				sAssertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Return "+sAssertionConsumerServiceURL);
		return sAssertionConsumerServiceURL;
	}

	// This is an error response
	private void sendErrorArtifact(Response errorResponse, AuthnRequest authnRequest,
					HttpServletResponse httpResponse, String sRelayState)
	throws IOException, ASelectException
	{
		String sMethod = "sendErrorArtifact()";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		String sId = errorResponse.getID();

		Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
		String sArtifact = artifactManager.buildArtifact(errorResponse, _sASelectServerUrl, sId);

		// If the AssertionConsumerServiceURL is missing, redirecting the artifact is senseless
		// So in this case send a message to the browser
		String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(authnRequest);
		if (sAssertionConsumerServiceURL != null) {
			artifactManager.sendArtifact(sArtifact, errorResponse, sAssertionConsumerServiceURL, httpResponse, sRelayState);
		}
		else {
			String errorMessage = "Something wrong in SAML communication";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
			PrintWriter pwOut = httpResponse.getWriter();
			pwOut.write(errorMessage);
		}
	}

	// We're returning from the AuthSP
	// RequestQuery: aselect_credentials=7HxCWBudn...W8bAU3OY&rid=4B9FF1406696C0C8&a-select-server=umcn_aselect_server1
	private void processReturn(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "processReturn()";
        HashMap htTGTContext = null;
        HashMap htSessionContext = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Handle return from the AuthSP");
		
		try {
			// We have to return to the calling SP using a SAML Artifact
	        String sRid = (String) httpRequest.getParameter("rid");
			String sTgt = (String) httpRequest.getParameter("aselect_credentials");
			if (sTgt != null && !sTgt.equals("")) {
				sTgt = decryptCredentials(sTgt);
		        htTGTContext = getContextFromTgt(sTgt, false);  // Don't check expiration
			}
			else {
				htSessionContext = _oSessionManager.getSessionContext(sRid);
			}
	        // One of them must be available
	        if (htTGTContext == null && htSessionContext == null) {
	        	_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Neither TGT context nor Session context are available");
	        	throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
	        }

	        String sAssertUrl = null;
	        if (htTGTContext != null)
	        	sAssertUrl = (String)htTGTContext.get("sp_assert_url");
	        if (sAssertUrl == null && htSessionContext != null)
		        sAssertUrl = (String)htSessionContext.get("sp_assert_url");
	        if (sAssertUrl == null) {
	    		_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Return Url \"sp_assert_url\" is missing");
	            throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
	        }

	        // 20090603, Bauke: Only take RelayState from the session (not from TgT)
	        // If RelayState was given, it must be available in the Session Context.
	        String sRelayState = null;
	        if (htSessionContext != null)
	        	sRelayState = (String)htSessionContext.get("RelayState");
	        
	        // And off you go!
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Redirecting with artifact to: "+ sAssertUrl);
			sendSAMLArtifactRedirect(sAssertUrl, sRid, htSessionContext, sTgt, htTGTContext, httpResponse, sRelayState);
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Return from  AuthSP handled");

			// Cleanup for a forced_authenticate session
			Boolean bForcedAuthn = (Boolean)htTGTContext.get("forced_authenticate");
			if (bForcedAuthn && htTGTContext != null) {
				TGTManager tgtManager = TGTManager.getHandle();
				tgtManager.remove(sTgt);
			}
			if (bForcedAuthn && htSessionContext != null) {
				SessionManager sessionManager = SessionManager.getHandle();
				sessionManager.killSession(sRid);
			}
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	//
	// If htTGTContext is null we have to create an error <Response>
	// no Assertion, just <Status>
	//
	@SuppressWarnings("unchecked")
	private void sendSAMLArtifactRedirect(String sAppUrl, String sRid, HashMap htSessionContext,
				String sTgt, HashMap htTGTContext, HttpServletResponse oHttpServletResponse, String sRelayState)
	throws ASelectException
	{
		String sMethod = "sendSAMLArtifactRedirect";
		boolean isSuccessResponse = (htTGTContext != null);
		Assertion assertion = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		String sRedirectUrl = "";
		try {
			DateTime tStamp = new DateTime(); // We will use one timestamp
			
			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
			XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);

			String sSPRid = null;
			if (htSessionContext != null)
				sSPRid = (String) htSessionContext.get("sp_rid");
			
			if (htTGTContext != null) {
				sSPRid = (String) htTGTContext.get("sp_rid");
				String sAuthspLevel = (String) htTGTContext.get("betrouwbaarheidsniveau");
				if (sAuthspLevel==null)
					sAuthspLevel = (String) htTGTContext.get("authsp_level");
				String sUid = (String) htTGTContext.get("uid");
				String sCtxRid = (String) htTGTContext.get("rid");
				String sSubjectLocalityAddress = (String) htTGTContext.get("client_ip");
				String sAssertionID = SamlTools.generateIdentifier(_systemLogger, MODULE); 
				_systemLogger.log(Level.INFO, MODULE, sMethod, "CHECK ctxRid="+sCtxRid+" rid="+sRid +" client_ip="+sSubjectLocalityAddress);

				// Attributes
				XSString attributeAuthspLevelValue = (XSString) stringBuilder.buildObject(
						AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
				attributeAuthspLevelValue.setValue(sAuthspLevel);
	
				SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
						.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
				Attribute attributeAuthspLevel = attributeBuilder.buildObject();
				attributeAuthspLevel.setName("betrouwbaarheidsniveau");
				attributeAuthspLevel.getAttributeValues().add(attributeAuthspLevelValue);
	
				XSString attributeUidValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
						XSString.TYPE_NAME);
				attributeUidValue.setValue(sUid);
	
				Attribute attributeUid = attributeBuilder.buildObject();
				attributeUid.setName("uid");
				attributeUid.getAttributeValues().add(attributeUidValue);
	
				SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
						.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
				AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
				attributeStatement.getAttributes().add(attributeUid);
				attributeStatement.getAttributes().add(attributeAuthspLevel);

				// AuthenticationContext
				SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
						.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
				AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
				String sAutnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sAuthspLevel, _systemLogger, MODULE);
				authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);
	
				SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
						.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
				AuthnContext authnContext = authnContextBuilder.buildObject();
				authnContext.setAuthnContextClassRef(authnContextClassRef);
	
				SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
						.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
				AuthnStatement authnStatement = authnStatementBuilder.buildObject();
				authnStatement.setAuthnInstant(new DateTime());
				// Sun doesn't like this:
				// authnStatement.setSessionIndex((String) htTGTContext.get("sp_issuer"));
				String sSessionIndex = sAssertionID.replaceAll("_", "");
				authnStatement.setSessionIndex(sSessionIndex);
				// Always try to set the locality address, except when null or empty
				if (sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress)) {
					SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) builderFactory
									.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
					SubjectLocality locality = subjectLocalityBuilder.buildObject();
					locality.setAddress(sSubjectLocalityAddress);
					authnStatement.setSubjectLocality(locality);
					// TODO maybe also set DNSName in locality, not requested (for now)
				}
			
				authnStatement.setAuthnContext(authnContext);
				SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
						.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
				Audience audience = audienceBuilder.buildObject();
				audience.setAudienceURI((String) htTGTContext.get("sp_issuer"));  // 20081109 added
	
				SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
						.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
				AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
				audienceRestriction.getAudiences().add(audience);
	
				SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
						.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
				SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
				subjectConfirmationData = (SubjectConfirmationData)SamlTools.setValidityInterval(subjectConfirmationData,  tStamp, null, getMaxNotOnOrAfter());
				subjectConfirmationData.setRecipient((String) htTGTContext.get("sp_assert_url"));

				// Bauke: added for OpenSSO 20080329
				subjectConfirmationData.setInResponseTo(sSPRid);
	
				SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
						.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
				SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
				// The following constant is not present in the saml2 library
				subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
				subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
	
				SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
						.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
				NameID nameID = nameIDBuilder.buildObject();
				nameID.setFormat(NameIDType.TRANSIENT);  // was PERSISTENT
				// 20090602, Bauke Saml-core-2.0, section 2.2.2: SHOULD be omitted:
				//nameID.setNameQualifier(_sASelectServerUrl);
				nameID.setValue(sTgt); // back to TgT sUid);  ///*sTgt);  // REPLACES: */ (String)htTGTContext.get("uid"));
				_systemLogger.log(Level.INFO, MODULE, sMethod, "nameID="+Utils.firstPartOf(nameID.getValue(), 30));
				
				SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
						.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
				Subject subject = subjectBuilder.buildObject();
				subject.setNameID(nameID);
				subject.getSubjectConfirmations().add(subjectConfirmation);
	
				SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
						.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
				Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
				assertionIssuer.setFormat(NameIDType.ENTITY);
				assertionIssuer.setValue(_sASelectServerUrl);
	
				SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
						.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
				assertion = assertionBuilder.buildObject();
	
				assertion.setID(sAssertionID);
				assertion.setIssueInstant(tStamp);
				// Set interval conditions
				assertion = (Assertion)SamlTools.setValidityInterval(assertion, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());
				// and then AudienceRestrictions
				assertion = (Assertion)SamlTools.setAudienceRestrictions(assertion, audienceRestriction);
	
				assertion.setVersion(SAMLVersion.VERSION_20);
				assertion.setIssuer(assertionIssuer);
				assertion.setSubject(subject);
				assertion.getAuthnStatements().add(authnStatement);
				assertion.getAttributeStatements().add(attributeStatement);
			}

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Set StatusCode");
			SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
					.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
			StatusCode statusCode = statusCodeBuilder.buildObject();
			statusCode.setValue((htTGTContext==null)? StatusCode.AUTHN_FAILED_URI: StatusCode.SUCCESS_URI);

			SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
					.getBuilder(Status.DEFAULT_ELEMENT_NAME);
			Status status = statusBuilder.buildObject();
			status.setStatusCode(statusCode);
			if (htTGTContext == null) {
				String sResultCode = (String)htSessionContext.get("result_code");
				SAMLObjectBuilder<StatusMessage> statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory
						.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
				StatusMessage msg = statusMessageBuilder.buildObject();
				msg.setMessage((sResultCode != null)? sResultCode: "unspecified error");
				status.setStatusMessage(msg);
			}

			SAMLObjectBuilder<Issuer> responseIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer responseIssuer = responseIssuerBuilder.buildObject();
			responseIssuer.setFormat(NameIDType.ENTITY);
			responseIssuer.setValue(_sASelectServerUrl);

			SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
					.getBuilder(Response.DEFAULT_ELEMENT_NAME);
			Response response = responseBuilder.buildObject();

			response.setInResponseTo(sSPRid);
			
			response.setID("_"+sRid);  // 20090512, Bauke: must be NCNAME format
			response.setIssueInstant(tStamp);
			
			response.setVersion(SAMLVersion.VERSION_20);
			response.setStatus(status);
			response.setIssuer(responseIssuer);
			if (isSuccessResponse) {
				response.getAssertions().add(assertion);
			}

			Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "buildArtifact serverUrl="+_sASelectServerUrl+" rid="+sRid);
			String sArtifact = artifactManager.buildArtifact(response, _sASelectServerUrl, sRid);

			_systemLogger.log(Level.INFO, MODULE, sMethod, "sendArtifact "+sArtifact);
			artifactManager.sendArtifact(sArtifact, response, sAppUrl, oHttpServletResponse, sRelayState);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Redirect to : '" + sRedirectUrl + "' failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}
}