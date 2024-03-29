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
package org.aselect.server.request.handler.xsaml20.idp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.print.attribute.standard.NumberOfDocuments;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.Saml20_ArtifactManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
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
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDecl;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.RequesterID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.EncryptedIDBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;

// Example configuration
// <handler id="saml20_sso"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_SSO"
//    target="/saml20_sso.*" >
// </handler>
//
public class Xsaml20_SSO extends Saml20_BrowserHandler
{
	private static final String LOCALS_NAME_ADD_CERTIFICATE = "AddCertificate";
	private static final String LOCALS_NAME_ADD_KEY_NAME = "AddKeyName";
	private static final String LOCALS_NAME_REQ_SIGNING = "ReqSigning";
	private static final String LOCALS_NAME_SIGN_ASSERTION = "SignAssertion";
	private static final String LOCALS_NAME_ADDED_PATCHING = "AddedPatching";
	private static final String LOCALS_NAME_APP_ID = "AppId";
	private final static String MODULE = "Xsaml20_SSO";
	private final static String RETURN_SUFFIX = "_return";
		
	private final String AUTHNREQUEST = "AuthnRequest";
	private String _sPostTemplate = null;
	private String _sSpecialSettings = null;
	private String _sNameIDAttribute = null;	// RH, 20161013, n

	// Communication for processReturn()
	// RH, 20210122, so
	// Using new mechanism retrieving localsettings
//	private String _sAppId = null;
//	private String _sAddedPatching = null;
//	boolean _bSignAssertion = false;  // must be retrieved from the metadata
	// RH, 20210122, eo
	
	List<String> _suppress_default_attributes =  null;	// option to suppress unwanted attributes in AttrubuteStatement put in by legacy default
	
	/**
	 * Initializes the request handler by reading the following configuration: <br/>
	 * <br/>
	 * 
	 * <pre>
	 * &lt;aselect&gt;
	 * &lt;server_id&gt;[_sMyServerId]&lt;/server_id&gt;
	 * &lt;organization&gt;[_sAppOrg]&lt;/organization&gt;
	 * &lt;/aselect&gt;
	 * 
	 * &lt;handler&gt;
	 * &lt;server_id&gt;[_sASelectServerId]&lt;/server_id&gt;
	 * &lt;server_url&gt;[_sASelectServerUrl]&lt;/server_url&gt;
	 * &lt;clientcommunicator&gt;[_oClientCommunicator]&lt;/clientcommunicator&gt;
	 * &lt;/handler&gt;
	 * </pre>
	 * <ul>
	 * <li><b>_sMyServerId</b> - The id of <b>this</b> (IDP) A-Select Server</li>
	 * <li><b>_sAppOrg</b> - The organization of <b>this</b> (IDP) A-Select Server</li>
	 * <li><b>_sASelectServerId</b> - The id of the IDP A-Select Server</li>
	 * <li><b>_sASelectServerUrl</b> - The url of the IDP A-Select Server</li>
	 * <li><b>_oClientCommunicator</b> - The ClientCommunicator</li>
	 * </ul>
	 * <br>
	 * .
	 * 
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 *             the a select exception
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oHandlerConfig);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		
		try {
			setPostTemplate(_configManager.getParam(oHandlerConfig, "post_template"));
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'post_template' found", e);
		}

		try {
			_sSpecialSettings = _configManager.getParam(oHandlerConfig, "special_settings");
		}
		catch (ASelectConfigException e) {
			;
		}

		// RH, 20161013, sn
		try {
			_sNameIDAttribute = _configManager.getParam(oHandlerConfig, "nameid_attribute");
		}
		catch (ASelectConfigException e) {
			_sNameIDAttribute = null;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No config item 'nameid_attribute' found, using defaults");
		}
		// RH, 20161013, en

		// RH, 20180213, sn
		try {
			String _sSuppress_default_attributes = _configManager.getParam(oHandlerConfig, "suppress_default_attributes");
			_suppress_default_attributes = new ArrayList<String>(Arrays.asList(_sSuppress_default_attributes.split(",")));
		}
		catch (ASelectConfigException e) {
			_suppress_default_attributes = null;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No config item 'suppress_default_attributes' found, not suppressing");
			;
		}
		// RH, 20180213, en

//		// RH, 20140925,sn
//		try {
//			String use_sha256 =_sReqSigning = _configManager.getParam(oHandlerConfig, "use_sha256");
//			if ( Boolean.parseBoolean(use_sha256 ))  {
//				_sDefaultSigning = "sha256";
//			}
//		}
//		catch (ASelectConfigException e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'use_sha256' found, normal operation resumes");
//		}
//
//		try {
//			String add_keyname = _configManager.getParam(oHandlerConfig, "add_keyname");
//			if ( Boolean.parseBoolean(add_keyname ))  {
//				_sDefaultAddKeyname = "true";	// lowercase
//			}
//		}
//		catch (ASelectConfigException e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'add_keyname' found, normal operation resumes");
//		}
//
//		try {
//			String add_certifcate = _configManager.getParam(oHandlerConfig, "add_certificate");
//			if ( Boolean.parseBoolean(add_certifcate ))  {
//				_sDefaultAddCertificate = "true";	// lowercase
//			}
//		}
//		catch (ASelectConfigException e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'add_certificate' found, normal operation resumes");
//		}
//		// RH, 20140925,en

	
	}
	
	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		if (elementName.equals(AUTHNREQUEST)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			return authnRequest.getIssuer();
		}
		return null;
	}

	/**
	 * Overrides the default.
	 * 
	 * @param request
	 *            - HttpServletRequest
	 * @param response
	 *            - HttpServletResponse
	 * @return RequestState
	 * @throws ASelectException
	 *             the a select exception
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path="+sPathInfo + " RequestQuery: "+request.getQueryString());
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path=" + sPathInfo+
				" Locale="+request.getLocale().getLanguage()+" Method="+request.getMethod());

		_htSessionContext = null;
		try {
			if (sPathInfo.endsWith(RETURN_SUFFIX)) {
				processReturn(request, response);
			}
			// 20100331, Bauke: added HTTP POST support
			else if (request.getParameter("SAMLRequest") != null || "POST".equals(request.getMethod())) {
				handleSAMLMessage(request, response);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: "+request.getQueryString()+" is not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled ");
		}
		catch (ASelectException e) {  // need this to use the finally clause
			throw e;
		}
		finally {
			// 20130821, Bauke: save friendly name after session is gone
			if (_htSessionContext != null) {
				String sStatus = (String)_htSessionContext.get("status");
				String sAppId = (String)_htSessionContext.get("app_id");
				if ("del".equals(sStatus) && Utils.hasValue(sAppId)) {
					String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
					HandlerTools.setEncryptedCookie(response, "requestor_friendly_name", sUF, _configManager.getCookieDomain(), -1/*age*/, _systemLogger);
				}
			}
			_oSessionManager.finalSessionProcessing(_htSessionContext, true/*update session*/);
		}
		return new RequestState(null);
	}
	
	/**
	 * Tell caller the XML type we want recognized
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @return
	 *		the XML type
	 */
	protected String retrieveXmlType()
	{
		return AUTHNREQUEST;
	}
	
	/**
	 * Handle specific saml20 request.
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @param httpRequest
	 *            the HTTP request
	 * @param httpResponse
	 *            the HTTP response
	 * @param samlMessage
	 *            the saml message to be handled
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			PrintWriter pwOut, SignableSAMLObject samlMessage, String sRelayState)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request " + Thread.currentThread().getId();
		AuthnRequest authnRequest = (AuthnRequest) samlMessage;
		String sQuery = httpRequest.getQueryString();
		String sSpecials = Utils.getParameterValueFromUrl(sQuery, "aselect_specials");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PathInfo="+httpRequest.getPathInfo()+
				" Query="+sQuery+" language="+" Specials="+sSpecials+httpRequest.getParameter("language"));
		
		try {
			Response errorResponse = validateAuthnRequest(authnRequest, httpRequest.getRequestURL().toString());
			if (errorResponse != null) {
				_systemLogger.log(Audit.SEVERE, MODULE, sMethod, "validateAuthnRequest failed");
				sendErrorArtifact(errorResponse, authnRequest, httpRequest, httpResponse, pwOut, sRelayState);
				return;
			}
			// The message is OK
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest received");
			String sAppId = authnRequest.getIssuer().getValue(); // authnRequest.getProviderName();
			String sSPRid = authnRequest.getID();
			String sIssuer = authnRequest.getIssuer().getValue();
			
			// RH, 20210225, sn
			List<String> forced_resourcegroup_keys = new ArrayList<>();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "looking for Scoping RequesterIDs");
			if (authnRequest.getScoping() != null && authnRequest.getScoping().getRequesterIDs() != null) {
				List<RequesterID> reqList = authnRequest.getScoping().getRequesterIDs();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found Scoping RequesterIDs: " + reqList);
				for ( RequesterID requesterid : reqList) {
					forced_resourcegroup_keys.add(requesterid.getRequesterID());
				}
			}
			// RH, 20210225, en
			
			//  RH, 20101101, get the requested binding, can be null
			String sReqBinding = authnRequest.getProtocolBinding();
			boolean bForcedAuthn = authnRequest.isForceAuthn();
			
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested binding="+sReqBinding+" ForceAuthn = " + bForcedAuthn);
			// RH, 20140922, sn
			boolean bIsPassive = authnRequest.isPassive();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Requested binding="+sReqBinding+" ForceAuthn = " + bForcedAuthn + " IsPassive = " + bIsPassive);
			// RH, 20140922, en

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "SPRid=" + sSPRid + " RelayState=" + sRelayState);

			HashMap<String, String> hmBinding = new HashMap<String, String>();
			String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(samlMessage, hmBinding);
			if (sAssertionConsumerServiceURL == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "AssertionConsumerServiceURL not found");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INVALID_REQUEST);
			}
			// 20120313, Bauke: 
			if (!Utils.hasValue(sReqBinding))
				sReqBinding = hmBinding.get("binding");

			// Start an authenticate request, we've done signature checking already, so do not ask to do it again
			// Also performAuthenticateRequest is an internal call, so who wants signing
			// 20110407, Bauke: check sig set to false
			_systemLogger.log(Level.INFO, MODULE, sMethod, "performAuthenticateRequest AppId=" + sAppId+" binding="+sReqBinding);
			HashMap<String, Object> htResponse = performAuthenticateRequest(_sASelectServerUrl, httpRequest.getPathInfo(),
					RETURN_SUFFIX, sAppId, false /* check sig */, _oClientCommunicator);

			String sASelectServerUrl = (String) htResponse.get("as_url");
			String sIDPRid = (String) htResponse.get("rid");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Supplied rid=" + sIDPRid + " response=" + htResponse);

			// We need the session
			//_htSessionContext = _oSessionManager.getSessionContext(sIDPRid);
			_htSessionContext = (HashMap<String, Object>) htResponse.get("session");  // 20120404, Bauke: was getSessionContext(sIDPRid)
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + sIDPRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			if (sRelayState != null) {
				_htSessionContext.put("RelayState", sRelayState);
			}
			// 20121029, Bauke, language bug solved.
			String sLanguage = httpRequest.getParameter("language");
			if (Utils.hasValue(sLanguage))
				_htSessionContext.put("language", sLanguage);
			if (Utils.hasValue(sSpecials))
				_htSessionContext.put("aselect_specials", sSpecials);
			_htSessionContext.put("sp_rid", sSPRid);
			_htSessionContext.put("sp_issuer", sIssuer);
			_htSessionContext.put("sp_assert_url", sAssertionConsumerServiceURL);
			
			// RH, 20210225, sn
			if (!forced_resourcegroup_keys.isEmpty())
				_htSessionContext.put("sp_forced_resourcegroup_keys", forced_resourcegroup_keys);
			// RH, 20210225, en

			// RH, 20180625, sn
			String appEndEntityID = ApplicationManager.getHandle().getApplicationEndpointAudience(sAppId);
			if ( appEndEntityID != null && appEndEntityID.length() > 0) {
				_htSessionContext.put("sp_audience", appEndEntityID);
			}
			// RH, 20180625, sn
			
			// RH, 20101101, Save requested binding for when we return from authSP
			// 20110323, Bauke: if no requested binding, take binding from metadata
			if (Utils.hasValue(sReqBinding))  // 20120313, Bauke: added test
				_htSessionContext.put("sp_reqbinding", sReqBinding);  // 20120313: hmBinding.get("binding"));  // 20110323: sReqBinding);

			// RH, 20140922, sn
			if (bIsPassive) {
				_htSessionContext.put("forced_passive", new Boolean(bIsPassive)); 
				_systemLogger.log(Level.FINER, MODULE, sMethod, "'forced_passive' in htSession set to: "
						+ bIsPassive);
			}
			// RH, 20140922, en
			
			// RH, 20081117, strictly speaking forced_logon != forced_authenticate
			// 20090613, Bauke: 'forced_login' is used as API parameter (a String value)
			// 'forced_authenticate' is used in the Session (a Boolean value), the meaning of both is identical
			if (bForcedAuthn) {
				_htSessionContext.put("forced_authenticate", new Boolean(bForcedAuthn));
				_systemLogger.log(Level.FINER, MODULE, sMethod, "'forced_authenticate' in htSession set to: "
						+ bForcedAuthn);
			}
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: added

			// The betrouwbaarheidsniveau is stored in the session context
			RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
			HashMap<String, String> secLevels =  ApplicationManager.getHandle().getSecLevels(sAppId);
			
//			boolean useLoa = (_sSpecialSettings != null && _sSpecialSettings.contains("use_loa"));
			String addedPatching = ApplicationManager.getHandle().getAddedPatching(sAppId);
			boolean useLoa = (addedPatching != null && addedPatching.contains("use_loa")) || (_sSpecialSettings != null && _sSpecialSettings.contains("use_loa"));
			
			_systemLogger.log(Level.FINER, MODULE, sMethod, "useLoa="+useLoa);
//			boolean useNewLoa = (_sSpecialSettings != null && _sSpecialSettings.contains("use_newloa"));
			boolean useNewLoa = (addedPatching != null && addedPatching.contains("use_newloa")) || (_sSpecialSettings != null && _sSpecialSettings.contains("use_newloa"));
			_systemLogger.log(Level.FINER, MODULE, sMethod, "useNewLoa="+useNewLoa);
			String sBetrouwbaarheidsNiveau = null;
			if (useNewLoa) {	// fix for new loa levels
				sBetrouwbaarheidsNiveau = SecurityLevel.getComparedSecurityLevelUsingExternal(requestedAuthnContext, secLevels, useLoa, SecurityLevel.getNewLoaLevels(), _systemLogger);
			} else {
				sBetrouwbaarheidsNiveau = SecurityLevel.getComparedSecurityLevelUsingExternal(requestedAuthnContext, secLevels, useLoa, SecurityLevel.getDefaultLevels(), _systemLogger);
			}
			if (sBetrouwbaarheidsNiveau == null) {
				// We've got a security level but it is not known
				String sStatusMessage = "The requested AuthnContext isn't present in the configuration";
				errorResponse = errorResponse(sSPRid, sAssertionConsumerServiceURL, StatusCode.NO_AUTHN_CONTEXT_URI,
						sStatusMessage);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage);
				sendErrorArtifact(errorResponse, authnRequest, httpRequest, httpResponse, pwOut, sRelayState);
				return;
			}

			// 20090110, Bauke changed requested_betrouwbaarheidsniveau to required_level
			_htSessionContext.put("required_level", sBetrouwbaarheidsNiveau);
			_htSessionContext.put("requested_level", sBetrouwbaarheidsNiveau);
				_htSessionContext.put("level", Integer.parseInt(sBetrouwbaarheidsNiveau)); // 20090111, Bauke added, NOTE: it's an Integer
			
			// 20110722, Bauke conditional setting, should come from configuration however
//			if (Integer.parseInt(sBetrouwbaarheidsNiveau) <= 10)	// RH, 20141113, o
			// Quick fix for PreviousSession. Should somehow be done a different way
			// 20160115, Bauke: Moved to SecurityLevel:
			//if (Integer.parseInt(sBetrouwbaarheidsNiveau) != SecurityLevel.LEVEL_PREVIOUS && Integer.parseInt(sBetrouwbaarheidsNiveau) <= 10)	// RH, 20141113, n, not clear why this is here, try to be backwards compatible anyway
			if (SecurityLevel.isLowLevelButNotPreviousSession(Integer.parseInt(sBetrouwbaarheidsNiveau)))
				_htSessionContext.put("forced_uid", "saml20_user");
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			// redirect with A-Select request=login1
			StringBuffer sbURL = new StringBuffer(sASelectServerUrl);
			sbURL.append("&rid=").append(sIDPRid);
			sbURL.append("&a-select-server=").append(_sASelectServerID);
			if (bForcedAuthn)
				sbURL.append("&forced_logon=").append(bForcedAuthn);
			if (bIsPassive)
				sbURL.append("&forced_passive=").append(bIsPassive);	// RH, 20140925, n
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Redirect to " + sbURL.toString());
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Challenge for credentials, redirect to:"
					+ sbURL.toString());
			httpResponse.sendRedirect(sbURL.toString());
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML AuthnRequest handled");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, Auxiliary.obfuscate(XMLHelper.prettyPrintXML(samlMessage.getDOM()), 
					Auxiliary.REGEX_PATTERNS));
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}
	
	/**
	 * The incoming AuthnRequest is something like:
	 * 
	 * <pre>
	 * &lt;sp:AuthnRequest
	 * xmlns:sp=&quot;urn:oasis:names:tc:SAML:2.0:protocol&quot;
	 * AssertionConsumerServiceURL=&quot;https://localhost:8780/SP-A&quot;
	 * Destination=&quot;https://localhost:8880/IDP-F&quot;
	 * ForceAuthn=&quot;false&quot;
	 * ID=&quot;RTXXcU5moVW3OZcvnxVoc&quot;
	 * IsPassive=&quot;false&quot;
	 * IssueInstant=&quot;2007-08-13T11:29:11Z&quot;
	 * ProtocolBinding=&quot;urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact&quot;
	 * ProviderName=&quot;SP 1&quot;
	 * Version=&quot;2.0&quot;&gt;
	 * &lt;sa:Issuer
	 * xmlns:sa=&quot;urn:oasis:names:tc:SAML:2.0:assertion&quot;
	 * Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:entity&quot;&gt;
	 * https://localhost:8780/sp.xml
	 * &lt;/sa:Issuer&gt;
	 * &lt;sp:NameIDPolicy
	 * AllowCreate=&quot;true&quot;
	 * Format=&quot;urn:oasis:names:tc:SAML:2.0:nameid-format:persistent&quot;&gt;
	 * &lt;/sp:NameIDPolicy&gt;
	 * &lt;/sp:AuthnRequest&gt;
	 * </pre>
	 * 
	 * The following attributes and elements are required (from a business perspective) and are checked on presence: <br>
	 * <br>
	 * <ul>
	 * <li>ProviderName</li>
	 * </ul>
	 * The following constraints come from the SAML Protocol: <br>
	 * <br>
	 * <ul>
	 * <li>If attribute Destination is present it MUST be checked that the URI reference identifies <br>
	 * the location at which the message was received.</li> <br>
	 * <br>
	 * 
	 * @param authnRequest
	 *            the authn request
	 * @param httpRequest
	 *            the http request
	 * @return the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected Response validateAuthnRequest(AuthnRequest authnRequest, String sRequestUrl)
	throws ASelectException
	{
		String sMethod = "validateAuthnRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "RequestUrl=" + sRequestUrl);

		Response errorResponse = null;
		String sInResponseTo = authnRequest.getID(); // Is required in SAMLsyntax
		String sDestination = authnRequest.getAssertionConsumerServiceURL();
		if (sDestination == null) {
			sDestination = "UnknownDestination";
		}
		String sStatusCode = "";
		String sStatusMessage = "";

		/*
		 * The opensaml library already checks that
		 * the 'Destination' attribute from the AuthnRequest matches 'RequestURL'
		 */
		// Check validity interval here
		if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(authnRequest)) {
			sStatusCode = StatusCode.REQUEST_DENIED_URI;
			sStatusMessage = "The time interval in element AuthnRequest is not valid";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sStatusMessage + " Destination="
					+ authnRequest.getDestination() + " RequestUrl=" + sRequestUrl);
			return errorResponse(sInResponseTo, sDestination, sStatusCode, sStatusMessage);
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, sMethod + " successful");
		return errorResponse;
	}

	/**
	 * Gets the assertion consumer service url.
	 * 
	 * @param samlMessage
	 *            the saml message
	 * @param hmBinding
	 *            the hashmap to receive the binding
	 * @return the assertion consumer service url
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getAssertionConsumerServiceURL(SignableSAMLObject samlMessage, HashMap<String, String> hmBinding)
	throws ASelectException
	{
		String sMethod = "getAssertionConsumerServiceURL " + Thread.currentThread().getId();

		String sAssertionConsumerServiceURL = null;
		String sElementName = AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME;
		String elementName = samlMessage.getElementQName().getLocalPart();

		// IDP MUST honor requested sAssertionConsumerServiceURL from AUTHNREQUEST first
		String sBindingName = null;
		if (AUTHNREQUEST.equals(elementName)) {
			AuthnRequest authnRequest = (AuthnRequest) samlMessage;
			sAssertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
			sBindingName = authnRequest.getProtocolBinding();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Location from AuthnRequest="+sAssertionConsumerServiceURL+" binding="+sBindingName);
		}

		if (sAssertionConsumerServiceURL == null) {	// We didn't find it in the authnrequest
			
			Issuer issuer = retrieveIssuer(elementName, samlMessage);
			if (issuer == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "SAMLMessage: " + elementName + " was not recognized");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			String sEntityId = issuer.getValue();
	
			// get from metadata
			MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Looking for EntityId="+sEntityId + " sElementName="+sElementName+
//					" sBindingName="+sBindingName + " in:"+metadataManager.getMetadataURL(sEntityId));	// RH, 20190325, o
					" sBindingName="+sBindingName + " in:"+metadataManager.getMetadataURL(_sResourceGroup, sEntityId));	// RH, 20190325, n
			
			try {
				// if sBindingName was null, binding was not present in the Auhtentication request
//				sAssertionConsumerServiceURL = metadataManager.getLocationAndBinding(sEntityId, sElementName,	// RH, 20190325, o
				sAssertionConsumerServiceURL = metadataManager.getLocationAndBinding(_sResourceGroup, sEntityId, sElementName,	// RH, 20190325, n
						sBindingName, "Location", hmBinding);
			}
			catch (ASelectException e) {
				// Metadata retrieval failed so get it from the message
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to get location: " + e.getMessage());
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Meta done ACurl="+sAssertionConsumerServiceURL+" hmBinding="+hmBinding);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Return " + sAssertionConsumerServiceURL+" binding="+hmBinding);
		return sAssertionConsumerServiceURL;
	}

	/**
	 * Error response, send error artifact.
	 * 
	 * @param errorResponse
	 *            the error response
	 * @param authnRequest
	 *            the authn request
	 * @param httpResponse
	 *            the http response
	 * @param sRelayState
	 *            the s relay state
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void sendErrorArtifact(Response errorResponse, AuthnRequest authnRequest,
			HttpServletRequest httpRequest, HttpServletResponse httpResponse, PrintWriter pwOut, String sRelayState)
	throws IOException, ASelectException
	{
		String sMethod = "sendErrorArtifact";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");

		String sId = errorResponse.getID();

		Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
		String sArtifact = artifactManager.buildArtifact(errorResponse, _sASelectServerUrl, sId);

		// If the AssertionConsumerServiceURL is missing, redirecting the artifact is senseless
		// So in this case send a message to the browser
		String sAssertionConsumerServiceURL = getAssertionConsumerServiceURL(authnRequest, null);
		if (sAssertionConsumerServiceURL != null) {
			artifactManager.sendArtifact(sArtifact, errorResponse, sAssertionConsumerServiceURL,
					httpRequest, httpResponse, sRelayState, null);
		}
		else {
			String errorMessage = "Something wrong in SAML communication";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, errorMessage);
			pwOut.write(errorMessage);
		}
	}

	// We're returning from the AuthSP
	// RequestQuery: aselect_credentials=7HxCWBudn...W8bAU3OY&rid=4B9FF1406696C0C8&a-select-server=umcn_aselect_server1
	/**
	 * Process return.
	 * 
	 * @param httpRequest
	 *            the http request
	 * @param httpResponse
	 *            the http response
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void processReturn(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
	throws ASelectException
	{
		String sMethod = "processReturn";
		HashMap htTGTContext = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Handle return from the AuthSP");

		try {
			// We have to return to the calling SP using a SAML Artifact
			// RH, 20101101, or maybe another binding
			// If a TgT is present the session has been deleted
			String sRid = (String) httpRequest.getParameter("rid");
			String sTgt = (String) httpRequest.getParameter("aselect_credentials");
			if (sTgt != null && !sTgt.equals("")) {
				sTgt = decryptCredentials(sTgt);
				htTGTContext = getContextFromTgt(sTgt, false); // Don't check expiration
			}
			else {
				_htSessionContext = _oSessionManager.getSessionContext(sRid);
			}

			// One of them must be available
			if (htTGTContext == null && _htSessionContext == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod,
						"Neither TGT context nor Session context are available");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}

			String sAssertUrl = null;
			if (htTGTContext != null)
				sAssertUrl = (String) htTGTContext.get("sp_assert_url");
			if (sAssertUrl == null && _htSessionContext != null)
				sAssertUrl = (String) _htSessionContext.get("sp_assert_url");
			if (sAssertUrl == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Return url \"sp_assert_url\" is missing");
				throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
			}

			// 20090603, Bauke: Only take RelayState from the session (not from TgT)
			// If RelayState was given, it must be available in the Session Context.
			String sRelayState = null;
			if (_htSessionContext != null)
				sRelayState = (String) _htSessionContext.get("RelayState");
			else
				sRelayState = (String) htTGTContext.get("RelayState");

			// RH, 2011101, retrieve the requested binding
			String sReqBInding = null;
			if (htTGTContext  != null)
				sReqBInding = (String) htTGTContext.get("sp_reqbinding");
			if (sReqBInding == null && _htSessionContext != null )
				sReqBInding = (String) _htSessionContext.get("sp_reqbinding");
			if (sReqBInding == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Requested binding \"sp_reqbinding\" is missing, using default" );
			}

//			retrieveLocalSettings(_htSessionContext, htTGTContext);  // results are placed in this object	//	RH, 20210122, o
			HashMap<String, String> localSettings = retrieveLocalSettings(_htSessionContext, htTGTContext);  // results are placed in this object	//	RH, 20210122, n

			// And off you go!
			// 20120719, Bauke added test for post_template!
			if (Saml20_Metadata.singleSignOnServiceBindingConstantPOST.equals(sReqBInding) && getPostTemplate() != null) {
				_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Redirecting with post to: " + sAssertUrl);
//				sendSAMLResponsePOST(sAssertUrl, sRid, _htSessionContext, sTgt, htTGTContext, httpRequest, httpResponse, sRelayState);
				sendSAMLResponsePOST(sAssertUrl, sRid, _htSessionContext, sTgt, htTGTContext, httpRequest, httpResponse, sRelayState, localSettings);
			}
			else {	// use artifact as default (for backward compatibility) 
				if (Saml20_Metadata.singleSignOnServiceBindingConstantPOST.equals(sReqBInding)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Requested POST binding but post_template missing, doing redirect" );
				}
				_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Redirecting with artifact to: " + sAssertUrl);
//				sendSAMLArtifactRedirect(sAssertUrl, sRid, _htSessionContext, sTgt, htTGTContext, httpRequest, httpResponse, sRelayState);
				sendSAMLArtifactRedirect(sAssertUrl, sRid, _htSessionContext, sTgt, htTGTContext, httpRequest, httpResponse, sRelayState, localSettings);
			}
			_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> Return from AuthSP handled");

			// Cleanup for a forced_authenticate session
//			Boolean bForcedAuthn = (Boolean) htTGTContext.get("forced_authenticate");	// 20140924, o
			Boolean bForcedAuthn = (htTGTContext == null) ? null : (Boolean) htTGTContext.get("forced_authenticate");	// 20140924, n
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			if (bForcedAuthn && htTGTContext != null) {
				TGTManager tgtManager = TGTManager.getHandle();
				tgtManager.remove(sTgt);
			}
			Tools.calculateAndReportSensorData(ASelectConfigManager.getHandle(), _systemLogger, "srv_s20", sRid, _htSessionContext, sTgt, true);
			if (bForcedAuthn && _htSessionContext != null) {
				_oSessionManager.setDeleteSession(_htSessionContext, _systemLogger);  //20120403, Bauke: was killSession
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

	/**
	 * Send saml artifact error redirect.
	 * If htTGTContext is null we have to create an error <Response>, send no Assertion, just <Status>
	 * 
	 * @param sAppUrl
	 *            the s app url
	 * @param sRid
	 *            the s rid
	 * @param htSessionContext
	 *            the ht session context
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param servletResponse
	 *            the o http servlet response
	 * @param sRelayState
	 *            the s relay state
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLArtifactRedirect(String sAppUrl, String sRid, HashMap htSessionContext, String sTgt,
//			HashMap htTGTContext, HttpServletRequest servletRequest, HttpServletResponse servletResponse, String sRelayState)
			HashMap htTGTContext, HttpServletRequest servletRequest, HttpServletResponse servletResponse, String sRelayState, HashMap<String, String> localsettings )
	throws ASelectException
	{
		String sMethod = "sendSAMLArtifactRedirect";

//		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext);
		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext, localsettings);
			
		Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "buildArtifact serverUrl=" + _sASelectServerUrl + " rid=" + sRid);
		String sArtifact = artifactManager.buildArtifact(response, _sASelectServerUrl, sRid);
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "sendArtifact " + sArtifact);
//			artifactManager.sendArtifact(sArtifact, response, sAppUrl, servletRequest, servletResponse, sRelayState, _sAddedPatching);
			artifactManager.sendArtifact(sArtifact, response, sAppUrl, servletRequest, servletResponse, sRelayState, localsettings.get(LOCALS_NAME_ADDED_PATCHING));
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Redirect to : '" + sAppUrl + "' failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}


	/**
	 * Send SAMLResponse POST redirect.
	 * 
	 * @param sAppUrl
	 *            the app url
	 * @param sRid
	 *            the RID
	 * @param htSessionContext
	 *            the session context
	 * @param sTgt
	 *            the TGT
	 * @param htTGTContext
	 *            the tgt context
	 * @param servletResponse
	 *            the http servlet response
	 * @param sRelayState
	 *            the relay state
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	private void sendSAMLResponsePOST(String sAppUrl, String sRid, HashMap htSessionContext, String sTgt,
//			HashMap htTGTContext, HttpServletRequest servletRequest, HttpServletResponse servletResponse, String sRelayState)
			HashMap htTGTContext, HttpServletRequest servletRequest, HttpServletResponse servletResponse, String sRelayState, HashMap<String, String> localsettings)
	throws ASelectException
	{
		String sMethod = "sendSAMLResponsePOST";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signing >======");
//		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext);
		Response response = buildSpecificSAMLResponse(sRid, htSessionContext, sTgt, htTGTContext, localsettings);
		
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response SignAssertion=" + _bSignAssertion+" sha="+ _sReqSigning);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Response SignAssertion=" + localsettings.get(LOCALS_NAME_SIGN_ASSERTION)+" sha="+ localsettings.get(LOCALS_NAME_REQ_SIGNING));
//		if (_bSignAssertion) {
		if ( Boolean.parseBoolean(localsettings.get(LOCALS_NAME_SIGN_ASSERTION)) ) {
			// Only the assertion must be signed, actually this is a MUST for this profile according to the saml specs.
			try {
				// don't forget to marshall the response when no signing will be done here
				org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot marshall object", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		else {  // No assertion signing, sign the complete response
//			response = (Response)SamlTools.signSamlObject(response, _sReqSigning, 
//							"true".equals(_sAddKeyName), "true".equals(_sAddCertificate));	// RH, 20180918, o
//			response = (Response)SamlTools.signSamlObject(response, _sReqSigning, 
			response = (Response)SamlTools.signSamlObject(response,localsettings.get(LOCALS_NAME_REQ_SIGNING), 
//					"true".equals(_sAddKeyName), "true".equals(_sAddCertificate), null);	// RH, 20180918, n
//					"true".equals(localsettings.get(LOCALS_NAME_ADD_KEY_NAME)), "true".equals(_sAddCertificate), null);	// RH, 20180918, n
					"true".equals(localsettings.get(LOCALS_NAME_ADD_KEY_NAME)), "true".equals(localsettings.get(LOCALS_NAME_ADD_CERTIFICATE)), null);	// RH, 20180918, n
		}
		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Response signing ======<"+response);
		
		String sResponse = XMLHelper.nodeToString(response.getDOM());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Response=" + Auxiliary.obfuscate(sResponse, Auxiliary.REGEX_PATTERNS));
		try {
			byte[] bBase64Assertion = sResponse.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			sResponse = b64enc.encode(bBase64Assertion);
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}

		String sp_assert_url = null;
		if (htTGTContext  != null)
			sp_assert_url = (String) htTGTContext.get("sp_assert_url");
		if (sp_assert_url == null && htSessionContext != null )
			sp_assert_url = (String) htSessionContext.get("sp_assert_url");
		if (sp_assert_url== null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No assertion consumer url provided");
			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);	
		}

		// Handle RelayState
		try {
			byte[] bBase64RelayState = sAppUrl.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			sAppUrl = b64enc.encode(bBase64RelayState);
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if ("".equals(sRelayState))
			sRelayState = sAppUrl;	// By convention we load RelayState with appURL

		String sInputs = buildHtmlInput("RelayState", sRelayState);
		String sLang = null;
		if (htTGTContext  != null)
			sLang = (String) htTGTContext.get("language");
		if (sLang == null && htSessionContext != null )
			sLang = (String) htSessionContext.get("language");
		if (sLang != null)
			sInputs += buildHtmlInput("language",sLang);
		
		// Keep logging short:
		_systemLogger.log(Level.FINER, MODULE, sMethod, "Template="+getPostTemplate()+" sInputs="+sInputs+" ...");
		sInputs += buildHtmlInput("SAMLResponse", sResponse);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));

		// Let's POST the token
		if (getPostTemplate() != null) {
			String sSelectForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
					getPostTemplate(), _sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
			handlePostForm(sSelectForm, sp_assert_url, sInputs, servletRequest, servletResponse);
		}
		else {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No POST template found");
			throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
		}	
	}
	
	// RH, 20210122, sn
	// Using new mechanism retrieving localsettings
	/**
	 * Retrieve several settings for session and/or context
	 * 
	 * @param htSessionContext the session context
	 * @param htTGTContext the ticket
	 * @return HashMap<String,String> containing localsettings
	 */
	private HashMap<String,String> retrieveLocalSettings(HashMap htSessionContext, HashMap htTGTContext)
	{
		String sMethod = "retrieveLocalSettings";
		HashMap<String,String> locals = new HashMap<String,String>();
		
		String sAppId = null;
		String sAddedPatching = null;
		boolean bSignAssertion = false;
		String sReqSigning = null;
		String sAddKeyName = null;
		String sAddCertificate = null;
		
		// 20110526, Bauke: prefer sp_issuer if present (which is probably always)
		if (htTGTContext != null) {
			sAppId = (String)htTGTContext.get("sp_issuer");
			if (sAppId == null)
				sAppId = (String) htTGTContext.get("app_id");
		}
		if (sAppId == null && htSessionContext != null) {
			sAppId = (String)htSessionContext.get("sp_issuer");
			if (sAppId == null)
				sAppId = (String) htSessionContext.get("app_id");
		}
		if (sAppId == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve app_id from any context" );
		}

		if (sAppId != null) {	// application level overrules handler level configuration
			sAddedPatching = ApplicationManager.getHandle().getAddedPatching(sAppId);
		}

		if (sAddedPatching == null) {	// backward compatibility, get it from handler configuration
			sAddedPatching = _configManager.getAddedPatching() != null ? _configManager.getAddedPatching() : "";
		}
		bSignAssertion = sAddedPatching.contains("sign_assertion");  // this is an application attribute
		
		if (htTGTContext  != null)
			sReqSigning = (String) htTGTContext.get("sp_reqsigning");
		if (sReqSigning == null && htSessionContext != null )
			sReqSigning = (String) htSessionContext.get("sp_reqsigning");
		if (sReqSigning == null) {
			sReqSigning = _sDefaultSigning;
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Requested signing \"sp_reqsigning\" is missing, using default: " + sReqSigning);
		}

		if (!"sha256".equals(sReqSigning))  // we only support sha256 and sha1
			sReqSigning = "sha1";

		if (htTGTContext  != null)
			sAddKeyName = (String) htTGTContext.get("sp_addkeyname");
		if (sAddKeyName == null && htSessionContext != null )
			sAddKeyName = (String) htSessionContext.get("sp_addkeyname");
		if (sAddKeyName == null) {
			sAddKeyName = _sDefaultAddKeyname;
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Requested signing \"sp_addkeyname\" is missing, using default:" + sAddKeyName );
		}

		if (htTGTContext  != null)
			sAddCertificate = (String) htTGTContext.get("sp_addcertificate");
		if (sAddCertificate == null && htSessionContext != null )
			sAddCertificate = (String) htSessionContext.get("sp_addcertificate");
		if (sAddCertificate == null) {
			sAddCertificate = _sDefaultAddCertificate;
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Requested signing \"sp_addcertificate\" is missing, using default:" + sAddCertificate);
		}
		
		locals.put(LOCALS_NAME_APP_ID, sAppId);
		locals.put(LOCALS_NAME_ADDED_PATCHING, sAddedPatching);
		locals.put(LOCALS_NAME_SIGN_ASSERTION, Boolean.toString(bSignAssertion));
		locals.put(LOCALS_NAME_REQ_SIGNING, sReqSigning);
		locals.put(LOCALS_NAME_ADD_KEY_NAME, sAddKeyName);
		locals.put(LOCALS_NAME_ADD_CERTIFICATE, sAddCertificate);
		
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved locals="+locals);
		return locals;
	}
	// RH, 20210122, en
	
	/**
	 * Build a SAML response and return it.
	 * 
	 * @param sRid
	 *            the s rid
	 * @param htSessionContext
	 *            the ht session context
	 * @param sTgt
	 *            the s tgt
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param oHttpServletResponse
	 *            the o http servlet response
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
//	private Response buildSpecificSAMLResponse(String sRid, HashMap htSessionContext, String sTgt, HashMap htTGTContext)
	private Response buildSpecificSAMLResponse(String sRid, HashMap htSessionContext, String sTgt, HashMap htTGTContext, 
			HashMap<String, String> localsettings)
	throws ASelectException
	{
		String sMethod = "buildSpecificSAMLResponse";
		boolean isSuccessResponse = (htTGTContext != null);
		Assertion assertion = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "====");
		
		
		DateTime tStamp = new DateTime(); // We will use one timestamp

		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);

		String sSPRid = null;
		
		if (htSessionContext != null) {
			sSPRid = (String) htSessionContext.get("sp_rid");
		} else {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "htSessionContext is null."); //BW
		}
		
		
		if (htTGTContext != null) {
			
			sSPRid = (String) htTGTContext.get("sp_rid");
			String sSelectedLevel = null;
						
			// 20210914, BW sn 	
			String applicationId = (String) htTGTContext.get("app_id");
		
			boolean returnRequestedLevel = ApplicationManager.getHandle().isReturnRequestedLevel(applicationId);
						
			if(returnRequestedLevel) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "return_requested_level parameter: " + returnRequestedLevel);
				String requestedLevel = (String) htTGTContext.get("requested_level");
				// set sSelectedLevel to requestedLevel
				if(requestedLevel != null) {
					
					// return level moet hoger zijn dan de applicatie level, anders applicatie level terug
					
					
					
					sSelectedLevel = requestedLevel;
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "sSelectedLevel overwritten with requested_level: " + sSelectedLevel);
				} else {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "sSelectedLevel not overwritten, requested_level == null");
				}				
			} // 20210915, BW en 
			
			// String sSelectedLevel = (String) htTGTContext.get("sel_level");
			if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("sel_level");
			if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("authsp_level");
			if (sSelectedLevel == null) sSelectedLevel = (String) htTGTContext.get("betrouwbaarheidsniveau");  // To be removed
			String sUid = (String) htTGTContext.get("uid");
			String sCtxRid = (String) htTGTContext.get("rid");
			String sSubjectLocalityAddress = (String) htTGTContext.get("client_ip");
			String sAssertionID = SamlTools.generateIdentifier(_systemLogger, MODULE);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "CHECK ctxRid=" + sCtxRid + " rid=" + sRid
					+ " client_ip=" + sSubjectLocalityAddress);

			// ---- Attributes
			// Create an attribute statement builder
			QName qName = AttributeStatement.DEFAULT_ELEMENT_NAME;
			_systemLogger.log(Level.FINER, MODULE, sMethod, "AttributeStatement qName="+qName);
			SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder =
				(SAMLObjectBuilder<AttributeStatement>) builderFactory.getBuilder(qName);
			AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

			// Create an attribute builder
			qName = Attribute.DEFAULT_ELEMENT_NAME;
//			_systemLogger.log(Level.FINER, MODULE, sMethod, "Attribute qName="+qName+" AppId="+_sAppId);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Attribute qName="+qName+" AppId="+localsettings.get(LOCALS_NAME_APP_ID));
			
			SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(qName);

			// Gather attributes, including the attributes from the ticket context
			HashMap htAttributes = getAttributesFromTgtAndGatherer(htTGTContext);
			String sAllAttributes = org.aselect.server.utils.Utils.serializeAttributes(htAttributes);

			// 20090910, Bauke: new mechanism to pass the attributes
			HashMap htAllAttributes = new HashMap();
			// RH, 20180213, so

			// RH, 20180213, eo
			// RH, 20180213, sn
			if (_suppress_default_attributes != null) {
				if (!_suppress_default_attributes.contains("attributes")) {
					htAllAttributes.put("attributes", sAllAttributes);
				}
				if (!_suppress_default_attributes.contains("uid")) {
					htAllAttributes.put("uid", sUid);
				}
				if (!_suppress_default_attributes.contains("betrouwbaarheidsniveau")) {
					htAllAttributes.put("betrouwbaarheidsniveau", sSelectedLevel);
				}
			} else {	// backwards compatibility
			// RH, 20180213, en
				htAllAttributes.put("attributes", sAllAttributes);
				htAllAttributes.put("uid", sUid);
				htAllAttributes.put("betrouwbaarheidsniveau", sSelectedLevel);
			}// RH, 20180213, n

			
			// 20101229, Bauke: add configurable fixed value attributes
//			if (_sAppId != null) {
			if (localsettings.get(LOCALS_NAME_APP_ID) != null) {
//				HashMap<String,String> additionalAttributes = ApplicationManager.getHandle().getAdditionalAttributes(_sAppId);
				HashMap<String,String> additionalAttributes = ApplicationManager.getHandle().getAdditionalAttributes(localsettings.get(LOCALS_NAME_APP_ID));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "AddAttr="+additionalAttributes);
				// RH, 20180907, sn
//				Set<Pattern> additionalRegex = ApplicationManager.getHandle().getAdditionalRexex(_sAppId);
				Set<Pattern> additionalRegex = ApplicationManager.getHandle().getAdditionalRexex(localsettings.get(LOCALS_NAME_APP_ID));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "AddRegex="+additionalRegex);
				if (additionalRegex != null && !additionalRegex.isEmpty() ) {
					Set<String> attrNames = htAttributes.keySet();
					for ( Pattern p : additionalRegex) {
						for (String attrName : attrNames) {
							if (p.matcher(attrName).matches()) {
								if (additionalAttributes == null) {
									additionalAttributes = new HashMap<String,String>();
								}
								additionalAttributes.put(attrName, null);
							}
						}
					}
				}
				// RH, 20180907, en

				if (additionalAttributes != null) {
					Set<String> keys = additionalAttributes.keySet();
					for (String sKey : keys) {
//						String sValue = additionalAttributes.get(sKey);	// RH, 20130115, o
						Object sValue = additionalAttributes.get(sKey);	// RH, 20130115, sn
						if (sValue == null) {	
							sValue = htAttributes.get(sKey);
						}// RH, 20130115, en
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved Attr "+sKey+"="+Auxiliary.obfuscate(sValue));
						htAllAttributes.put(sKey, sValue);
					}
				}
			}
			List <PublicKey> pubKeys = null;

			Set keys = htAllAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String)s;
//				Object oValue = htAllAttributes.get(sKey);
//				if (!(oValue instanceof String))
//					continue;
				Iterable aValues = null;
				
				Object anyValue = htAllAttributes.get(sKey);
				if ((anyValue instanceof String)) {
					Vector v = new Vector();
					v.add(anyValue);
					aValues = v;
				} else	if ((anyValue instanceof Iterable)) {
						aValues = (Iterable)anyValue;
				} else {
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Non Iterable attribute found, skipping:  "+sKey+"="+aValues);	// RH, 20190129, o
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Non Iterable attribute found, skipping:  "+sKey+"="+Auxiliary.obfuscate(aValues));	// RH, 20190129, n
					
					continue;
				}

//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Setting Attr "+sKey+"="+aValues);	// RH, 20190129, o
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Setting Attr "+sKey+"="+Auxiliary.obfuscate(aValues));	// RH, 20190129, n
				// RH, 20210712, sn
				// Should we do some encryption
				// Get the pubKeys only once
				if (pubKeys == null && 
						(isEncryptAttribute(sKey, localsettings.get(LOCALS_NAME_APP_ID))
								|| isEncryptAttributeValue(sKey, localsettings.get(LOCALS_NAME_APP_ID)) )) {	// we will only retrieve the puKeys once
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retieving pubKeys for: " + localsettings.get(LOCALS_NAME_APP_ID));
									// for now use resource = null
					// RH, 20210812, sn
					// First try to locate encryption certificate
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Trying 'use' encryption first");
					pubKeys = retrievePublicKeys(null, localsettings.get(LOCALS_NAME_APP_ID), UsageType.ENCRYPTION);
					// if none found fall back to signing certificate
					if (pubKeys == null || pubKeys.size() == 0) {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Now trying 'use' signing as fallback");
						pubKeys = retrievePublicKeys(null, localsettings.get(LOCALS_NAME_APP_ID));
					}
					// RH, 20210812, en
//					pubKeys = retrievePublicKeys(null, localsettings.get(LOCALS_NAME_APP_ID));	// RH, 20210812, o
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retieved pupKeys: " + pubKeys);
				}
				//
				// RH, 20210712, en
				Attribute theAttribute = attributeBuilder.buildObject();
				for ( Object oValue : aValues) {
					String sValue = null;
					if ((oValue instanceof String)) {
						sValue = (String)oValue;
					} else {
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Non String attribute found, skipping:  "+sKey+"="+aValues);	// RH, 20190129, o
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Non String attribute found, skipping:  "+sKey+"="+Auxiliary.obfuscate(aValues));	// RH, 20190129, n	//RH,  20200615, o
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Non String attribute value found, only String type supported, skipping: " +Auxiliary.obfuscate(oValue));	// RH, 20190129, n	//RH,  20200615, n
						continue;
					}
					
	//				Attribute theAttribute = attributeBuilder.buildObject();
					theAttribute.setName(sKey);
//					XSString theAttributeValue = null;	// RH, 20200616, o
//					boolean bNvlAttrName = _sAddedPatching.contains("nvl_attrname");
					boolean bNvlAttrName = localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("nvl_attrname");
					if (bNvlAttrName) {
						// add namespaces to the attribute
						_systemLogger.log(Level.FINER, MODULE, sMethod, "nvl_attrname");
//						boolean bXS = _sAddedPatching.contains("nvl_attr_namexsd");
						boolean bXS = localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("nvl_attr_namexsd");
						Namespace namespace = new Namespace(XMLConstants.XSD_NS, (bXS)? "xsd": XMLConstants.XSD_PREFIX);
						theAttribute.addNamespace(namespace);
						namespace = new Namespace(XMLConstants.XSI_NS, XMLConstants.XSI_PREFIX);
						theAttribute.addNamespace(namespace);
						theAttribute.setNameFormat(Attribute.BASIC);  // URI_REFERENCE);  // BASIC);
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Novell Attribute="+theAttribute);
					}
					// RH, 20200616, sn
					// SAML2 specs say, no Empty values allowed 
					if (sValue != null && sValue.length()>0 ) {	// Should not be null nor length = 0
						XSString theAttributeValue = null;
//						// RH, 20200616, en
						theAttributeValue = (XSString)stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
						theAttributeValue.setValue(sValue);
						// RH, 20210715, sn
						// Should we encrypt theAttributeValue
						if (isEncryptAttributeValue(sKey, localsettings.get(LOCALS_NAME_APP_ID))) {
							XMLObjectBuilder<XSAny> xsAnyBuilder = builderFactory.getBuilder(XSAny.TYPE_NAME);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "xsAnyBuilder: " +xsAnyBuilder);
							XSAny anyAttributeValue = xsAnyBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "anyAttributeValue: " +anyAttributeValue);
							XMLObject encryptedAttributeValue =  SamlTools.encryptSamlObjectValue( theAttributeValue, pubKeys.get(0));
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "encryptedAttributeValue: " +encryptedAttributeValue);
							anyAttributeValue.getUnknownXMLObjects().add(encryptedAttributeValue);
							theAttribute.getAttributeValues().add(anyAttributeValue);
						} else {
							theAttribute.getAttributeValues().add(theAttributeValue);
						}
						//
						// RH, 20210715, en
//						theAttribute.getAttributeValues().add(theAttributeValue);	// RH, 20210715, o
					// RH, 20200616, sn
					} else {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Empty attribute value found, skipping empty value for key: "+sKey);
					}
//					// RH, 20200616, en
				}
				// Or should we encrypt the entire attibute
				// For test we'll try to encrypt the entire attribute
				if (isEncryptAttribute(sKey, localsettings.get(LOCALS_NAME_APP_ID))) {
//					theAttribute = SamlTools.encryptSamlObject(theAttribute, pubKeys.get(0));	// Just take the first for now
					attributeStatement.getEncryptedAttributes().add((EncryptedAttribute) SamlTools.encryptSamlObject(theAttribute, pubKeys.get(0)));
				} else {
					attributeStatement.getAttributes().add(theAttribute); // add the plain attribute
				}
				//
//				attributeStatement.getAttributes().add(theAttribute); // add this attribute	// RH, 202210713, o
			}
			
			// ---- AuthenticationContext
			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
			
			// RH, 20101214, sn
			String sAutnContextClassRefURI = null;
//			HashMap<String, String> secLevels =  ApplicationManager.getHandle().getSecLevels(_sAppId);
			HashMap<String, String> secLevels =  ApplicationManager.getHandle().getSecLevels(localsettings.get(LOCALS_NAME_APP_ID));
			if (secLevels != null) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "secLevels="+secLevels);
				sAutnContextClassRefURI = secLevels.get(sSelectedLevel);
			}
			if (sAutnContextClassRefURI == null) {	// for backward compatability
				// Throws an exception on invalid levels:
//				boolean useLoa = (_sSpecialSettings != null && _sSpecialSettings.contains("use_loa"));
//				String addedPatching = ApplicationManager.getHandle().getAddedPatching(_sAppId);
				String addedPatching = ApplicationManager.getHandle().getAddedPatching(localsettings.get(LOCALS_NAME_APP_ID));
				boolean useLoa = (addedPatching != null && addedPatching.contains("use_loa")) || (_sSpecialSettings != null && _sSpecialSettings.contains("use_loa"));

				_systemLogger.log(Level.FINER, MODULE, sMethod, "useLoa="+useLoa);
//				boolean useNewLoa = (_sSpecialSettings != null && _sSpecialSettings.contains("use_newloa"));
				boolean useNewLoa = (addedPatching != null && addedPatching.contains("use_newloa")) || (_sSpecialSettings != null && _sSpecialSettings.contains("use_newloa"));

				_systemLogger.log(Level.FINER, MODULE, sMethod, "useNewLoa="+useNewLoa);
				if (useNewLoa) {	// fix for new loa levels
					sAutnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sSelectedLevel, useLoa, SecurityLevel.getNewLoaLevels(), _systemLogger);
				} else {
					sAutnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sSelectedLevel, useLoa, SecurityLevel.getDefaultLevels(), _systemLogger);
				}
			}				
			// RH, 20101214, en
			authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);

			SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
					.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
			AuthnContext authnContext = authnContextBuilder.buildObject();
			authnContext.setAuthnContextClassRef(authnContextClassRef);
			
			
			// RH, 20141002, sn
			// for eHerk authnContext AuthenticatingAuthorities MUST contain EntityID of AD
//			if ( ApplicationManager.getHandle().getAuthenticatingAuthority(_sAppId) != null ) {
			if ( ApplicationManager.getHandle().getAuthenticatingAuthority(localsettings.get(LOCALS_NAME_APP_ID)) != null ) {
				SAMLObjectBuilder<AuthenticatingAuthority> authenticatingAuthorityBuilder = (SAMLObjectBuilder<AuthenticatingAuthority>) builderFactory
																.getBuilder(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
				AuthenticatingAuthority authAuth = authenticatingAuthorityBuilder.buildObject();
//				authAuth.setURI(ApplicationManager.getHandle().getAuthenticatingAuthority(_sAppId));		// get from application section
				authAuth.setURI(ApplicationManager.getHandle().getAuthenticatingAuthority(localsettings.get(LOCALS_NAME_APP_ID)));		// get from application section
				authnContext.getAuthenticatingAuthorities().add(authAuth);
			}
			// RH, 20141002, en
			
			
			// RH, 20101217, sn
			// Add application specific context from aselect.xml
//			if ( ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId) != null ) {
			if ( ApplicationManager.getHandle().getAuthnContextDeclValue(localsettings.get(LOCALS_NAME_APP_ID)) != null ) {
//				if (AuthnContextDecl.DEFAULT_ELEMENT_LOCAL_NAME.equals(ApplicationManager.getHandle().getAuthnContextDeclType(_sAppId)) ) {
				if (AuthnContextDecl.DEFAULT_ELEMENT_LOCAL_NAME.equals(ApplicationManager.getHandle().getAuthnContextDeclType(localsettings.get(LOCALS_NAME_APP_ID))) ) {
					SAMLObjectBuilder<AuthnContextDecl> authnContextDeclBuilderBuilder = (SAMLObjectBuilder<AuthnContextDecl>) builderFactory
					.getBuilder(AuthnContextDecl.DEFAULT_ELEMENT_NAME);
					AuthnContextDecl authnContextDecl = authnContextDeclBuilderBuilder.buildObject();
//					authnContextDecl.setTextContent(ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId));
					authnContextDecl.setTextContent(ApplicationManager.getHandle().getAuthnContextDeclValue(localsettings.get(LOCALS_NAME_APP_ID)));
					authnContext.setAuthnContextDecl(authnContextDecl);
				} else {
					SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclBuilderBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) builderFactory
					.getBuilder(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
					AuthnContextDeclRef authnContextDeclRef = authnContextDeclBuilderBuilder.buildObject();
//					authnContextDeclRef.setAuthnContextDeclRef(ApplicationManager.getHandle().getAuthnContextDeclValue(_sAppId));
					authnContextDeclRef.setAuthnContextDeclRef(ApplicationManager.getHandle().getAuthnContextDeclValue(localsettings.get(LOCALS_NAME_APP_ID)));
					authnContext.setAuthnContextDeclRef(authnContextDeclRef);
				}
			}
			// RH, 20101217, sn
			
			SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
					.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
			AuthnStatement authnStatement = authnStatementBuilder.buildObject();
			authnStatement.setAuthnInstant(tStamp);
			
			// Sun doesn't like this:
			// authnStatement.setSessionIndex((String) htTGTContext.get("sp_issuer"));
			String sSessionIndex = sAssertionID.replaceAll("_", "");

			//			authnStatement.setSessionIndex(sSessionIndex);	// RH, 20141006, o
			// RH, 20141006, sn
//			if ( (!_sAddedPatching.contains("saml_sessionindex_none")) && sSessionIndex != null && !"".equals(sSessionIndex) ) {	
			if ( (!localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_sessionindex_none")) && sSessionIndex != null && !"".equals(sSessionIndex) ) {	
				authnStatement.setSessionIndex(sSessionIndex);			}
			// RH, 20141006, sn
									
			/////////////////////////////////////////////////////////////////
			// Always try to set the locality address, except when null or empty
			// or forced supression through added_patching
			// _sAddedPatching.contains("saml_subjectlocality_none")
			
//			if (sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress)) {	// RH, 20141002, o
//			if ( (!_sAddedPatching.contains("saml_subjectlocality_none")) && sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress) ) {		// RH, 20141002, n
			if ( (!localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_subjectlocality_none")) && sSubjectLocalityAddress != null && !"".equals(sSubjectLocalityAddress) ) {		// RH, 20141002, n
				SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) builderFactory
						.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
				SubjectLocality locality = subjectLocalityBuilder.buildObject();
				locality.setAddress(sSubjectLocalityAddress);
				authnStatement.setSubjectLocality(locality);
				// We could also set DNSName in locality, but for now, that's not requested
			}
			// RH, 20141002, sn
			// RH, 20141002, en
			authnStatement.setAuthnContext(authnContext);
			SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
					.getBuilder(Audience.DEFAULT_ELEMENT_NAME);
			Audience audience = audienceBuilder.buildObject();
			
//				audience.setAudienceURI((String) htTGTContext.get("sp_issuer")); // 20081109 added
			// RH, 20160211, sn
			// Overrules Audience if set
//			String sAudience = ApplicationManager.getHandle().getForcedAudience(_sAppId);
			String sAudience = ApplicationManager.getHandle().getForcedAudience(localsettings.get(LOCALS_NAME_APP_ID));
			if (sAudience == null) {
				sAudience = (String) htTGTContext.get("sp_audience");
			}
			// RH, 20160211, en
//			String sAudience = (String) htTGTContext.get("sp_audience");	// 20160211, o
			audience.setAudienceURI( (sAudience != null) ? sAudience : (String) htTGTContext.get("sp_issuer")); // 20101116, RH,  for backward compatibility

			SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
					.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
			AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
			audienceRestriction.getAudiences().add(audience);

			SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
					.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
			subjectConfirmationData = (SubjectConfirmationData) SamlTools.setValidityInterval(
					subjectConfirmationData, tStamp, null, getMaxNotOnOrAfter());
			subjectConfirmationData.setRecipient((String) htTGTContext.get("sp_assert_url"));

			// Bauke: added for OpenSSO 20080329
			subjectConfirmationData.setInResponseTo(sSPRid);

			SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
					.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
			subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);  // "urn:oasis:names:tc:SAML:2.0:cm:bearer"
			subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

			SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) builderFactory
					.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			NameID nameID = nameIDBuilder.buildObject();
			
			// 20100525, flag added for Novell, they need PERSISTENT			
//			boolean bNvlPersist = _sAddedPatching.contains("nvl_persist");
			boolean bNvlPersist = localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("nvl_persist");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "nvl_persist=" + bNvlPersist);
			
			//	RH, 20130117, sn
//			if ( _sAddedPatching.contains("saml_format_persist") ){
			if ( localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_format_persist") ){
				_systemLogger.log(Level.FINE, MODULE, sMethod, "saml_format_persist");
				nameID.setFormat(NameIDType.PERSISTENT);
//			} else if ( _sAddedPatching.contains("saml_format_trans") ){
			} else if ( localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_format_trans") ){
				_systemLogger.log(Level.FINE, MODULE, sMethod, "saml_format_trans");
				nameID.setFormat(NameIDType.TRANSIENT);
//			} else if ( _sAddedPatching.contains("saml_format_unspec") ){
			} else if ( localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_format_unspec") ){
				_systemLogger.log(Level.FINE, MODULE, sMethod, "saml_format_unspec");
				nameID.setFormat(NameIDType.UNSPECIFIED);
//			} else if ( _sAddedPatching.contains("saml_format_none") ){	// do not set a nameid-format
			} else if ( localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_format_none") ){	// do not set a nameid-format
				_systemLogger.log(Level.FINE, MODULE, sMethod, "saml_format_none");
			} else { // backward compatibility with nvl
				nameID.setFormat((bNvlPersist)? NameIDType.PERSISTENT: NameIDType.TRANSIENT);
			}
			//	RH, 20130117, en
//			nameID.setFormat((bNvlPersist)? NameIDType.PERSISTENT: NameIDType.TRANSIENT); // was PERSISTENT originally, RH, 20130117, o

			// nvl_patch, Novell: added
//			if (_sAddedPatching.contains("nvl_patch")) {
			if (localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("nvl_patch")) {
				nameID.setNameQualifier(_sASelectServerUrl);  // NameQualifier
				nameID.setSPNameQualifier((String) htTGTContext.get("sp_issuer"));  // SPNameQualifier
			// RH, 20141002, sn
//			} else if (ApplicationManager.getHandle().getAssertionSubjectNameIDNameQualifier(_sAppId) != null) {
			} else if (ApplicationManager.getHandle().getAssertionSubjectNameIDNameQualifier(localsettings.get(LOCALS_NAME_APP_ID)) != null) {
				//////////////////////////////////////////////
				// for eHerk this MUST contain NameQualiifier with EntityID of MR
				////////////////////////////////////////////
//				nameID.setNameQualifier(ApplicationManager.getHandle().getAssertionSubjectNameIDNameQualifier(_sAppId));
				nameID.setNameQualifier(ApplicationManager.getHandle().getAssertionSubjectNameIDNameQualifier(localsettings.get(LOCALS_NAME_APP_ID)));
			}
			// RH, 20141002, en

			// RH, 20171211, sn
			// application specific takes precedence
			String appSpecNameIDAttribute = ApplicationManager.getHandle().getNameIDAttribute(localsettings.get(LOCALS_NAME_APP_ID));
			if (appSpecNameIDAttribute == null) {
				appSpecNameIDAttribute = _sNameIDAttribute;	// overwrite the value from the handler config if exists
			}
			// RH, 20171211, en
			
			// 20090602, Bauke Saml-core-2.0, section 2.2.2: SHOULD be omitted:
			// nameID.setNameQualifier(_sASelectServerUrl);
			// RH, 20161013, sn
			if (appSpecNameIDAttribute != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "requested attribute for nameid=" + appSpecNameIDAttribute); // RH, 20161013, n
				String sname = (String) htAttributes.get(appSpecNameIDAttribute);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "value found=" + (sname == null ? "" : Auxiliary.obfuscate(sname))); // RH, 20161013, n
				nameID.setValue(sname == null ? "" : sname);
			} else {	// the old way
			// RH, 20161013, en
				nameID.setValue((bNvlPersist)? sUid: sTgt);  // 20100811: depends on NameIDType
			} // RH, 20161013, n
//			_systemLogger.log(Level.FINER, MODULE, sMethod, "nameID=" + Utils.firstPartOf(nameID.getValue(), 30)); // RH, 20161013, o
			_systemLogger.log(Level.FINER, MODULE, sMethod, "nameID=" + Auxiliary.obfuscate(Utils.firstPartOf(nameID.getValue(), 30))); // RH, 20161013, n

			SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
					.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
			Subject subject = subjectBuilder.buildObject();
			subject.setNameID(nameID);
			
			subject.getSubjectConfirmations().add(subjectConfirmation);

			SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
			
			// RH, 20141002, sn
			//////////////////////////////////
			// for eHerk this MUST be ommitted
			
//			if (!_sAddedPatching.contains("saml_format_none")) {
			if (!localsettings.get(LOCALS_NAME_ADDED_PATCHING).contains("saml_format_none")) {
				assertionIssuer.setFormat(NameIDType.ENTITY);
			}
			////////////////////////////////////////
			// RH, 20141002, en

			assertionIssuer.setValue(_sASelectServerUrl);

			SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
					.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
			assertion = assertionBuilder.buildObject();

			assertion.setID(sAssertionID);
			assertion.setIssueInstant(tStamp);
			// Set interval conditions
			assertion = (Assertion) SamlTools.setValidityInterval(assertion, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());
			// and then AudienceRestrictions
			assertion = (Assertion) SamlTools.setAudienceRestrictions(assertion, audienceRestriction);

			assertion.setVersion(SAMLVersion.VERSION_20);
			assertion.setIssuer(assertionIssuer);
			assertion.setSubject(subject);
			assertion.getAuthnStatements().add(authnStatement);
			assertion.getAttributeStatements().add(attributeStatement);

			// 20110406, Bauke: added option to only sign the assertion
//			if (_bSignAssertion) {
			if ( Boolean.parseBoolean(localsettings.get(LOCALS_NAME_SIGN_ASSERTION)) ) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Sign Assertion");
//				assertion = (Assertion)SamlTools.signSamlObject(assertion, _sReqSigning,
//						"true".equals(_sAddKeyName), "true".equals(_sAddCertificate));	// RH, 20180918, o
//				assertion = (Assertion)SamlTools.signSamlObject(assertion, _sReqSigning,
				assertion = (Assertion)SamlTools.signSamlObject(assertion, localsettings.get(LOCALS_NAME_REQ_SIGNING),
//						"true".equals(_sAddKeyName), "true".equals(_sAddCertificate), null);	// RH, 20180918, n
//						"true".equals(localsettings.get(LOCALS_NAME_ADD_KEY_NAME)), "true".equals(_sAddCertificate), null);	// RH, 20180918, n
						"true".equals(localsettings.get(LOCALS_NAME_ADD_KEY_NAME)), "true".equals(localsettings.get(LOCALS_NAME_ADD_CERTIFICATE)), null);	// RH, 20180918, n
			}
		}

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Set StatusCode");
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
//		statusCode.setValue((htTGTContext == null) ? StatusCode.AUTHN_FAILED_URI : StatusCode.SUCCESS_URI);	// RH, 20160125, o
		// RH, 20160125, sn
		// StatusCode must be one of top-level values
		if (htTGTContext != null) {
			statusCode.setValue(StatusCode.SUCCESS_URI);
		} else {
			// set the top-level value
			statusCode.setValue(StatusCode.RESPONDER_URI);
			// build the second-level statuscode
			StatusCode second_level_statusCode = statusCodeBuilder.buildObject();
			second_level_statusCode.setValue(StatusCode.AUTHN_FAILED_URI);
			statusCode.setStatusCode(second_level_statusCode);
		}
		// RH, 20160125, en
		
		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);
		if (htTGTContext == null) {
			String sResultCode = (String) htSessionContext.get("result_code");
			SAMLObjectBuilder<StatusMessage> statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) builderFactory
					.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
			StatusMessage msg = statusMessageBuilder.buildObject();
//			msg.setMessage((sResultCode != null) ? sResultCode : "unspecified error");	// RH, 20140925, o
			msg.setMessage((sResultCode != null) ? sResultCode : Errors.ERROR_ASELECT_SERVER_USER_NOT_ALLOWED);	// RH, 20140925, n
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

		// nvl_patch, Novell: add xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		response.addNamespace(new Namespace(SAMLConstants.SAML20_NS, "saml"));
		
		response.setID("_" + sRid); // 20090512, Bauke: must be NCNAME format
		response.setIssueInstant(tStamp);
		
		String sAssertUrl = null;
		if (htTGTContext != null)
			sAssertUrl = (String) htTGTContext.get("sp_assert_url");
		if (sAssertUrl == null && htSessionContext != null)
			sAssertUrl = (String) htSessionContext.get("sp_assert_url");
		if (sAssertUrl != null) {
			response.setDestination(sAssertUrl);
		} else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Return url \"sp_assert_url\" is missing, no Destination in response");
		}


		response.setVersion(SAMLVersion.VERSION_20);
		response.setStatus(status);
		response.setIssuer(responseIssuer);
		if (isSuccessResponse) {
			response.getAssertions().add(assertion);
		}
		return response;
	}

	// RH, 20210712, sn
	private boolean isEncryptAttributeValue(String sKey, String appid) {
		String sMethod = "isEncryptAttributeValue";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Looking for application: " + appid);

		try {
			HashMap<Pattern, Boolean> encryptAttributes = ApplicationManager.getHandle().getEncryptAtributes(appid);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found patterns: " + encryptAttributes);
			if (encryptAttributes != null) {
				for (Pattern pattern : encryptAttributes.keySet()) {
					Matcher m = pattern.matcher(sKey);
					if (m.matches() && encryptAttributes.get(pattern)) {
						return true;
					}
				}
			} else {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No attribute values to be encrypted, continuing");
			}
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application not found: " + appid);
		}
		return false;
	}


	private boolean isEncryptAttribute(String sKey, String appid) {
		String sMethod = "isEncryptAttribute";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Looking for application: " + appid);

		try {
			HashMap<Pattern, Boolean> encryptAttributes = ApplicationManager.getHandle().getEncryptAtributes(appid);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found patterns: " + encryptAttributes);
			if (encryptAttributes != null) {
				for (Pattern pattern : encryptAttributes.keySet()) {
					Matcher m = pattern.matcher(sKey);
					if (m.matches()  && !encryptAttributes.get(pattern)) {
						return true;
					}
				}
			} else {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No attributes to be encrypted, continuing");
			}
		} catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application not found: " + appid);
		}
		return false;
	}
	// RH, 20210712, en


	public synchronized String getPostTemplate()
	{
		return _sPostTemplate;
	}
	public synchronized void setPostTemplate(String sPostTemplate)
	{
		_sPostTemplate = sPostTemplate;
	}
}