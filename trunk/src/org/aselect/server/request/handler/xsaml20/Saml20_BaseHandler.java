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

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.server.request.handler.xsaml20.sp.MetaDataManagerSp;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Utils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

//
//
public abstract class Saml20_BaseHandler extends ProtoRequestHandler
{
	private final static String MODULE = "Saml20_BaseHandler";

	// RH, 20080602
	// We (Bauke and I) decided that default should be NOT to verify
	// SAML2 says it SHOULD be signed, therefore it's advisable to activate it in the configuration
	private boolean _bVerifySignature = false;
	private boolean verifyResponseSignature = false;
	private boolean verifyAssertionSignature = false;
	
	private boolean _bVerifyInterval = false; // Checking of Saml2 NotBefore and NotOnOrAfter
	private Long maxNotBefore = null; // relaxation period before NotBefore, validity period will be extended with this
	// value (seconds)
	// if null value is not specified in aselect.xml
	private Long maxNotOnOrAfter = null;
	// relaxation period after NotOnOrAfter, validity period will be extended with this value (seconds)
	// if null value is not specified in aselect.xml
	private boolean useBackchannelClientcertificate = false;

	private SSLSocketFactory sslSocketFactory = null;

	// RH, 20151016, sn, refactor pull up from Xsaml20_SSO
	protected String _sReqSigning = null;

	protected String _sAddKeyName = null;

	protected String _sAddCertificate = null;

	protected String _sDefaultSigning = null;

	protected String _sDefaultAddKeyname = null;

	protected String _sDefaultAddCertificate = null;
	// RH, 20151016, en
	
	protected boolean audiencelogout_required = false;

	// RH, 20190319, n, refactor pull up from Xsaml20_ISTS
	protected String _sResourceGroup = null;

	
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
		String sMethod = "init";

		super.init(oServletConfig, oHandlerConfig);

		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "OpenSAML library could not be initialized", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Bootstrap done");

		String sVerifySignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_signature", false);
		if ("true".equalsIgnoreCase(sVerifySignature)) {
			set_bVerifySignature(true);
		}
		
		String sVerifyResponseSignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_responsesignature", false);
		if ("true".equalsIgnoreCase(sVerifyResponseSignature)) {
			setVerifyResponseSignature(true);
		}

		String sVerifyAssertionSignature = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_assertionsignature", false);
		if ("true".equalsIgnoreCase(sVerifyAssertionSignature)) {
			setVerifyAssertionSignature(true);
		}
		
		String sIntervalInterval = ASelectConfigManager.getSimpleParam(oHandlerConfig, "verify_interval", false);
		if ("true".equalsIgnoreCase(sIntervalInterval)) {
			set_b_VerifyInterval(true);
		}

		String sMaxNotBefore = ASelectConfigManager.getSimpleParam(oHandlerConfig, "max_notbefore", false);
		if (sMaxNotBefore != null) {
			setMaxNotBefore(new Long(Long.parseLong(sMaxNotBefore) * 1000));
		}
		String sMaxNotOnOrAfter = ASelectConfigManager.getSimpleParam(oHandlerConfig, "max_notonorafter", false);
		if (sMaxNotOnOrAfter != null) {
			setMaxNotOnOrAfter(new Long(Long.parseLong(sMaxNotOnOrAfter) * 1000));
		}
		
		// RH, 20120322, sn
		String sUseBackChannelClientCertificate = ASelectConfigManager.getSimpleParam(oHandlerConfig, "use_backchannelclientcertificate", false);
		if ("true".equalsIgnoreCase(sUseBackChannelClientCertificate)) {
			setUseBackchannelClientcertificate(true);

			String sKeystore = ASelectConfigManager.getParamFromSection(oHandlerConfig, "use_backchannelclientcertificate", "keystore", true);
			String sKeystorePw = ASelectConfigManager.getParamFromSection(oHandlerConfig, "use_backchannelclientcertificate", "keystorepw", false);
			try {
				SSLSocketFactory _sslSocketFactory = HandlerTools.createSSLSocketFactory(sKeystore, sKeystorePw);
				if (_sslSocketFactory != null) {
					setSslSocketFactory(_sslSocketFactory);
				} else {
					StringBuffer sbBuffer = new StringBuffer("Unable to setup SSLSocketFactory, maybe keystore or keystore password invalid: \"");
					sbBuffer.append("keystore:" + sKeystore);
					sbBuffer.append("\" errorcode: ");
					sbBuffer.append(Errors.ERROR_ASELECT_CONFIG_ERROR);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString());
					throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
			}
			catch (IOException iox) {
				StringBuffer sbBuffer = new StringBuffer("Unable to setup SSLSocketFactory, maybe keystore invalid: \"");
				sbBuffer.append("keystore:" + sKeystore);
				sbBuffer.append("\" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_CONFIG_ERROR);
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), iox);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR, iox);
			}
			catch (GeneralSecurityException e) {
				StringBuffer sbBuffer = new StringBuffer("Unable to setup SSLSocketFactory, maybe keystore or keystore password invalid: \"");
				sbBuffer.append("keystore:" + sKeystore);
				sbBuffer.append("\" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_CONFIG_ERROR);
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
			}

			
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "use_backchannelclientcertificate: " + isUseBackchannelClientcertificate());
		// RH, 20120322, en
		
		// RH, 20151016, sn, refactor pull up from Xsaml20_SSO
		_sDefaultSigning = "sha256";		// RH, 20170727, n		
		try {
//			String use_sha256 =_sReqSigning = _configManager.getParam(oHandlerConfig, "use_sha256");
			String use_sha256 = _configManager.getParam(oHandlerConfig, "use_sha256");
//			if ( Boolean.parseBoolean(use_sha256 ))  {		// RH, 20170727, o
//				_sDefaultSigning = "sha256";		// RH, 20170727, o
			if (  "false".equalsIgnoreCase(use_sha256) )  {		// RH, 20170727, n
				_sDefaultSigning = "sha1";		// RH, 20170727, n
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'use_sha256' found, normal operation resumes");
		}

		try {
			String add_keyname = _configManager.getParam(oHandlerConfig, "add_keyname");
			if ( Boolean.parseBoolean(add_keyname ))  {
				_sDefaultAddKeyname = "true";	// lowercase
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'add_keyname' found, normal operation resumes");
		}

		try {
			String add_certifcate = _configManager.getParam(oHandlerConfig, "add_certificate");
			if ( Boolean.parseBoolean(add_certifcate ))  {
				_sDefaultAddCertificate = "true";	// lowercase
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'add_certificate' found, normal operation resumes");
		}
		// RH, 20151016, en

		// RH, 20161219, sn, audience logout implementation
		try {
			String audiencelogout = _configManager.getParam(oHandlerConfig, "audiencelogout");
			 audiencelogout_required = Boolean.parseBoolean(audiencelogout );
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'audiencelogout' found, normal operation resumes");
			audiencelogout_required = false;
		}
		
		// RH, 20190319, sn, pull-up from Xsam20_ISTS
		_sResourceGroup = ASelectConfigManager.getSimpleParam(oHandlerConfig, "resourcegroup", false);


	}

	// Unfortunately, sNameID is not equal to our tgtID (it's the Federation's)
	// So we have to search all TGT's (for now a very inefficient implementation)
	/**
	 * Removes the tgt by name id.
	 * 
	 * @param sNameID
	 *            the s name id
	 * @return the int
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
//	protected int removeTgtByNameID(String sNameID)	// RH, 20161215, o
	// Return the deleted tgt or null if not found, caller might need the tgt one last time	// RH, 20161215, n
	protected HashMap removeTgtByNameID(String sNameID)
	throws ASelectStorageException
	{
		String sMethod = "removeByNameID";
		HashMap htTGTContext = null;	// RH, 20161215, n
		TGTManager tgtManager = TGTManager.getHandle();
		HashMap allTgts = tgtManager.getAll();

		// For all TGT's
		int found = 0;
		Set keys = allTgts.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
			// String sKey = e.nextElement();
//			HashMap htTGTContext = (HashMap) tgtManager.get(sKey);	// RH, 20161215, o
			htTGTContext = (HashMap) tgtManager.get(sKey);	// RH, 20161215, n
			String tgtNameID = (String) htTGTContext.get("name_id");
			if (sNameID.equals(tgtNameID)) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Remove TGT=" + Utils.firstPartOf(sKey, 30));
				tgtManager.remove(sKey);
				found = 1;
				break;
			}
		}
		//	return found;	// RH, 20161215, o
		// RH, 20161215, sn
		if ( found == 1) {
			return htTGTContext;
		} else {
			 return null;	// RH, 20161215, n
		}
		// RH, 20161215, en
	}

	/**
	 * Send logout to id p.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param sTgT
	 *            the TGT
	 * @param htTGTContext
	 *            the TGT context
	 * @param sIssuer
	 *            the issuer
	 * @param sLogoutReturnUrl
	 *            the logout return url
	 * @throws ASelectException
	 * @return the int, 0 = logout to IDP, 1 = logout not required/supported
	 */
	protected int sendLogoutToIdP(HttpServletRequest request, HttpServletResponse response, String sTgT,
			HashMap htTGTContext, String sIssuer, String sLogoutReturnUrl)
	throws ASelectException
	{
		String sMethod = "sendLogoutToIdP";
		int returnValue = 0;

		// Send a saml LogoutRequest to the federation idp
//		LogoutRequestSender logoutRequestSender = new LogoutRequestSender();	// RH, 20180918, o
		String sNameID = (String) htTGTContext.get("name_id");

		// metadata
		String sFederationUrl = (String) htTGTContext.get("federation_url");
		// RH, 20190322, sn
		String sFederationGroup = (String) htTGTContext.get("federation_group");
		if (sFederationGroup == null) {	// fall-back
			sFederationGroup = _sResourceGroup;
		}
		// RH, 20190322, en
		
		// RH, 20120307, Add partnerdata for later usage, this is the best point for geting the federationurl, we already retrieved the tgtcontext 
//		PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);// RH, 20190322, o
		PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationGroup, sFederationUrl);// RH, 20190322, n
		if ("true".equalsIgnoreCase(partnerData.getLogoutSupport())) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Logout to IdP="+sFederationUrl + " returnUrl="+sLogoutReturnUrl);
			// if (sFederationUrl == null) sFederationUrl = _sFederationUrl; // xxx for now
			MetaDataManagerSp metadataManager = MetaDataManagerSp.getHandle();
//			String url = metadataManager.getLocation(sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, o
			String url = metadataManager.getLocation(sFederationGroup, sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, n
					SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			// RH, 20200110, sn
			String binding = null;
			if (url != null) {	// for now Redirect is preferred, this should be based on isDefault and index 
				binding = "HTTP-Redirect";
				
			} else {
				url = metadataManager.getLocation(sFederationGroup, sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, n
						SAMLConstants.SAML2_POST_BINDING_URI);
				if (url != null) {
					binding = "HTTP-POST";
				} else {
					url = metadataManager.getLocation(sFederationGroup, sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, n
							SAMLConstants.SAML2_POST_SIMPLE_SIGN_BINDING_URI);
					if (url != null) {
						binding = "HTTP-POST-SimpleSign";
					}
				}
			}
			// RH, 20200110, en
			if (url != null) {
				// RH, 20180918, sn
				PrivateKey specialKey = null;
				LogoutRequestSender logoutRequestSender = null;
				if (partnerData.getCrypto() != null) {
					logoutRequestSender = new LogoutRequestSender(partnerData.getCrypto());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using specific private key for redirect");
				} else {
					logoutRequestSender = new LogoutRequestSender();
				}
				// RH, 20180918, en

				// Get list of sessions to kill if present in tgt
				Vector<String> sessionindexes = (Vector<String>) htTGTContext.get("remote_sessionlist");	// can be null
				// RH, 20190129, sn
				// DigiD wants same issuer for login and logout
				if (partnerData != null && partnerData.getLocalIssuer() != null) {
					sIssuer = partnerData.getLocalIssuer();
				}
				logoutRequestSender.setBinding(binding);// RH, 20200110, n

				// RH, 20190129, sn
				logoutRequestSender.sendLogoutRequest(request, response, sTgT, url, sIssuer/* issuer */, sNameID,
						"urn:oasis:names:tc:SAML:2.0:logout:user", sLogoutReturnUrl, sessionindexes, partnerData);
			}
			else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No IdP SingleLogoutService");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
		} else {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Partner: " + partnerData.getPartnerID() + " doesn't require/support logout, straight back to initiating SP");
			returnValue = 1;	// logout not required/supported
		}
		return returnValue;
	}

	/**
	 * Finish logout actions.
	 * 
	 * @param servletResponse
	 *            the http response
	 * @param resultCode
	 *            the result code
	 * @param sLogoutReturnUrl
	 *            the return url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void finishLogoutActions(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String resultCode, String sLogoutReturnUrl)
	throws ASelectException
	{
		String sMethod = "finishLogoutActions";
		String sLogoutResultPage = "";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using sLogoutReturnUrl: " + sLogoutReturnUrl);

		// And inform the caller or user
		if (Utils.hasValue(sLogoutReturnUrl)) {
			int idx = sLogoutReturnUrl.indexOf("\r");
			if (idx >= 0) sLogoutReturnUrl = sLogoutReturnUrl.substring(0, idx);
			idx = sLogoutReturnUrl.indexOf("\n");
			if (idx >= 0) sLogoutReturnUrl = sLogoutReturnUrl.substring(0, idx);
			
			// Redirect to the "RelayState" url
			String sAmpQuest = (sLogoutReturnUrl.indexOf('?') >= 0) ? "&" : "?";
			String url = sLogoutReturnUrl + sAmpQuest + "result_code=" + resultCode;
			try {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Redirect to " + url);
				servletResponse.sendRedirect(url);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			}
		}
		else {
			PrintWriter pwOut = null;
			try {
				sLogoutResultPage = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
						"logoutresult", _sUserLanguage, _sFriendlyName, Version.getVersion());
				sLogoutResultPage = Utils.replaceString(sLogoutResultPage, "[result_code]", resultCode);
				sLogoutResultPage = _configManager.updateTemplate(sLogoutResultPage, null/*no session*/, servletRequest);
				
				pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);
				pwOut.println(sLogoutResultPage);
			}
			catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			finally {
				if (pwOut != null) {
					pwOut.close();
				}
			}
		}
	}

	@Override
	public void destroy()
	{
	}

	/**
	 * Checks if is _b verify signature.
	 * 
	 * @return true, if is _b verify signature
	 */
	public synchronized boolean is_bVerifySignature()
	{
		return _bVerifySignature;
	}

	/**
	 * Sets the _b verify signature.
	 * 
	 * @param verifySignature
	 *            the new _b verify signature
	 */
	public synchronized void set_bVerifySignature(boolean verifySignature)
	{
		_bVerifySignature = verifySignature;
	}

	/**
	 * Checks if is _b verify interval.
	 * 
	 * @return true, if is _b verify interval
	 */
	public synchronized boolean is_bVerifyInterval()
	{
		return _bVerifyInterval;
	}

	/**
	 * Sets the _b_ verify interval.
	 * 
	 * @param verifyInterval
	 *            the new _b_ verify interval
	 */
	public synchronized void set_b_VerifyInterval(boolean verifyInterval)
	{
		_bVerifyInterval = verifyInterval;
	}

	/**
	 * Gets the max not before.
	 * 
	 * @return the max not before
	 */
	public synchronized Long getMaxNotBefore()
	{
		return maxNotBefore;
	}

	/**
	 * Sets the max not before.
	 * 
	 * @param maxNotBefore
	 *            the new max not before
	 */
	public synchronized void setMaxNotBefore(Long maxNotBefore)
	{
		this.maxNotBefore = maxNotBefore;
	}

	/**
	 * Gets the max not on or after.
	 * 
	 * @return the max not on or after
	 */
	public synchronized Long getMaxNotOnOrAfter()
	{
		return maxNotOnOrAfter;
	}

	/**
	 * Sets the max not on or after.
	 * 
	 * @param maxNotOnOrAfter
	 *            the new max not on or after
	 */
	public synchronized void setMaxNotOnOrAfter(Long maxNotOnOrAfter)
	{
		this.maxNotOnOrAfter = maxNotOnOrAfter;
	}

	/**
	 * Extract XML object from document string as present in a HTTP POST request
	 * 
	 * @param docReceived
	 *            the doc received
	 * @return the authz decision query
	 * @throws ASelectException
	 *             the ASelect exception
	 */
	protected XMLObject extractXmlObject(String docReceived, String sXmlType)
	throws ASelectException
	{
		String _sMethod = "handleSAMLRequest";
		_systemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message:\n" + docReceived);
		XMLObject authzDecisionQuery = null;
		try {
			// Build XML Document
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_systemLogger);
			dbFactory.setNamespaceAware(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(docReceived);
			InputSource inputSource = new InputSource(stringReader);
			Document parsedDocument = builder.parse(inputSource);
			_systemLogger.log(Level.FINER, MODULE, _sMethod, "parsedDocument=" + parsedDocument);
	
			// Get AuthzDecision object
			Element elementReceived = parsedDocument.getDocumentElement();
			Node eltAuthzDecision = SamlTools.getNode(elementReceived, sXmlType);
	
			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltAuthzDecision);
			authzDecisionQuery = unmarshaller.unmarshall((Element) eltAuthzDecision);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to process SAML message", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return authzDecisionQuery;
	}
	
	/**
	 * Send Logout request to sp audience <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method sends a logout request to the sp audience <br>
	 * .
	 * 
	 * @param sNameID
	 *            String with the NameID
	 * @param entityID
	 *            String where to send logout request
	 * @param reason
	 *            String reason for logout
	 *  @return result of logout as StususCode string          
	 * @throws ASelectException
	 *             If send request fails.
	 */
//	protected String sendLogoutRequestToSpAudience(String sNameID, String entityID, String reason)	// Rh, 20190322, o
	protected String sendLogoutRequestToSpAudience(String resourceGroup, String sNameID, String entityID, String reason)	// Rh, 20190322, n
	throws ASelectException
	{
		String _sMethod = "sendLogoutRequestToSpAudience";
		String status = null;
		SoapLogoutRequestSender requestSender = new SoapLogoutRequestSender();
		MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
//		String url = metadataManager.getLocation(entityID, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, o
		String url = metadataManager.getLocation(resourceGroup, entityID, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190322, n
				SAMLConstants.SAML2_SOAP11_BINDING_URI);

		_systemLogger.log(Level.FINEST, MODULE, _sMethod, "Found audience url = " + url);

		List<PublicKey> pkeys = null;	// RH, 20181119, n
		if (is_bVerifySignature()) {
//			pkeys = metadataManager.getSigningKeyFromMetadata(entityID);	// RH, 20181119, n	// RH, 20190322, o
			pkeys = metadataManager.getSigningKeyFromMetadata(resourceGroup, entityID);	// RH, 20181119, n	// RH, 20190322, n
			if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181119, n
				_systemLogger.log(Level.SEVERE, MODULE, _sMethod, "No valid public key in metadata");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		try {
//			StatusCode statuscode = requestSender.sendSoapLogoutRequestWithStatus(url, _sServerUrl, sNameID, reason, pkey, null);	// RH, 20180918, o
//			StatusCode statuscode = requestSender.sendSoapLogoutRequestWithStatus(url, _sServerUrl, sNameID, reason, pkey, null, null);	// RH, 20180918, n	// RH, 20181119, o
			StatusCode statuscode = requestSender.sendSoapLogoutRequestWithStatus(url, _sServerUrl, sNameID, reason, pkeys, null, null);	// RH, 20180918, n	// RH, 20181119, n
			
			status = statuscode.getValue();
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "IDP - exception trying to send logout request to audience", e);
			status = StatusCode.PARTIAL_LOGOUT_URI;
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return status;
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


	/**
	 * @return the sslSocketFactory
	 */
	public SSLSocketFactory getSslSocketFactory()
	{
		return sslSocketFactory;
	}

	/**
	 * @param sslSocketFactory the sslSocketFactory to set
	 */
	public void setSslSocketFactory(SSLSocketFactory sslSocketFactory)
	{
		this.sslSocketFactory = sslSocketFactory;
	}

	public synchronized boolean isVerifyResponseSignature()
	{
		return verifyResponseSignature;
	}

	public synchronized void setVerifyResponseSignature(boolean verifyResponseSignature)
	{
		this.verifyResponseSignature = verifyResponseSignature;
	}

	public synchronized boolean isVerifyAssertionSignature()
	{
		return verifyAssertionSignature;
	}

	public synchronized void setVerifyAssertionSignature(boolean verifyAssertionSignature)
	{
		this.verifyAssertionSignature = verifyAssertionSignature;
	}

}
