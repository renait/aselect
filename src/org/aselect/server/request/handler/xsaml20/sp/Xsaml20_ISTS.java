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
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.PropertyException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMResult;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.config.Version;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.Saml20_RedirectEncoder;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.RequesterID;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;


public class Xsaml20_ISTS extends Saml20_BaseHandler
{
	private final static String MODULE = "Xsaml20_ISTS";
	protected final String singleSignOnServiceBindingConstantREDIRECT = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	protected final String singleSignOnServiceBindingConstantHTTPPOST = SAMLConstants.SAML2_POST_BINDING_URI;
	
	private String _sServerId = null; // <server_id> in <aselect>
	
	private String _sAssertionConsumerUrl = null;
	private String _sPostTemplate = null;
	private String _sHttpMethod = "GET";
	private String _sFallbackUrl = null;
	private String _sRedirectSyncTime = null;
	private boolean bIdpSelectForm = false;

	// Example configuration
	//
	// <handler id="saml20_ists" target="/saml20_ists.*"
	// class="org.aselect.server.request.handler.xsaml20.Xsaml20_ISTS">
	//
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BaseHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		Object sam = null;
		Object agent = null;
		Object idpSection = null;
	
		try {
			super.init(oServletConfig, oConfig);
		}
		catch (ASelectException e) { // pass to caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		_sServerId = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);

		_sHttpMethod = ASelectConfigManager.getSimpleParam(oConfig, "http_method", false);
		if (_sHttpMethod != null && _sHttpMethod.equalsIgnoreCase("POST"))
			_sHttpMethod = "POST";
		else
			_sHttpMethod = "GET";
		
		if (_sHttpMethod.equals("POST"))
			_sPostTemplate = readTemplateFromConfig(oConfig, "post_template");

		String sUseIdpSelectForm = ASelectConfigManager.getSimpleParam(oConfig, "use_idp_select", false);
		if (sUseIdpSelectForm != null && sUseIdpSelectForm.equals("true"))
			bIdpSelectForm = true;

//		_sIdpResourceGroup = ASelectConfigManager.getSimpleParam(oConfig, "resourcegroup", false);	// RH, 20190319, o // pulled up
		if (_sResourceGroup == null)
			_sResourceGroup = "federation-idp";  // backward compatibility
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "IDP resourcegroup="+_sResourceGroup);	// RH, 20190319, o
		_systemLogger.log(Level.INFO, MODULE, sMethod, "resourcegroup="+_sResourceGroup);	// RH, 20190319, o

		_sFallbackUrl = ASelectConfigManager.getSimpleParam(oConfig, "fallback_url", false);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "fallback_url="+_sFallbackUrl);
		
		// Find the resourcegroup
		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		try {
			Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id=" + _sResourceGroup);
			idpSection = _configManager.getSection(metaResourcegroup, "resource");
		}		
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No resourcegroup: "+_sResourceGroup+" configured");
		}
		
		// And pass it's resources to the metadata manager
		MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();  // will create the MetaDataManager object
		while (idpSection != null) {
//			metadataMgr.processResourceSection(idpSection);	// RH, 20190321, o
			metadataMgr.processResourceSection(_sResourceGroup, idpSection);	// RH, 20190321, n
			idpSection = _configManager.getNextSection(idpSection);
		}
		metadataMgr.logIdPs();
		
		// Get Assertion Consumer data from config
		try {
			Object oRequest = _configManager.getSection(null, "requests");
			Object oHandlers = _configManager.getSection(oRequest, "handlers");
			Object oHandler = _configManager.getSection(oHandlers, "handler");
			Object oASelect = _configManager.getSection(null, "aselect");
			String sRedirectUrl = _configManager.getParam(oASelect, "redirect_url");

			for ( ; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				String sId = _configManager.getParam(oHandler, "id");
				if (sId != null && !sId.equals("saml20_assertionconsumer"))
					continue;
				// The Assertion Consumer
				String sTarget = _configManager.getParam(oHandler, "target");
				if (sTarget != null) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget);
					sTarget = sTarget.replace("\\", "");
					sTarget = sTarget.replace(".*", "");
					_sAssertionConsumerUrl = sRedirectUrl + sTarget;
				}
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}
	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@SuppressWarnings("unchecked")
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "process";
		String sRid;
		String sFederationUrl = null;
		PrintWriter pwOut = null;

		String sMyUrl = _sServerUrl; // extractAselectServerUrl(request);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "MyUrl=" + sMyUrl + " MyId="+getID()+ " path=" + servletRequest.getPathInfo());

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			sRid = servletRequest.getParameter("rid");
			if (sRid == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing RID parameter");
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}

			// Find the associated session context
			_htSessionContext = _oSessionManager.getSessionContext(sRid);
			if (_htSessionContext == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No session found for RID: " + sRid);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			// Session present
			Tools.resumeSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102, can change the session
			// 20091028, Bauke, let the user choose which IdP to use
			// 20110308, Bauke: changed, user chooses when "use_idp_select" is "true"
			//     otherwise this handler uses it's own resource group to get a resource and sets "federation_url"
			//     to the id of that resource
			sFederationUrl = servletRequest.getParameter("federation_url");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Received federation_url="+sFederationUrl);
			
			//int cnt = MetaDataManagerSp.getHandle().getIdpCount();
			//if (cnt == 1) {
			//	sFederationUrl = MetaDataManagerSp.getHandle().getDefaultIdP(); // there can only be one
			//}
			if (bIdpSelectForm && (!Utils.hasValue(sFederationUrl))) {
				// No Federation URL choice made yet, allow the user to choose
				String sIdpSelectForm = Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(), null/*subdir*/,
						"idpselect", _sUserLanguage, _configManager.getOrgFriendlyName(), Version.getVersion());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[rid]", sRid);
				// Not backward compatible! [aselect_url] used to be server_url/handler_id,
				// they're separated now to allow use of [aselect_url] in the traditional way too!
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[handler_url]", sMyUrl + "/" + getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[aselect_url]", sMyUrl); // 20110310 + "/" + getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[handler_id]", getID());
				sIdpSelectForm = Utils.replaceString(sIdpSelectForm, "[a-select-server]", _sServerId);  // 20110310
				//sSelectForm = Utils.replaceString(sSelectForm, "[language]", sLanguage);
				sIdpSelectForm = _configManager.updateTemplate(sIdpSelectForm, _htSessionContext, servletRequest);  // 20130822, Bauke: added to show requestor_friendly_name
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Template updated, [handler_url]="+sMyUrl + "/" + getID());

				_htSessionContext.put("user_state", "state_idpselect");			
				_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession
				Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can update the session
				pwOut.println(sIdpSelectForm);
				return new RequestState(null);
			}
			// federation_url was set or bIdpSelectForm is false
			_htSessionContext.put("user_state", "state_toidp");  // at least remove state_select
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			// 20110308, Bauke: new mechanism to get to the IdP using the SAM agent (allows redundant resources)
			// User choice was made, or "federation_url" was set programmatically
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Getting active resource from resourcegroup=" + _sResourceGroup);
			ASelectSAMAgent samAgent = ASelectSAMAgent.getHandle();
			SAMResource samResource = null;
			try {
				samResource = samAgent.getActiveResource(_sResourceGroup);
			}
			catch (ASelectSAMException ex) {  // no active resource
				// if a fallback is present: REDIRECT to the authsp
				if (Utils.hasValue(_sFallbackUrl)) {
					// Don't come back here:
					_htSessionContext.remove("forced_authsp");
					// 20110331, Bauke: We leave forced_uid in place!
					// If we do, control can easily be transferred to e.g. DigiD
					//htSessionContext.remove("forced_uid");
					_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: added

					String sRedirectUrl = _sFallbackUrl;
					//sRedirectUrl = "[aselect_url]?request=direct_login1&rid=[rid]&authsp=Ldap&a-select-server=[a-select-server]";
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[aselect_url]", sMyUrl);
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[a-select-server]", _sServerId);
					sRedirectUrl = Utils.replaceString(sRedirectUrl, "[rid]", sRid);
					//sRedirectUrl = Utils.replaceString(sRedirectUrl, "[language]", sLanguage);
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Fallback REDIRECT to: " + sRedirectUrl);
					
					Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can change the session
					//_oSessionManager.updateSession(sRid, _htSessionContext);  // 20120403, Bauke: removed
					servletResponse.sendRedirect(sRedirectUrl);
					return new RequestState(null);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No active resource available");
					throw new ASelectSAMException(Errors.ERROR_ASELECT_SAM_UNAVALABLE);
				}
			}
			// The result is a single resource from our own resourcegroup
			sFederationUrl = samResource.getId();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Found active IdP resource id using asfederation_url="+sFederationUrl);

			// 20090811, Bauke: save type of Authsp to store in the TGT later on
			// This is needed to prevent session sync when we're not saml20
			_htSessionContext.put("authsp_type", "saml20");
			_htSessionContext.put("federation_url", sFederationUrl);
			
			// RH, 20190322, sn
			// save federation group (resourcegroup) as well
			_htSessionContext.put("federation_group", _sResourceGroup);
			// RH, 20190322, en
			
			_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);  // 20120403, Bauke: was updateSession

			_systemLogger.log(Level.FINER, MODULE, sMethod, "Get MetaData FederationUrl=" + sFederationUrl);
			MetaDataManagerSp metadataMgr = MetaDataManagerSp.getHandle();
			// RM_57_01
			// RM_57_02
			// We now support the Redirect and POST Binding
			String sDestination = null;
			if ("POST".equalsIgnoreCase(_sHttpMethod)) {
//				sDestination = metadataMgr.getLocation(sFederationUrl,	// RH, 20190322, o
				sDestination = metadataMgr.getLocation(_sResourceGroup, sFederationUrl,	// RH, 20190322, n
						SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantHTTPPOST);
			} else {
//				sDestination = metadataMgr.getLocation(sFederationUrl,	// RH, 20190322, o
				sDestination = metadataMgr.getLocation(_sResourceGroup, sFederationUrl,	// RH, 20190322, n
						SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME, singleSignOnServiceBindingConstantREDIRECT);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Location retrieved=" + sDestination);
			if ("".equals(sDestination))
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			
//			PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);	// RH, 20190322, o
			PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sFederationUrl);	// RH, 20190322, n
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Retreived Partnerdata: "+partnerData);
			String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
			
			// Use Level of Assurance (for ETD) instead of PASSWORDPROTECTEDTRANSPORT_URI and his friends
			boolean useLoa = (specialSettings != null && specialSettings.contains("use_loa"));

			String sApplicationId = (String)_htSessionContext.get("app_id");
			String sApplicationLevel = getApplicationLevel(sApplicationId);
			
			// RH, 20180810, sn
			boolean useNewLoa = (specialSettings != null && specialSettings.contains("use_newloa"));
			String sAuthnContextClassRefURI = null;
			if (useNewLoa) {
				sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, useLoa, SecurityLevel.getNewLoaLevels(), _systemLogger);
				
			} else {
				sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, useLoa, SecurityLevel.getDefaultLevels(), _systemLogger);
			}
			// RH, 20180810, en
			
			// Throws an exception on invalid levels:
//			String sAuthnContextClassRefURI = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, useLoa, _systemLogger); // RH, 20180810, o
			//if (sAuthnContextClassRefURI == null) {
			//	// this level was not configured. Log it and inform the user
			//	_systemLogger.log(Level.WARNING, MODULE, sMethod, "Application Level "+sApplicationLevel+" has not been configured");
			//	throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL);
			//}
			
			// Send SAML request to the IDP
			XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

			SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
					.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();

			authnContextClassRef.setAuthnContextClassRef(sAuthnContextClassRefURI);

			SAMLObjectBuilder<RequestedAuthnContext> requestedAuthnContextBuilder = (SAMLObjectBuilder<RequestedAuthnContext>) builderFactory
					.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
			RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
			requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
			
			// 20100311, Bauke: added for eHerkenning
			if (specialSettings != null && specialSettings.contains("minimum"))
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
			else
				requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

			// RH, 20171201, sn
			Scoping scoping = null;
			boolean suppressscoping = partnerData != null && "true".equalsIgnoreCase(partnerData.getSuppressscoping());	// RH, 20180327, sn
			if (!suppressscoping) {	// RH, 20180327, en
				String sApplicationRequestorID = getApplicationRequesterID(sApplicationId);
				if (sApplicationRequestorID != null) {
					// RH, 20190211, sn
					// RequesterID has type anyURI. Therefore it should not contain unencoded spaces, control characters and <>#%{}|\^`
					// We therefore will use the {} pair to define variable parameter to inject
					sApplicationRequestorID = Utils.parseSessionVariable(_htSessionContext, sApplicationRequestorID, "{", "}", _systemLogger);
					// RH, 20190211, en
					
					SAMLObjectBuilder<Scoping> scopingtBuilder = null;
					scopingtBuilder = (SAMLObjectBuilder<Scoping>) builderFactory
							.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
					scoping = scopingtBuilder.buildObject();
					SAMLObjectBuilder<RequesterID> requestorIDBuilder = (SAMLObjectBuilder<RequesterID>) builderFactory
							.getBuilder(RequesterID.DEFAULT_ELEMENT_NAME);
					RequesterID requestorID = requestorIDBuilder.buildObject();
					requestorID.setRequesterID(sApplicationRequestorID);
					scoping.getRequesterIDs().add(requestorID);
				} else {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "No config item 'authnrequest_requesterid' found");
				}
				// RH, 20171201, en
				
			// RH, 20180327, sn
			} else {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Suppress Scoping enabled" );
			}
			// RH, 20180327, en

			// RH, 20181005, sn
			String sIDPEntryProviderID = partnerData == null ? null : partnerData.getIdpentryproviderid();
			if (sIDPEntryProviderID != null) {
				if (scoping == null) {
					SAMLObjectBuilder<Scoping> scopingtBuilder = null;
					scopingtBuilder = (SAMLObjectBuilder<Scoping>) builderFactory
							.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
					scoping = scopingtBuilder.buildObject();
				}
				SAMLObjectBuilder<IDPList> idpListBuilder = (SAMLObjectBuilder<IDPList>) builderFactory
						.getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
				IDPList idpList = idpListBuilder.buildObject();
				SAMLObjectBuilder<IDPEntry> idpEntryBuilder = (SAMLObjectBuilder<IDPEntry>) builderFactory
						.getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
				IDPEntry idpEntry = idpEntryBuilder.buildObject();
				idpEntry.setProviderID(sIDPEntryProviderID);
				idpList.getIDPEntrys().add(idpEntry);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Setting the idp sIDPEntryProviderID:" + sIDPEntryProviderID);
				scoping.setIDPList(idpList);
			} else {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "No config item 'authnrequest_providerid' found");
			}
			// RH, 20181005, en

			// 20120706, Bauke: save in session, must be transferred to TGT and used for Digid4 session_sync mechanism
			String sst = partnerData.getRedirectSyncTime();
			if (Utils.hasValue(sst)) {
				_htSessionContext.put("redirect_sync_time", sst);
				_htSessionContext.put("redirect_ists_url", sMyUrl + "/" + getID());
				_htSessionContext.put("redirect_post_form", partnerData.getRedirectPostForm());
				_oSessionManager.setUpdateSession(_htSessionContext, _systemLogger);
			}
			
			SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
					.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = issuerBuilder.buildObject();
			// 20100311, Bauke: Alternate Issuer, added for eHerkenning
			if (partnerData != null && partnerData.getLocalIssuer() != null)
				issuer.setValue(partnerData.getLocalIssuer());
			else
				issuer.setValue(sMyUrl);

			// AuthnRequest
			SAMLObjectBuilder<AuthnRequest> authnRequestbuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
					.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			AuthnRequest authnRequest = authnRequestbuilder.buildObject();

			if (partnerData != null && partnerData.getExtensionsdata4partner().getRequestedAttributes() != null ) {	// maybe define some other condition
				
				// Add the stork extensions
				Extensions extensions = createSTORKExtensions(sApplicationLevel, sApplicationId, partnerData);
				authnRequest.setExtensions(extensions);
				authnRequest = (AuthnRequest) HandlerTools.rebuildAssertion(authnRequest);
			}

			// RH, 20200629, sn
			else {	// either Stork or eID for now
				if (partnerData != null && partnerData.getExtensionsdata4partner().geteIDAttributes() != null ) {
					// Add the eID extensions
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Adding eID extensions");
					Extensions extensions = createeIDExtensions(sApplicationLevel, sApplicationId, partnerData);
					authnRequest.setExtensions(extensions);
					authnRequest = (AuthnRequest) HandlerTools.rebuildAssertion(authnRequest);
				}
			}
			// RH, 20200629, en

			 
			// We should be able to set AssertionConsumerServiceIndex. This is according to saml specs mutually exclusive with
			// ProtocolBinding and AssertionConsumerServiceURL
			
			if (partnerData !=null)
				_systemLogger.log(Level.FINER, MODULE, sMethod, "acsi="+partnerData.getAssertionConsumerServiceindex());
			
			if  (partnerData != null && partnerData.getAssertionConsumerServiceindex() != null) {
				authnRequest.setAssertionConsumerServiceIndex(Integer.parseInt(partnerData.getAssertionConsumerServiceindex() ));
			}
			else {	 // mutually exclusive
				// 20100311, Bauke: added for eHerkenning
				// The assertion consumer url must be set to the value in the Metadata:
				// 20101112, RH, added support for POST binding
				if (specialSettings != null && specialSettings.toUpperCase().contains("POST"))
					authnRequest.setProtocolBinding(Saml20_Metadata.singleSignOnServiceBindingConstantPOST);
				else	// backward compatibility, defaults to ARTIFACT
					authnRequest.setProtocolBinding(Saml20_Metadata.assertionConsumerServiceBindingConstantARTIFACT);
	
				// We should be able to not set setAssertionConsumerServiceURL and let IDP get it from metadata
				// But not sure if all idp's will handle that well
				if (partnerData != null && partnerData.getDestination() != null) {
					if (!"".equals(partnerData.getDestination().trim())) {	// if empty, let the idp look for the AssertionConsumerServiceURL in metadata 
						authnRequest.setAssertionConsumerServiceURL(partnerData.getDestination());
					}
				}
				else {	// backward compatibility, default to _sAssertionConsumerUrl
					authnRequest.setAssertionConsumerServiceURL(_sAssertionConsumerUrl);
				}
			}
			
			// RH, 20140505, sn
			String sForcedAttrConServInd = ApplicationManager.getHandle().getForcedAttrConsServIndex(sApplicationId);
			if ( sForcedAttrConServInd != null ) {
				authnRequest.setAttributeConsumingServiceIndex(Integer.parseInt(sForcedAttrConServInd));
			} else {
				// RH, 20140505, en

				if  (partnerData != null && partnerData.getAttributeConsumerServiceindex() != null) {
					authnRequest.setAttributeConsumingServiceIndex(Integer.parseInt(partnerData.getAttributeConsumerServiceindex() ));
				} else {	// be backwards compatible
					authnRequest.setAttributeConsumingServiceIndex(2);
				}

			}// RH, 20140505, n
			
			authnRequest.setDestination(sDestination);
			DateTime tStamp = new DateTime();
			// Set interval conditions
			authnRequest = (AuthnRequest) SamlTools.setValidityInterval(authnRequest, tStamp, getMaxNotBefore(), getMaxNotOnOrAfter());

			// 20100531, Bauke, use Rid but add part of the timestamp to make the ID unique
			// The AssertionConsumer will strip it off to regain our Rid value
			String timePostFix = String.format("%02d%02d%02d%03d", tStamp.getHourOfDay(), tStamp.getMinuteOfHour(), tStamp.getSecondOfMinute(), tStamp.getMillisOfSecond());
			authnRequest.setID(sRid+timePostFix);

			authnRequest.setProviderName(_sServerId);
			authnRequest.setVersion(SAMLVersion.VERSION_20);
			authnRequest.setIssuer(issuer);
			authnRequest.setIssueInstant(new DateTime());  // 20100712
			authnRequest.setRequestedAuthnContext(requestedAuthnContext);

			// RH, 20171201, sn
			if (scoping != null) {
				authnRequest.setScoping(scoping);
			}
			// RH, 20171201, en
			
			// RH, 20190412, sn
			// for idp partner sso
			boolean suppressforcedauthn = partnerData != null && "true".equalsIgnoreCase(partnerData.getSuppresssforcedauthn());
			if (!suppressforcedauthn) {
			// RH, 20190412, en
				
				// Check if we have to set the ForceAuthn attribute
				// 20090613, Bauke: use forced_authenticate (not forced_logon)!
				Boolean bForcedAuthn = (Boolean)_htSessionContext.get("forced_authenticate");
				if (bForcedAuthn == null)
					bForcedAuthn = false;
				// 20100311, Bauke: "force" special_setting added for eHerkenning
				if (bForcedAuthn || (specialSettings != null && specialSettings.contains("force"))) {
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the ForceAuthn attribute");
					authnRequest.setForceAuthn(true);
				}
			}	// RH, 20190412, n

			// 20140924, RH: "force_passive" special_setting (only for testing yet)
			// If needed in production must have its own element/attribuut in config
			Boolean bForcedPassive = (Boolean)_htSessionContext.get("forced_passive");
			if (bForcedPassive || (specialSettings != null && specialSettings.contains("passive"))) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting the IsPassive attribute");
				authnRequest.setIsPassive(true);
			}

			
			// Handle testdata
			if (partnerData.getTestdata4partner() != null) {
				String timeOffset = partnerData.getTestdata4partner().getIssueInstant();
				if (timeOffset != null) {
//					if (timeOffset.startsWith("-")) {
//						authnRequest.setIssueInstant(new DateTime().minus(1000*Long.parseLong(timeOffset)));
//					} else {
						authnRequest.setIssueInstant(new DateTime().plus(1000*Long.parseLong(timeOffset)));
//					}
					// RM_57_03
				}
				if (partnerData.getTestdata4partner().getIssuer() != null) {
					authnRequest.getIssuer().setValue(partnerData.getTestdata4partner().getIssuer());
				}
				if (partnerData.getTestdata4partner().getAuthnContextClassRefURI() != null) {
					// There should be one so take first
					authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs().get(0).setAuthnContextClassRef(partnerData.getTestdata4partner().getAuthnContextClassRefURI());
				}
				if (partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration() != null) {
					if ("minimum".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
						requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
					else if ("exact".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
						requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
						else if ("better".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
							requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
							else if ("maximum".equalsIgnoreCase( partnerData.getTestdata4partner().getAuthnContextComparisonTypeEnumeration()) ) 
								requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
				}
				if ( partnerData.getTestdata4partner() .getForceAuthn() != null) {
					authnRequest.setForceAuthn(Boolean.parseBoolean(partnerData.getTestdata4partner() .getForceAuthn()));
				}
				if (partnerData.getTestdata4partner() .getProviderName() != null) {
					authnRequest.setProviderName(partnerData.getTestdata4partner() .getProviderName());
					
				}
				if (partnerData.getTestdata4partner() .getAssertionConsumerServiceIndex() != null) {
					// RM_57_04
					authnRequest.setAssertionConsumerServiceIndex(Integer.parseInt(partnerData.getTestdata4partner() .getAssertionConsumerServiceIndex()));
				}
				if (partnerData.getTestdata4partner() .getAssertionConsumerServiceURL() != null) {
					authnRequest.setAssertionConsumerServiceURL(partnerData.getTestdata4partner() .getAssertionConsumerServiceURL());
				}
				if (partnerData.getTestdata4partner() .getDestination() != null) {
					authnRequest.setDestination(partnerData.getTestdata4partner() .getDestination());
				}
				
			}
			
			
			// 20100908, Bauke: Look for aselect_specials!
			// In app_url or in the caller's RelayState (if we're an IdP)
			String sSpecials = null;
			if (specialSettings != null && specialSettings.contains("relay_specials")) {
				sSpecials = Utils.getAselectSpecials(_htSessionContext, false/*leave base64*/, _systemLogger);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "<special_settings>="+specialSettings+" aselect_specials="+sSpecials);
			
			// Create the new RelayState
			String sRelayState = "idp=" + sFederationUrl;
			if (specialSettings != null && specialSettings.contains("relay_specials")) {	
				if (Utils.hasValue(sSpecials))
					sRelayState += "&aselect_specials="+sSpecials;
				sRelayState = Base64Codec.encode(sRelayState.getBytes());
				_systemLogger.log(Level.FINER, MODULE, sMethod, "RelayState="+sRelayState);
			}

			// RH, 20180918, sn
			PartnerData.Crypto specificCrypto = partnerData.getCrypto();	// might be null
			// RH, 20180918, en

			//
			// We have the AuthnRequest, now get it to the other side
			//
			boolean useSha256 = (specialSettings != null && specialSettings.contains("sha256"));
			if (_sHttpMethod.equals("GET")) {
				// No use signing the AuthnRequest, it's even forbidden according to the Saml specs
				// Brent Putman quote: The Redirect-DEFLATE binding encoder strips off the protocol message's ds:Signature element (if even present)
				// before the marshalling and signing operations. Per the spec, it's not allowed to carry the signature that way.
				SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
						.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
				Endpoint samlEndpoint = endpointBuilder.buildObject();
				samlEndpoint.setLocation(sDestination);
				samlEndpoint.setResponseLocation(sMyUrl);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "GET EndPoint="+samlEndpoint+" Destination="+sDestination);
				
				//HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sDestination);
				HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(servletResponse,
							(sDestination == null)? false: sDestination.toLowerCase().startsWith("https"));
				
				// RH, 20081113, set appropriate headers
				outTransport.setHeader("Pragma", "no-cache");
				outTransport.setHeader("Cache-Control", "no-cache, no-store");
	
				BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
				messageContext.setOutboundMessageTransport(outTransport);
				messageContext.setOutboundSAMLMessage(authnRequest);
				messageContext.setPeerEntityEndpoint(samlEndpoint);
	
				BasicX509Credential credential = new BasicX509Credential();
//				PrivateKey key = _configManager.getDefaultPrivateKey();	// RH, 20180918, o
				// RH, 20180918, sn
				PrivateKey key = null;
				if (specificCrypto != null) {
					key = specificCrypto.getPrivateKey();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using specific private key for redirect");
				} else {
					key = _configManager.getDefaultPrivateKey();
				}
				// RH, 20180918, en
				credential.setPrivateKey(key);
				messageContext.setOutboundSAMLMessageSigningCredential(credential);
	
				// 20091028, Bauke: use RelayState to transport rid to my AssertionConsumer
				messageContext.setRelayState(sRelayState);
	
				MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
				Marshaller marshaller = marshallerFactory.getMarshaller(messageContext.getOutboundSAMLMessage());
				Node nodeMessageContext = marshaller.marshall(messageContext.getOutboundSAMLMessage());
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "RelayState="+sRelayState+" OutboundSAMLMessage:\n"+Auxiliary.obfuscate(XMLHelper.prettyPrintXML(nodeMessageContext), 
						Auxiliary.REGEX_PATTERNS));
				
				if (useSha256) {
					Saml20_RedirectEncoder encoder = new Saml20_RedirectEncoder();  // is a HTTPRedirectDeflateEncoder
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				else {
					// HTTPRedirectDeflateEncoder: SAML 2.0 HTTP Redirect encoder using the DEFLATE encoding method.
					// This encoder only supports DEFLATE compression and DSA-SHA1 and RSA-SHA1 signatures.
					HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
					encoder.encode(messageContext);  // does a sendRedirect()
				}
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Ready "+messageContext);
			}
			else {  // POST
				// 20100331, Bauke: added support for HTTP POST
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Sign the authnRequest >======"+authnRequest);
//				authnRequest = (AuthnRequest)SamlTools.signSamlObject(authnRequest, useSha256? "sha256": "sha1", 
//							"true".equalsIgnoreCase(partnerData.getAddkeyname()), "true".equalsIgnoreCase(partnerData.getAddcertificate()) );	// RH, 20180918, o
				authnRequest = (AuthnRequest)SamlTools.signSamlObject(authnRequest, useSha256? "sha256": "sha1", 
						"true".equalsIgnoreCase(partnerData.getAddkeyname()), "true".equalsIgnoreCase(partnerData.getAddcertificate()), specificCrypto);	// RH, 20180918, N
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the authnRequest ======<"+authnRequest);

				String sAssertion = XMLHelper.nodeToString(authnRequest.getDOM());
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Assertion=" + Auxiliary.obfuscate(sAssertion, Auxiliary.REGEX_PATTERNS));
				try {
					byte[] bBase64Assertion = sAssertion.getBytes("UTF-8");
					BASE64Encoder b64enc = new BASE64Encoder();
					sAssertion = b64enc.encode(bBase64Assertion);
				}
				catch (UnsupportedEncodingException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}

				// Let's POST the token
				String sInputs = buildHtmlInput("RelayState", sRelayState);
//				sInputs += buildHtmlInput("SAMLResponse", sAssertion);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));
				// RH, 20101104, this should be a SAMLRequest, we were just lucky the other side didn't bother   
				sInputs += buildHtmlInput("SAMLRequest", sAssertion);  //Tools.htmlEncode(nodeMessageContext.getTextContent()));
				
				// 20100317, Bauke: pass language to IdP (does not work in the GET version)
				String sLang = (String)_htSessionContext.get("language");
				if (sLang != null)
					sInputs += buildHtmlInput("language",sLang);
	
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Inputs=" + Utils.firstPartOf(sInputs,200));
				handlePostForm(_sPostTemplate, sDestination, sInputs, servletRequest, servletResponse);
			}
			Tools.pauseSensorData(_configManager, _systemLogger, _htSessionContext);  //20111102 can change the session
		}
		catch (ASelectException e) { // pass unchanged to the caller
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
			
			// 20130821, Bauke: save friendly name after session is gone
			if (_htSessionContext != null) {
				String sStatus = (String)_htSessionContext.get("status");
				String sAppId = (String)_htSessionContext.get("app_id");
				if ("del".equals(sStatus) && Utils.hasValue(sAppId)) {
					String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
					HandlerTools.setEncryptedCookie(servletResponse, "requestor_friendly_name", sUF, _configManager.getCookieDomain(), -1/*age*/, _systemLogger);
				}
			}
			_oSessionManager.finalSessionProcessing(_htSessionContext, true/*update session*/);
		}
		return new RequestState(null);
	}

	// RH, 20200616, sn
	public Extensions createClusterExtensions(String sApplicationLevel, String sApplicationId, PartnerData partnerData)
			throws JAXBException, PropertyException, ParserConfigurationException, UnmarshallingException, ASelectException
		{
			String sMethod = "createClusterExtensions";
			Extensions extensions = new ExtensionsBuilder().buildObject(new QName(SAMLConstants.SAML20P_NS,
			        Extensions.LOCAL_NAME, SAMLConstants.SAML20P_PREFIX));
			ArrayList<XMLObject> extObjects = new ArrayList<XMLObject>();

			
			extensions.getUnknownXMLObjects().addAll(extObjects);
			return extensions;

		}
	// RH, 20200616, en

	
	/**
	 * @param sMethod
	 * @return
	 * @throws JAXBException
	 * @throws PropertyException
	 * @throws ParserConfigurationException
	 * @throws UnmarshallingException
	 * @throws ASelectException 
	 */
	public Extensions createSTORKExtensions(String sApplicationLevel, String sApplicationId, PartnerData partnerData)
		throws JAXBException, PropertyException, ParserConfigurationException, UnmarshallingException, ASelectException
	{
		
		String sMethod = "createSTORKExtensions";
		ArrayList<XMLObject> extObjects = new ArrayList<XMLObject>();
		Integer assLevel = partnerData.getExtensionsdata4partner().getQualityAuthenticationAssuranceLevel();
		if (assLevel == null) {
			// RH, 20180810, sn
			String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
			boolean useNewLoa = (specialSettings != null && specialSettings.contains("use_newloa"));
			String s_loaLevel = null;
			if (useNewLoa) {
				s_loaLevel = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, true, SecurityLevel.getNewLoaLevels(), _systemLogger);
			} else {
				s_loaLevel = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, true, SecurityLevel.getDefaultLevels(), _systemLogger);
			}
			// RH, 20180810, en
//			String s_loaLevel = SecurityLevel.convertLevelToAuthnContextClassRefURI(sApplicationLevel, true, _systemLogger);// RH, 20180810, o
			assLevel = SecurityLevel.loa2stork(s_loaLevel);
		}
		
		String spSect = partnerData.getExtensionsdata4partner().getSpSector();
		
		String spInstitution = partnerData.getExtensionsdata4partner().getSpInstitution();	// SpInstitution must be done via "any" element, not part of STORK extensions
		String spApplication = partnerData.getExtensionsdata4partner().getSpApplication();
		if (spApplication == null) spApplication = sApplicationId;
		String spCountry = partnerData.getExtensionsdata4partner().getSpCountry();;
		
		Boolean eIDSectorShare = partnerData.getExtensionsdata4partner().geteIDSectorShare();
		Boolean eIDCrossSectorShare = partnerData.getExtensionsdata4partner().geteIDCrossSectorShare();
		Boolean eIDCrossBorderShare = partnerData.getExtensionsdata4partner().geteIDCrossBorderShare();
		
		Extensions extensions = new ExtensionsBuilder().buildObject(new QName(SAMLConstants.SAML20P_NS,
		        Extensions.LOCAL_NAME, SAMLConstants.SAML20P_PREFIX));
		
		 eu.stork.extension.assertion.ObjectFactory extFact = new  eu.stork.extension.assertion.ObjectFactory();
		 JAXBContext context = JAXBContext.newInstance(extFact.getClass());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created context:" + context.toString());
		 javax.xml.bind.Marshaller m = context.createMarshaller();
		 m.setProperty(javax.xml.bind.Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        try {
        	// com.sun.xml.internal.bind.marshaller.NamespacePrefixMapper; gone from jdk6u18 onwards, so we implement our own
            m.setProperty("com.sun.xml.bind.namespacePrefixMapper",new NamespacePrefixMapperImpl());
        } catch( PropertyException e ) {
            // if the JAXB provider doesn't recognize the prefix mapper,
            // it will throw this exception. Since being unable to specify
            // a human friendly prefix is not really a fatal problem,
            // you can just continue marshalling without failing
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not set marshaller property namespacePrefixMapper, trying to continue");
        }
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Marshaller:" + m.toString());
		 JAXBElement<Integer> oqal = extFact.createQualityAuthenticationAssuranceLevel(assLevel);
		 if (oqal != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created QualityAuthenticationAssuranceLevel:" + oqal.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m.marshal( oqal, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create QualityAuthenticationAssuranceLevel !" );
		 }
		 JAXBElement<String> ospSect = extFact.createSpSector(spSect);
		 if (ospSect != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created spSector:" + ospSect.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m.marshal( ospSect, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create spSector !" );
		 }
		 
		 JAXBElement<String> ospInstitution = extFact.createSpInstitution(spInstitution);	// this is a custom defined element, not part of stork
		 if (ospInstitution != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created spInstitution:" + ospInstitution.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m.marshal( ospInstitution, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create spInstitution !" );
		 }
		  //
		 
		 JAXBElement<String> ospApplication = extFact.createSpApplication(spApplication);
		 if (ospApplication != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created spApplication:" + ospApplication.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m.marshal( ospApplication, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create spSector !" );
		 }
		 
		 JAXBElement<String> ospCountry = extFact.createSpCountry(spCountry);
		 if (ospCountry != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created spCountry:" + ospCountry.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m.marshal( ospCountry, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create spCountry !" );
		 }
		 
		 
		 eu.stork.extension.protocol.ObjectFactory pextFact = new  eu.stork.extension.protocol.ObjectFactory();
		 JAXBContext context2 = JAXBContext.newInstance(pextFact.getClass());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created context:" + context2.toString());
		 javax.xml.bind.Marshaller m2 = context2.createMarshaller();
		 m2.setProperty(javax.xml.bind.Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        try {
        	// com.sun.xml.internal.bind.marshaller.NamespacePrefixMapper; gone from jdk6u18 onwards
        	m2.setProperty("com.sun.xml.bind.namespacePrefixMapper",new NamespacePrefixMapperImpl());
        } catch( PropertyException e ) {
            // if the JAXB provider doesn't recognize the prefix mapper,
            // it will throw this exception. Since being unable to specify
            // a human friendly prefix is not really a fatal problem,
            // you can just continue marshalling without failing
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not set marshaller property namespacePrefixMapper, trying to continue");
        }
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Marshaller:" + m.toString());
		
		 JAXBElement<Boolean> oeIDSectorShare = pextFact.createEIDSectorShare(eIDSectorShare);
		 if (oeIDSectorShare != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created oeIDSectorShare:" + oeIDSectorShare.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m2.marshal( oeIDSectorShare, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create oeIDSectorShare !" );
		 }

		 JAXBElement<Boolean> oeIDCrossSectorShare = pextFact.createEIDCrossSectorShare(eIDCrossSectorShare);
		 if (oeIDCrossSectorShare != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created eIDCrossSectorShare:" + oeIDCrossSectorShare.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m2.marshal( oeIDCrossSectorShare, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create oeIDCrossSectorShare !" );
		 }
		
		 
		 JAXBElement<Boolean> oeIDCrossBorderShare = pextFact.createEIDCrossBorderShare(eIDCrossBorderShare);
		 if (oeIDCrossBorderShare != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created eIDCrossBorderShare:" + oeIDCrossBorderShare.getName().getLocalPart());
				       DOMResult result = new DOMResult();
				       m2.marshal( oeIDCrossBorderShare, result ); 
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
				       Document doc = (Document) result.getNode();
				       Element element = doc.getDocumentElement();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
								Auxiliary.REGEX_PATTERNS));
						UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
						Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());

						XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
						if (xmlobject != null) {
							extObjects.add(xmlobject);
						} else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
						}
		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create eIDCrossBorderShare !" );
		 }
		 

		 eu.stork.extension.protocol.RequestedAttributesType rats = pextFact.createRequestedAttributesType();
		 JAXBElement<eu.stork.extension.protocol.RequestedAttributesType> oreqattributes = pextFact.createRequestedAttributes(rats);
		 if (oreqattributes != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created RequestedAttributes:" + oreqattributes.getName().getLocalPart());
				
				for ( Map<String, Object> reqAttribs :  partnerData.getExtensionsdata4partner().getRequestedAttributes() ) {
		 
					eu.stork.extension.protocol.RequestedAttributeType rat = pextFact.createRequestedAttributeType();
					
					if (reqAttribs.get("isrequired") != null) rat.setIsRequired((Boolean) reqAttribs.get("isrequired"));
					rat.setNameFormat((String) reqAttribs.get("nameformat"));
					rat.setName((String) reqAttribs.get("name"));
					rats.getRequestedAttribute().add(rat);

				}

					DOMResult result = new DOMResult();
					m2.marshal( oreqattributes, result ); 
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created result so far:" +result);
					Document doc = (Document) result.getNode();
					Element element = doc.getDocumentElement();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created element so far:" +Auxiliary.obfuscate(XMLHelper.prettyPrintXML(element), 
							Auxiliary.REGEX_PATTERNS));
					UnmarshallerFactory factory = org.opensaml.xml.Configuration.getUnmarshallerFactory();
					Unmarshaller unmarshaller = factory.getUnmarshaller( XSAny.TYPE_NAME );
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Unmarshaller:" + unmarshaller.toString());
					
					XMLObject xmlobject = (XMLObject) unmarshaller.unmarshall(element);
					if (xmlobject != null) {
						extObjects.add(xmlobject);
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create xmlobject !" );
					}

		 } else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create RequestedAttributes !" );
		 }
		 
		extensions.getUnknownXMLObjects().addAll(extObjects);
		
		return extensions;
	}

	// RH, 20200629, sn
	/**
	 * @param sMethod
	 * @return
	 * @throws JAXBException
	 * @throws PropertyException
	 * @throws ParserConfigurationException
	 * @throws UnmarshallingException
	 * @throws ASelectException 
	 */
	public Extensions createeIDExtensions(String sApplicationLevel, String sApplicationId, PartnerData partnerData)
		throws JAXBException, PropertyException, ParserConfigurationException, UnmarshallingException, ASelectException
	{
		
		String sMethod = "createeIDExtensions";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Building eID extensions");

		ArrayList<XMLObject> extObjects = new ArrayList<XMLObject>();
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);


		
		Extensions extensions = new ExtensionsBuilder().buildObject(new QName(SAMLConstants.SAML20P_NS,
		        Extensions.LOCAL_NAME, SAMLConstants.SAML20P_PREFIX));
		
		
		// Create an attribute builder
		QName qName = Attribute.DEFAULT_ELEMENT_NAME;
		_systemLogger.log(Level.FINER, MODULE, sMethod, "Attribute qName="+qName);
		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(qName);

		for (String attName : partnerData.getExtensionsdata4partner().geteIDAttributes().keySet()) {
			Attribute theAttribute = attributeBuilder.buildObject();
			String sKey = attName;
			String sValue = partnerData.getExtensionsdata4partner().geteIDAttributes().get(sKey);
			theAttribute.setName(sKey);
			if (sValue != null && sValue.length()>0 ) {	// Should not be null nor length = 0
				XSString theAttributeValue = null;
				theAttributeValue = (XSString)stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
				theAttributeValue.setValue(sValue);
				theAttribute.getAttributeValues().add(theAttributeValue);
			} else {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Empty attribute value found, skipping empty value for key: "+ sKey);
			}
			extObjects.add(theAttribute);
		}

		extensions.getUnknownXMLObjects().addAll(extObjects);
		
		return extensions;
	}
	// RH, 20200629, en
	
	
	/**
	 * Gets the application level.
	 * 
	 * @param sApplicationId
	 *            the s application id
	 * @return the application level
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getApplicationLevel(String sApplicationId)
	throws ASelectException
	{
		String sMethod = "getApplicationLevel";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Id=" + sApplicationId);

		Object oApplications = null;
		try {
			oApplications = _configManager.getSection(null, "applications");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'applications' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		Object oApplication = null;
		try {
			oApplication = _configManager.getSection(oApplications, "application");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'application' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String sApplicationLevel = null;
		while (oApplication != null) {
			if (_configManager.getParam(oApplication, "id").equals(sApplicationId)) {
				sApplicationLevel = _configManager.getParam(oApplication, "level");
				if (sApplicationLevel == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config attribute 'level' found");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				return sApplicationLevel;
			}
			oApplication = _configManager.getNextSection(oApplication);
		}
		return null;
	}
	
	/**
	 * Gets the RequesterID for the AuthnRequest.
	 * 
	 * @param sApplicationId
	 *            the s application id
	 * @return the application level
	 * @throws ASelectException
	 *             the a select exception
	 */
	private String getApplicationRequesterID(String sApplicationId)
	throws ASelectException
	{
		String sMethod = "getApplicationRequesterID";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Id=" + sApplicationId);

		Object oApplications = null;
		try {
			oApplications = _configManager.getSection(null, "applications");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'applications' found", e);
			return null;
		}

		Object oApplication = null;
		try {
			oApplication = _configManager.getSection(oApplications, "application");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'application' found", e);
			return null;
		}
		while (oApplication != null) {
			if (_configManager.getParam(oApplication, "id").equals(sApplicationId)) {
//				String sApplicationRequesterID = _configManager.getSimpleParam(oApplication,  "authnrequest_requesterid", false);
				String sApplicationRequesterID = _configManager.getParamFromSection(oApplication, "authnrequest_scoping", "authnrequest_requesterid", false);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found 'authnrequest_requesterid' =" + sApplicationRequesterID);
				return sApplicationRequesterID;
			}
			oApplication = _configManager.getNextSection(oApplication);
		}
		return null;
	}
    
	
    class NamespacePrefixMapperImpl extends NamespacePrefixMapper {

        /**
         * Returns a preferred prefix for the given namespace URI.
         * 
         * This method is intended to be overrided by a derived class.
         * 
         * @param namespaceUri
         *      The namespace URI for which the prefix needs to be found.
         *      Never be null. "" is used to denote the default namespace.
         * @param suggestion
         *      When the content tree has a suggestion for the prefix
         *      to the given namespaceUri, that suggestion is passed as a
         *      parameter. Typicall this value comes from the QName.getPrefix
         *      to show the preference of the content tree. This parameter
         *      may be null, and this parameter may represent an already
         *      occupied prefix. 
         * @param requirePrefix
         *      If this method is expected to return non-empty prefix.
         *      When this flag is true, it means that the given namespace URI
         *      cannot be set as the default namespace.
         * 
         * @return
         *      null if there's no prefered prefix for the namespace URI.
         *      In this case, the system will generate a prefix for you.
         * 
         *      Otherwise the system will try to use the returned prefix,
         *      but generally there's no guarantee if the prefix will be
         *      actually used or not.
         * 
         *      return "" to map this namespace URI to the default namespace.
         *      Again, there's no guarantee that this preference will be
         *      honored.
         * 
         *      If this method returns "" when requirePrefix=true, the return
         *      value will be ignored and the system will generate one.
         */
        public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
            // I want this namespace to be mapped to "stork"
            if( "urn:eu:stork:names:tc:STORK:1.0:assertion".equals(namespaceUri) )
                return "stork";
             
            // and the other will use "storkp".
            if( "urn:eu:stork:names:tc:STORK:1.0:protocol".equals(namespaceUri) )
                return "storkp";
             
            // otherwise I don't care. Just use the default suggestion, whatever it may be.
            return suggestion;
        }
        
        
        
        /**
         * Returns a list of namespace URIs that should be declared
         * at the root element.
         * <p>
         * By default, the JAXB RI produces namespace declarations only when
         * they are necessary, only at where they are used. Because of this
         * lack of look-ahead, sometimes the marshaller produces a lot of
         * namespace declarations that look redundant to human eyes. For example,
         * <pre><xmp>
         * <?xml version="1.0"?>
         * <root>
         *   <ns1:child xmlns:ns1="urn:foo"> ... </ns1:child>
         *   <ns2:child xmlns:ns2="urn:foo"> ... </ns2:child>
         *   <ns3:child xmlns:ns3="urn:foo"> ... </ns3:child>
         *   ...
         * </root>
         * <xmp></pre>
         * <p>
         * If you know in advance that you are going to use a certain set of
         * namespace URIs, you can override this method and have the marshaller
         * declare those namespace URIs at the root element. 
         * <p>
         * For example, by returning <code>new String[]{"urn:foo"}</code>,
         * the marshaller will produce:
         * <pre><xmp>
         * <?xml version="1.0"?>
         * <root xmlns:ns1="urn:foo">
         *   <ns1:child> ... </ns1:child>
         *   <ns1:child> ... </ns1:child>
         *   <ns1:child> ... </ns1:child>
         *   ...
         * </root>
         * <xmp></pre>
         * <p>
         * To control prefixes assigned to those namespace URIs, use the
         * {@link #getPreferredPrefix} method. 
         * 
         * @return
         *      A list of namespace URIs as an array of {@link String}s.
         *      This method can return a length-zero array but not null.
         *      None of the array component can be null. To represent
         *      the empty namespace, use the empty string <code>""</code>.
         * 
         * @since
         *      JAXB RI 1.0.2 
         */
        public String[] getPreDeclaredNamespaceUris() {
            return new String[] { "urn:eu:stork:names:tc:STORK:1.0:assertion" , "urn:eu:stork:names:tc:STORK:1.0:protocol"};
        }
    }

}
