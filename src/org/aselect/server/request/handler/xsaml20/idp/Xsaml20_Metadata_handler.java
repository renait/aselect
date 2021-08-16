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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import javax.servlet.ServletConfig;

import org.apache.commons.codec.binary.Base64;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AuthzService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.XMLSignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.w3c.dom.Node;
import org.opensaml.xml.util.XMLHelper;

// Configuration example
//
// <handler id="saml20_idp_metadata"
//    class="org.aselect.server.request.handler.xsaml20.idp.Xsaml20_Metadata_handler"
//    target="/saml20_idp_metadata">
// </handler>
//
public class Xsaml20_Metadata_handler extends Saml20_Metadata
{
	private final static String MODULE = "idp.Xsaml20_Metadata_handler";

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		super.init(oServletConfig, oConfig);
		String sCheckCertificates = ASelectConfigManager.getSimpleParam(oConfig, "check_certificates", false);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "check_certificates=" + sCheckCertificates);
		if (sCheckCertificates != null) {
			AbstractMetaDataManager.setCheckCertificates(sCheckCertificates);
		}
	}

	// Get handler specific data from configuration
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#aselectReader()
	 */
	@Override
//	protected void aselectReader()
	protected void aselectReader(String groupid)
	throws ASelectException
	{
		String sMethod = "aselectReader";
		String sRedirectUrl = getRedirectURL();

		Object oRequest = null;
		Object oHandlers = null;
		Object oHandler = null;
//		super.aselectReader();
		super.aselectReader(groupid);

//		setSingleSignOnServiceTarget("saml20_sso"); // Preliminary default	// RH, 20190311, o
		// RH, 20190311, sn
		// cleaunup old values
		setSingleSignOnServiceTarget(null);
		setArtifactResolverTarget(null);
		setIdpSloHttpLocation(null);
		setIdpSloHttpResponse(null);
		setIdpSloSoapLocation(null);
		setIdpSloSoapResponse(null);
		setIdpSSSoapLocation(null);
		// RH, 20190311, sn
		try {
			oRequest = _configManager.getSection(null, "requests");
			oHandlers = _configManager.getSection(oRequest, "handlers");
			oHandler = _configManager.getSection(oHandlers, "handler");

			// Get targets for our handlers
			// NOTE: id's must match the configuration!
			for (; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				try {
					String sId = _configManager.getParam(oHandler, "id");
//					if (!sId.startsWith("saml20_")) {	// RH, 20190311, o
					if (!sId.contains("saml20_")) {	// RH, 20190311, n
						continue;
					}
//					String groupid = getRequestedGroupId();
					if (groupid != null) {
						String sGroup = null;
						try {
							sGroup = _configManager.getParam(oHandler, "resourcegroup");
						} catch (ASelectConfigException ace) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'resourcegroup' found for handler id:" + sId + ", continuing");
							continue;
						}
						if (!groupid.equals(sGroup)) {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Handler not belonging to requested 'groupid':" + groupid + ", continuing");
							continue;
						} else {
							String sTarget = _configManager.getParam(oHandler, "target");
							String sLocalUrl = Utils.getSimpleParam(_configManager, _systemLogger, oHandler, "local_url", false);
							_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget + "local_url="+sLocalUrl);
							sTarget = sTarget.replace("\\", "");
							sTarget = sTarget.replace(".*", "");
		
							if (sId.contains("saml20_sso")) {
								setSingleSignOnServiceTarget(sTarget);
								setIdpSsoUrl((sLocalUrl != null) ? sLocalUrl : sRedirectUrl);
							}
							else if (sId.contains("saml20_artifactresolver")) {
								setArtifactResolverTarget(sTarget);
								setIdpArtifactResolverUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
							else if (sId.contains("saml20_idp_slo_http_request")) {
								setIdpSloHttpLocation(sTarget);
								setIdpSloHttpRequestUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
							else if (sId.contains("saml20_idp_slo_http_response")) {
								setIdpSloHttpResponse(sTarget);
								setIdpSloHttpResponseUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
							else if (sId.contains("saml20_idp_slo_soap_request")) {
								setIdpSloSoapLocation(sTarget);
								setIdpSloSoapRequestUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
							else if (sId.contains("saml20_idp_slo_soap_response")) {
								setIdpSloSoapResponse(sTarget);
								setIdpSloSoapResponseUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
							else if (sId.contains("saml20_idp_session_sync")) {
								setIdpSSSoapLocation(sTarget);
								setIdpSyncUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
							}
						}
					} else {	// what we used to do	// RH, 20190311, en	
					// RH, 20190311, so
//					try {
//						String sId = _configManager.getParam(oHandler, "id");
//						if (!sId.startsWith("saml20_")) {
//							continue;
//						}
					// RH, 20190311, eo
						String sTarget = _configManager.getParam(oHandler, "target");
						String sLocalUrl = Utils.getSimpleParam(_configManager, _systemLogger, oHandler, "local_url", false);
						_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget + "local_url="+sLocalUrl);
						sTarget = sTarget.replace("\\", "");
						sTarget = sTarget.replace(".*", "");
	
						if (sId.equals("saml20_sso")) {
							setSingleSignOnServiceTarget(sTarget);
							setIdpSsoUrl((sLocalUrl != null) ? sLocalUrl : sRedirectUrl);
						}
						else if (sId.equals("saml20_artifactresolver")) {
							setArtifactResolverTarget(sTarget);
							setIdpArtifactResolverUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
						else if (sId.equals("saml20_idp_slo_http_request")) {
							setIdpSloHttpLocation(sTarget);
							setIdpSloHttpRequestUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
						else if (sId.equals("saml20_idp_slo_http_response")) {
							setIdpSloHttpResponse(sTarget);
							setIdpSloHttpResponseUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
						else if (sId.equals("saml20_idp_slo_soap_request")) {
							setIdpSloSoapLocation(sTarget);
							setIdpSloSoapRequestUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
						else if (sId.equals("saml20_idp_slo_soap_response")) {
							setIdpSloSoapResponse(sTarget);
							setIdpSloSoapResponseUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
						else if (sId.equals("saml20_idp_session_sync")) {
							setIdpSSSoapLocation(sTarget);
							setIdpSyncUrl(((sLocalUrl != null) ? sLocalUrl : sRedirectUrl));
						}
					}	// RH, 20190311, n
				}
				catch (ASelectConfigException e) {
//						_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'id' found in config next section 'handler'", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
		}
		catch (ASelectConfigException e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find 'aselect' config section in config file", e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find one of 'requests', 'handlers' or 'handler' in 'aselect' config section in config file", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	* Create Metadata entries for IdP
	 * @param the remoteID
	 * 		The remote identity for whom to create the metadata.
	 * 		with entityID is redirect_url from aselect.xml
	 * @return the xml metadata string
	 * @throws ASelectException
	 *             the a select exception
	* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#createMetaDataXML()
	 */
	@Override
//	protected String createMetaDataXML(String sLocalIssuer)
//	protected String createMetaDataXML(String sRemoteID)
	protected String createMetaDataXML(String sRemoteID, String resourceGroup)
	
	throws ASelectException
	{
		String sMethod = "createMetaDataXML";
		String xmlMDRequest = null;
		DateTime tStamp = new DateTime();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting to build metadata");

		// Create the EntityDescriptor
		SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) _oBuilderFactory
				.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

		EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
		// optionally we could get another entityID from application section in aselect.xml based on remoteID
		// but we don't use sRemoteID just yet
//		entityDescriptor.setEntityID((sRemoteID != null)? sRemoteID: getEntityIdIdp());	// RH, 20110111, o
		entityDescriptor.setEntityID(getEntityIdIdp());	// RH, 20110111, n
		entityDescriptor.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));

		if (getEpoch() != null)	tStamp = getEpoch();	// RH, 20200124, n
		if (getValidUntil() != null)
			entityDescriptor.setValidUntil(tStamp.plus(getValidUntil().longValue()));
		if (getCacheDuration() != null)
			entityDescriptor.setCacheDuration(getCacheDuration());

		// Create the IDPSSODescriptor
		SAMLObjectBuilder<IDPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<IDPSSODescriptor>) _oBuilderFactory
				.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		IDPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();

		// Create the SingleSignOnService
		if (getSingleSignOnServiceTarget() != null) {
			SAMLObjectBuilder<SingleSignOnService> ssoServiceBuilder = (SAMLObjectBuilder<SingleSignOnService>) _oBuilderFactory
					.getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);
			SingleSignOnService ssoService = ssoServiceBuilder.buildObject();
			ssoService.setBinding(singleSignOnServiceBindingConstantREDIRECT);
			ssoService.setLocation(getIdpSsoUrl() + getSingleSignOnServiceTarget());
			ssoDescriptor.getSingleSignOnServices().add(ssoService);
			// RM_47_01
			// add HTTP-POST binding on same handler
			SingleSignOnService ssoServicePOST = ssoServiceBuilder.buildObject();
			ssoServicePOST.setBinding(singleSignOnServiceBindingConstantPOST);
			ssoServicePOST.setLocation(getIdpSsoUrl() + getSingleSignOnServiceTarget());
			ssoDescriptor.getSingleSignOnServices().add(ssoServicePOST);
		}

		// Create the ArtifactResolutionService
		if (getArtifactResolverTarget() != null) {
			SAMLObjectBuilder<ArtifactResolutionService> artResolutionSeviceBuilder = (SAMLObjectBuilder<ArtifactResolutionService>) _oBuilderFactory
					.getBuilder(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
			ArtifactResolutionService artResolutionService = artResolutionSeviceBuilder.buildObject();
			artResolutionService.setBinding(artifactResolutionServiceBindingConstantSOAP);
			artResolutionService.setLocation(getIdpArtifactResolverUrl() + getArtifactResolverTarget());
			artResolutionService.setIsDefault(true);
			artResolutionService.setIndex(0);
			ssoDescriptor.getArtifactResolutionServices().add(artResolutionService);
		}

		// Create the SingleLogoutService HTTP
		if (getIdpSloHttpLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
			sloHttpService.setBinding(singleLogoutServiceBindingConstantREDIRECT);
			sloHttpService.setLocation(getIdpSloHttpRequestUrl() + getIdpSloHttpLocation());
			if (getIdpSloHttpResponse() != null)
				sloHttpService.setResponseLocation(getIdpSloHttpResponseUrl() + getIdpSloHttpResponse());
			ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
		}

		// Create the SingleLogoutService SOAP
		if (getIdpSloSoapLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloSoaperviceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloSoapService = sloSoaperviceBuilder.buildObject();
			sloSoapService.setBinding(singleLogoutServiceBindingConstantSOAP);
			sloSoapService.setLocation(getIdpSloSoapRequestUrl() + getIdpSloSoapLocation());
			if (getIdpSloSoapResponse() != null)
				sloSoapService.setResponseLocation(getIdpSloSoapResponseUrl() + getIdpSloSoapResponse());
			ssoDescriptor.getSingleLogoutServices().add(sloSoapService);
		}

		// Create the PDPDescriptor>
		SAMLObjectBuilder<PDPDescriptor> pdpDescriptorBuilder = (SAMLObjectBuilder<PDPDescriptor>) _oBuilderFactory
				.getBuilder(PDPDescriptor.DEFAULT_ELEMENT_NAME);
		PDPDescriptor pdpDescriptor = pdpDescriptorBuilder.buildObject();

		// Create the AuthDecisionQuery target
		if (getIdpSSSoapLocation() != null) {
			SAMLObjectBuilder<AuthzService> adqSoaperviceBuilder = (SAMLObjectBuilder<AuthzService>) _oBuilderFactory
					.getBuilder(AuthzService.DEFAULT_ELEMENT_NAME);
			AuthzService adqSoapService = adqSoaperviceBuilder.buildObject();
			adqSoapService.setBinding(authzServiceBindingConstantSOAP);
			adqSoapService.setLocation(getIdpSyncUrl() + getIdpSSSoapLocation());
			pdpDescriptor.getAuthzServices().add(adqSoapService);
		}

		// Create final EntityDescriptor
		ssoDescriptor.setWantAuthnRequestsSigned(true);
		// ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
//		ssoDescriptor.getKeyDescriptors().add(createKeyDescriptor(getSigningCertificate()));	// RH, 20161007, o
		ssoDescriptor.getKeyDescriptors().add(createKeyDescriptor(getSigningCertificate(), isAddkeyname2descriptors()));	// RH, 20161007, n
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

//		pdpDescriptor.getKeyDescriptors().add(createKeyDescriptor(getSigningCertificate()));	// RH, 20161007, o
		pdpDescriptor.getKeyDescriptors().add(createKeyDescriptor(getSigningCertificate(), isAddkeyname2descriptors()));	// RH, 20161007, n
		pdpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		// Make pdp descriptor optional
		if ( isAddpdpdescriptor() ) {
			entityDescriptor.getRoleDescriptors().add(pdpDescriptor);
		}
		
		// Add option for sha256 and KeyName
		
//		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor);// RH, 20150910, o
//		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor, isUsesha256() ? "sha256" : "sha1", 
//				isAddkeyname(), isAddcertificate());// RH, 20150910, n	// RH, 20180918, o
		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor, isUsesha256() ? "sha256" : "sha1", 
				isAddkeyname(), isAddcertificate(), null);// RH, 20150910, n	// RH, 20180918, n
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Just built the entityDescriptor");

		// Marshall to the Node
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(entityDescriptor);
		Node node = null;
		try {
			node = marshaller.marshall(entityDescriptor);
			_systemLogger.log(Level.INFO, MODULE, sMethod, xmlMDRequest);
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not marshall metadata", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Just marshalled into metadata node");

		xmlMDRequest = XMLHelper.nodeToString(node);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "xmlMDRequest: " + xmlMDRequest);
		return xmlMDRequest;
	}

	
	// Create the KeyDescriptor
	/**
	 * Creates the key descriptor.
	 * 
	 * @param signingCertificate
	 *            the signing certificate
	 * @return the key descriptor
	 */
	private KeyDescriptor createKeyDescriptor(String signingCertificate)
	{
		return createKeyDescriptor(signingCertificate, false);	// backwards compatibility 
	}
	
	// Create the KeyDescriptor
	// RM_47_02
	/**
	 * Creates the key descriptor.
	 * 
	 * @param signingCertificate
	 *            the signing certificate
	 * @param boolean addkeyname
	 *           add the keyname (thumbprint) as well
	 * @return the key descriptor
	 */
	private KeyDescriptor createKeyDescriptor(String signingCertificate, boolean addkeyname)
	{
		String sMethod = "createKeyDescriptor";

		SAMLObjectBuilder<KeyDescriptor> keyDescriptorBuilder = (SAMLObjectBuilder<KeyDescriptor>) _oBuilderFactory
				.getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
		keyDescriptor.setUse(org.opensaml.xml.security.credential.UsageType.SIGNING);

		XMLSignatureBuilder<KeyInfo> keyInfoBuilder = (XMLSignatureBuilder<KeyInfo>) _oBuilderFactory
				.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = keyInfoBuilder.buildObject();

		X509CertificateBuilder x509CertificateBuilder = (X509CertificateBuilder) _oBuilderFactory
				.getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = x509CertificateBuilder.buildObject();
		x509Certificate.setValue(signingCertificate);

		X509DataBuilder x509DataBuilder = (X509DataBuilder) _oBuilderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();
		x509Data.getX509Certificates().add(x509Certificate);
		keyInfo.getX509Datas().add(x509Data);

		// RH, 20161007, sn
		if (addkeyname) {
			byte[] baCert;
			try {
				baCert = signingCertificate.getBytes();	// use platform default because we encoded like that as well
				byte[] baCertDecoded = Base64.decodeBase64(baCert);
				MessageDigest mdDigest = MessageDigest.getInstance("SHA1");
				mdDigest.update(baCertDecoded);
				String sCertFingerPrint = Utils.byteArrayToHexString(mdDigest.digest());
				
				XMLSignatureBuilder<KeyName> keyNameBuilder = (XMLSignatureBuilder<KeyName>) _oBuilderFactory
						.getBuilder(KeyName.DEFAULT_ELEMENT_NAME);
				KeyName keyName = keyNameBuilder.buildObject();
	
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sCertFingerPrint:" + sCertFingerPrint);
				keyName.setValue(sCertFingerPrint);
				keyInfo.getKeyNames().add(keyName);
			}
			catch (NoSuchAlgorithmException e) {	// should never happen
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create MessageDigest for creating fingerprint, KeyName not added. " + e.getMessage());
			}
		}
		// RH, 20161007, en
		
		keyDescriptor.setKeyInfo(keyInfo);

		return keyDescriptor;
	}
}