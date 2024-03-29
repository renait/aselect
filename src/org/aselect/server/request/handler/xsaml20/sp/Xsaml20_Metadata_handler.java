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

import java.security.cert.CertificateEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Base64;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.PartnerData.ContactInfo;
import org.aselect.server.request.handler.xsaml20.PartnerData.Crypto;
import org.aselect.server.request.handler.xsaml20.PartnerData.HandlerInfo;
import org.aselect.server.request.handler.xsaml20.PartnerData.Metadata4Partner;
import org.aselect.server.request.handler.xsaml20.PartnerData.NamespaceInfo;
import org.aselect.server.request.handler.xsaml20.Saml20_Metadata;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.ServiceName;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.XMLSignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

// Configuration example
//
// <handler id="saml20_sp_metadata"
//    class="org.aselect.server.request.handler.xsaml20.sp.Xsaml20_Metadata_handler"
//    target="/saml20_sp_metadata">
// </handler>
//
public class Xsaml20_Metadata_handler extends Saml20_Metadata
{
	private final static String MODULE = "sp.Xsaml20_Metadata_handler";

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

//		super.aselectReader();
		super.aselectReader(groupid);
		// RH, 20190319, sn
		// cleaunup old values
		setAssertionConsumerTarget(null);
		setSpSloHttpLocation(null);
		setSpSloSoapLocation(null);
		setSpSloHttpResponse(null);
		setSpSloSoapResponse(null);

		setSpArtifactResolverTarget(null);

		// RH, 20190319, en
		try {
			Object oRequest = _configManager.getSection(null, "requests");
			Object oHandlers = _configManager.getSection(oRequest, "handlers");
			Object oHandler = _configManager.getSection(oHandlers, "handler");

			for (; oHandler != null; oHandler = _configManager.getNextSection(oHandler)) {
				try {
					String sId = _configManager.getParam(oHandler, "id");
//					if (!sId.startsWith("saml20_")) {	// RH, 20190319, o
					if (!sId.contains("saml20_")) {	// RH, 20190319, n
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
							_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget);
							sTarget = sTarget.replace("\\", "");
							sTarget = sTarget.replace(".*", "");
		
							if (sId.contains("saml20_assertionconsumer")) {
								setAssertionConsumerTarget(sTarget);
							}
							else if (sId.contains("saml20_sp_slo_http_request")) {
								setSpSloHttpLocation(sTarget);
							}
							else if (sId.contains("saml20_sp_slo_soap_request")) {
								setSpSloSoapLocation(sTarget);
							}
							else if (sId.contains("saml20_sp_slo_http_response")) {
								setSpSloHttpResponse(sTarget);
							}
							else if (sId.contains("saml20_sp_slo_soap_response")) {
								setSpSloSoapResponse(sTarget);
							}
							else if (sId.contains("saml20_sp_artifactresolver")) {
								setSpArtifactResolverTarget(sTarget);
							}
						}						
					} else {	// what we used to do
					// RH, 2090319, en
						String sTarget = _configManager.getParam(oHandler, "target");
						_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + " target=" + sTarget);
						sTarget = sTarget.replace("\\", "");
						sTarget = sTarget.replace(".*", "");
	
						if (sId.equals("saml20_assertionconsumer")) {
							setAssertionConsumerTarget(sTarget);
						}
						else if (sId.equals("saml20_sp_slo_http_request")) {
							setSpSloHttpLocation(sTarget);
						}
						else if (sId.equals("saml20_sp_slo_soap_request")) {
							setSpSloSoapLocation(sTarget);
						}
						else if (sId.equals("saml20_sp_slo_http_response")) {
							setSpSloHttpResponse(sTarget);
						}
						else if (sId.equals("saml20_sp_slo_soap_response")) {
							setSpSloSoapResponse(sTarget);
						}
						else if (sId.contains("saml20_sp_artifactresolver")) {
							setSpArtifactResolverTarget(sTarget);
						}
					}	// RH, 20190319, n
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config next section 'handler' found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not find 'aselect' config section in config file",
					e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	* Create Metadata entries for SP
	 * @param the remoteID
	 * 		The remote identity for whom to create the metadata. If null a default metadata xml will be created
	 * 		with entityID is redirect_url from aselect.xml 
	 * @return the xml metadata string
	 * @throws ASelectException
	 *             the a select exception
	* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_Metadata#createMetaDataXML()
	 */
	@Override
//	protected String createMetaDataXML(String sLocalIssuer)
//	protected String createMetaDataXML(String remoteID)
	protected String createMetaDataXML(String remoteID, String resourceGroup)
	throws ASelectException
	{
		String sMethod = "createMetaDataXML";
		String xmlMDRequest = null;
		DateTime tStamp = new DateTime();

		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting to build metadata");
//		 RH, 20110111, sn
		PartnerData partnerData = null;
		String sLocalIssuer = null;
		if (remoteID != null) {
			// find "id" in the partner's section
//			String resourceGroup = getRequestedGroupId();	// RH, 20190322, n	// RH, 20210412, o
//			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(remoteID);	// RH, 20190322, o
			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(resourceGroup, remoteID);	// RH, 20190322, o
		}
		if (partnerData != null)
			sLocalIssuer = partnerData.getLocalIssuer();

		Node node = null;
		
		
		Metadata4Partner metadata4partner = partnerData.getMetadata4partner();
		Crypto crypto4partner = partnerData.getCrypto();
		// RH, 20210421, sn
		boolean signEntityDescriptor = !(partnerData.getDVs() != null && partnerData.getDVs().size() > 0);
		boolean setValidityEntityDescriptor = !(partnerData.getDVs() != null && partnerData.getDVs().size() > 0);
		EntityDescriptor entityDescriptor = createEntityDescriptor(tStamp, /*partnerData,*/ sLocalIssuer, metadata4partner, crypto4partner,
				signEntityDescriptor, setValidityEntityDescriptor);
		// RH, 20210421, en
//		EntityDescriptor entityDescriptor = createEntityDescriptor(tStamp, /*partnerData,*/ sLocalIssuer, metadata4partner, crypto4partner);	// RH, 20210421, o

		// RH, 20210421, sn		
		EntitiesDescriptor entitiesDescriptor = null;
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "partnerData  getDVs():" + partnerData.getDVs());
		if (partnerData.getDVs() != null && partnerData.getDVs().size() > 0) {
			// Create the EntitiesDescriptor
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Adding DVs");
			SAMLObjectBuilder<EntitiesDescriptor> entitiesDescriptorBuilder = (SAMLObjectBuilder<EntitiesDescriptor>) _oBuilderFactory
					.getBuilder(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);

			entitiesDescriptor = entitiesDescriptorBuilder.buildObject();
			entitiesDescriptor.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));
			if (getEpoch() != null)	tStamp = getEpoch();
			if (getValidUntil() != null)
				entitiesDescriptor.setValidUntil(tStamp.plus(getValidUntil().longValue()));
			if (getCacheDuration() != null)
				entitiesDescriptor.setCacheDuration(getCacheDuration());

			entitiesDescriptor.getEntityDescriptors().add(entityDescriptor);
			// add DVs
			Set<String> dvs = partnerData.getDVs().keySet();
			for (String dv : dvs) {
				Metadata4Partner meta4dv =  partnerData.getDVs().get(dv).getMetadata();
				// RH, 20210420, sn
				Crypto crypto4dv =  partnerData.getDVs().get(dv).getCrypto();
				// Get the Crypto for the dv here
				EntityDescriptor entityDescriptorDV = createEntityDescriptor(tStamp, dv, meta4dv, crypto4dv, false, false);	// RH, 20210420, n
				// RH, 20210420, en
//				EntityDescriptor entityDescriptorDV = createEntityDescriptor(tStamp, /*partnerData,*/ sLocalIssuer, dvmeta, crypto4partner);	// RH, 20210420, o
				entitiesDescriptor.getEntityDescriptors().add(entityDescriptorDV);
			}
			// Still to do the signing here
			boolean usesha256 = metadata4partner.getSpecialsettings().contains("sha256");
			boolean addkeyname = Boolean.parseBoolean(metadata4partner.getAddkeyname());
			boolean addcertificate = Boolean.parseBoolean(metadata4partner.getAddcertificate());
			
			entitiesDescriptor = (EntitiesDescriptor) SamlTools.signSamlObject(entitiesDescriptor,  usesha256 ? "sha256": "sha1",
					addkeyname, addcertificate, crypto4partner);	// RH, 20180918, n

		}
		// RH, 20210421, en		
		
		// Marshall to the Node
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
//		Marshaller marshaller = factory.getMarshaller(entityDescriptor);
		Marshaller marshaller = factory.getMarshaller(entitiesDescriptor != null ? entitiesDescriptor : entityDescriptor);
		try {
//			node = marshaller.marshall(entityDescriptor);
			node = marshaller.marshall(entitiesDescriptor != null ? entitiesDescriptor : entityDescriptor);
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, e.getMessage(), e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not marshall metadata", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Marshalling done");
		xmlMDRequest = XMLHelper.nodeToString(node);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "xmlMDRequest: " + xmlMDRequest);
		return xmlMDRequest;
	}

	/**
	 * @param tStamp
	 * @param partnerData
	 * @param sLocalIssuer
	 * @param metadata4partner
	 * @param crypto TODO
	 * @return
	 * @throws ASelectException
	 */
	protected EntityDescriptor createEntityDescriptor(DateTime tStamp, /*PartnerData partnerData,*/
			String sLocalIssuer, Metadata4Partner metadata4partner, Crypto crypto, boolean sign, boolean setValidity) throws ASelectException {
		
		String sMethod = "createEntityDescriptor";

		// RH, 20110113, sn
		boolean addkeyname = false;
		boolean addcertificate = false;
		boolean usesha256 = false;
		// RH, 20110113, en
		boolean includesigningcertificate = true;	// RH, 20160225, n, defaults to true for backwards compatibility
		boolean includesigningkeyname = false;	// RH, 20160225, n, defaults to false for backwards compatibility
		boolean includeencryptioncertificate = false;	// RH, 20160225, n, defaults to false for backwards compatibility
		boolean includeencryptionkeyname = false;	// RH, 20160225, n, defaults to false for backwards compatibility
		
		
//		 RH, 20110111, en
		// RH, 20110113, sn
		_systemLogger.log(Level.INFO, MODULE, sMethod, "setting partnerdata");
//		if (partnerData != null) {
		if (metadata4partner != null) {
			addkeyname = Boolean.parseBoolean(metadata4partner.getAddkeyname());
			addcertificate = Boolean.parseBoolean(metadata4partner.getAddcertificate());
			
			// RH, 20160225, sn
			String _includesigningcertificate = metadata4partner.getIncludesigningcertificate();
			if (_includesigningcertificate != null)
				includesigningcertificate = Boolean.parseBoolean(_includesigningcertificate);
			String _includeencryptioncertificate = metadata4partner.getIncludeencryptioncertificate();
			if (_includeencryptioncertificate != null)
				includeencryptioncertificate = Boolean.parseBoolean(_includeencryptioncertificate);
			String _includesigningkeyname = metadata4partner.getIncludesigningkeyname();
			if (_includesigningkeyname != null)
				includesigningkeyname = Boolean.parseBoolean(_includesigningkeyname);
			String _includeencryptionkeyname = metadata4partner.getIncludeencryptionkeyname();
			if (_includeencryptionkeyname != null)
				includeencryptionkeyname = Boolean.parseBoolean(_includeencryptionkeyname);
			// RH, 20160225, en

			String specialsettings = metadata4partner.getSpecialsettings();
			usesha256 = specialsettings != null && specialsettings.toLowerCase().contains("sha256");
			
		}
		
		
		// Create the EntityDescriptor
		SAMLObjectBuilder<EntityDescriptor> entityDescriptorBuilder = (SAMLObjectBuilder<EntityDescriptor>) _oBuilderFactory
				.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

		EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
		// EntityID can be overruled by the caller
		entityDescriptor.setEntityID((sLocalIssuer != null)? sLocalIssuer: getEntityIdIdp());
		entityDescriptor.setID(SamlTools.generateIdentifier(_systemLogger, MODULE));

		if (setValidity) {	// RH, 20210421, n
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting validity on entityDescriptor");	// RH, 20210421, n
			if (getEpoch() != null)	tStamp = getEpoch();	// RH, 20200124, n
			if (getValidUntil() != null)
				entityDescriptor.setValidUntil(tStamp.plus(getValidUntil().longValue()));
			if (getCacheDuration() != null)
				entityDescriptor.setCacheDuration(getCacheDuration());
		}	// RH, 20210421, n
		
		//	RH, 20140320, sn
//		if (partnerData != null && partnerData.getMetadata4partner().getNamespaceInfo().size() > 0) {	// Get namespaceinfo + additional attributes to publish from partnerdata
		if (metadata4partner != null && metadata4partner.getNamespaceInfo().size() > 0) {	// Get namespaceinfo + additional attributes to publish from partnerdata
			Enumeration<NamespaceInfo> eHandler = metadata4partner.getNamespaceInfo().elements();
			while (eHandler.hasMoreElements()) {
				NamespaceInfo nsi = eHandler.nextElement();
				entityDescriptor.addNamespace(new Namespace(nsi.getUri(), nsi.getPrefix()));
				Hashtable<String, String> atts = nsi.getAttributes();
				Enumeration<String> attenum = atts.keys();
				while (attenum.hasMoreElements()) {
				String localp = attenum.nextElement();	
					entityDescriptor.getUnknownAttributes().put(new QName(nsi.getUri(), localp, nsi.getPrefix()), atts.get(localp));
				}
			}
		}
		//	RH, 20140320, en
		
		
		
		// Create the KeyDescriptor for signing certificate
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
		
		// RH, 20180920, sn
//		if (partnerData != null && crypto != null) {
		if (crypto != null) {
			java.security.cert.X509Certificate x509Cert = crypto.getX509Cert();
			try {
				String encodedCert = new String(Base64.encodeBase64(x509Cert.getEncoded()));
				x509Certificate.setValue(encodedCert);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Add specific partner certificate to Signing keyinfo");
			} catch (CertificateEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error encoding certificate");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		} else {
		// RH, 20180920, en
			x509Certificate.setValue(getSigningCertificate());
		}	// RH, 20180920, n

		X509DataBuilder x509DataBuilder = (X509DataBuilder) _oBuilderFactory.getBuilder(X509Data.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = x509DataBuilder.buildObject();
		x509Data.getX509Certificates().add(x509Certificate);
		if (includesigningcertificate)	// RH, 20160225, n
			keyInfo.getX509Datas().add(x509Data);
		
//		if ( addkeyname ) {	// RH, 20160225, o
		if ( includesigningkeyname || addkeyname /* backwards compatibility */  ) {	// RH, 20160225, n
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Add keyname to keyinfo");	// RH, 20160223, o
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Add keyname to Signing keyinfo");	// RH, 20160223, n

			XMLSignatureBuilder<KeyName> keyNameBuilder = (XMLSignatureBuilder<KeyName>) _oBuilderFactory
			.getBuilder(KeyName.DEFAULT_ELEMENT_NAME);
			KeyName keyName = keyNameBuilder.buildObject();
			// RH, 20180920, sn
			
//			if (partnerData != null && partnerData.getCrypto() != null) {
			if (crypto != null) {
				keyName.setValue( crypto.getCertFingerPrint());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Adding specific partner certificate keyname to Signing keyinfo");	// RH, 20160223, n
			} else {
				// RH, 20180920, en
				keyName.setValue( _configManager.getDefaultCertId());
			}	// RH, 20180920, n

			keyInfo.getKeyNames().add(keyName);
		}

		keyDescriptor.setKeyInfo(keyInfo);

		// RH, 20160223, sn
		// Create the KeyDescriptor for encryption certificate
		KeyDescriptor keyDescriptorEncryption = keyDescriptorBuilder.buildObject();
		keyDescriptorEncryption.setUse(org.opensaml.xml.security.credential.UsageType.ENCRYPTION);

		KeyInfo keyInfoEncryption = keyInfoBuilder.buildObject();

		X509Certificate x509CertificateEncryption = x509CertificateBuilder.buildObject();
		// RH, 20180920, sn
//		if (partnerData != null && partnerData.getCrypto() != null) {
		if (crypto != null) {
			java.security.cert.X509Certificate x509Cert = crypto.getX509Cert();
			try {
				String encodedCert = new String(Base64.encodeBase64(x509Cert.getEncoded()));
				x509CertificateEncryption.setValue(encodedCert);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Add specific partner certificate to Encryption keyinfo");
			} catch (CertificateEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error encoding certificate");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		} else {
		// RH, 20180920, en
			x509CertificateEncryption.setValue(getSigningCertificate());	// For now we use the same for signing and encryption
		}	// RH, 20180920, n
		X509Data x509DataEncryption = x509DataBuilder.buildObject();
		x509DataEncryption.getX509Certificates().add(x509CertificateEncryption);
		if (includeencryptioncertificate)	// RH, 20160225, n
			keyInfoEncryption.getX509Datas().add(x509DataEncryption);
		
		if ( includeencryptionkeyname ) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Add keyname to Encryption keyinfo");

			XMLSignatureBuilder<KeyName> keyNameBuilder = (XMLSignatureBuilder<KeyName>) _oBuilderFactory
			.getBuilder(KeyName.DEFAULT_ELEMENT_NAME);
			KeyName keyNameEncryption = keyNameBuilder.buildObject();
			// RH, 20180920, sn
//			if (partnerData != null && partnerData.getCrypto() != null) {
			if (crypto != null) {
				keyNameEncryption.setValue( crypto.getCertFingerPrint());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Adding specific partner certificate keyname to Encryption keyinfo");
			} else {
				// RH, 20180920, en
				keyNameEncryption.setValue( _configManager.getDefaultCertId());	// For now we use the same for signing and encryption
			}	// RH, 20180920, n
			keyInfoEncryption.getKeyNames().add(keyNameEncryption);
		}

		keyDescriptorEncryption.setKeyInfo(keyInfoEncryption);
		// RH, 20160223, en
		
		// Create the SPSSODescriptor
		SAMLObjectBuilder<SPSSODescriptor> ssoDescriptorBuilder = (SAMLObjectBuilder<SPSSODescriptor>) _oBuilderFactory
				.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		SPSSODescriptor ssoDescriptor = ssoDescriptorBuilder.buildObject();

		// RH, 20110113, sn
//		if (partnerData != null && partnerData.getMetadata4partner().getHandlers().size() > 0) {	// Get handlers to publish from partnerdata
		if (metadata4partner != null && metadata4partner.getHandlers().size() > 0) {	// Get handlers to publish from partnerdata
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using Parnerdata for handlers");

			Enumeration<HandlerInfo> eHandler = metadata4partner.getHandlers().elements();
			while (eHandler.hasMoreElements()) {
				HandlerInfo hHandler = eHandler.nextElement();
				if (AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					// Create the AssertionConsumerService
					
					// RH, 20121228, n, For assertionconsumer service we allow to define alternate location
					String forcedLocation = hHandler.getLocation();	// returns null if not set

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found AssertionConsumer target in handler:" + getAssertionConsumerTarget());
//					if (getAssertionConsumerTarget() != null) {	// RH, 20121228, o
					if ( (getAssertionConsumerTarget() != null) || (forcedLocation != null) ) {	// RH, 20121228, n
						SAMLObjectBuilder<AssertionConsumerService> assResolutionSeviceBuilder = (SAMLObjectBuilder<AssertionConsumerService>) _oBuilderFactory
								.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
						AssertionConsumerService assResolutionService = assResolutionSeviceBuilder.buildObject();
						if (SAMLConstants.SAML2_POST_BINDING_URI.equals(hHandler.getBinding())) {
							assResolutionService.setBinding( SAMLConstants.SAML2_POST_BINDING_URI);
						} else {
							assResolutionService.setBinding(assertionConsumerServiceBindingConstantARTIFACT);
						}
						if (forcedLocation != null) {	// RH, 20121228, sn
							assResolutionService.setLocation(forcedLocation);
						} else {	// RH, 20121228, en
							assResolutionService.setLocation(getRedirectURL() + getAssertionConsumerTarget());
						}
						if (hHandler.getResponselocation() != null) {	// RH, 20121228, sn
							assResolutionService.setResponseLocation(hHandler.getResponselocation());
						}	// RH, 20121228, en
						if (hHandler.getIsdefault() != null) {
							assResolutionService.setIsDefault( hHandler.getIsdefault().booleanValue() );
						}
						if (hHandler.getIndex() != null) {
							assResolutionService.setIndex(hHandler.getIndex().intValue());
						}
						ssoDescriptor.getAssertionConsumerServices().add(assResolutionService);
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not set location, maybe 'location' missing in metadata or handler missing 'resourcegroup'");
					}
				}
				
				if (SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					String sBInding = null;
					String sLocation = null;
					// RH, 20120703, n, For singlelogout service we allow to define alternate location
					String forcedLocation = hHandler.getLocation();	// returns null if not set
					
					if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(hHandler.getBinding())) {
						// Create the SingleLogoutService HTTP, creates Request and Response
						_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloHttpLocation());
						sBInding = SAMLConstants.SAML2_REDIRECT_BINDING_URI;
						sLocation = getSpSloHttpLocation();
					}	else if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(hHandler.getBinding())) {
						// Create the SingleLogoutService SOAP, creates Request and Response
						_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloSoapLocation());
						sBInding = SAMLConstants.SAML2_SOAP11_BINDING_URI;
						sLocation = getSpSloSoapLocation();
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'binding' found in metadata for handler: " + hHandler.getType());
					}

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found SingleLogoutService target in handler:" + sLocation);
//					if (sBInding != null && sLocation != null) {	// RH, 20210128, o
					if (sLocation != null || forcedLocation != null) {	// RH, 20210128, n
						SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
								.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
						SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
						sloHttpService.setBinding(sBInding);
						if (forcedLocation != null) {	// RH, 20120703, sn
							sloHttpService.setLocation(forcedLocation);
						} else 	// RH, 20120703, en
							sloHttpService.setLocation(getRedirectURL() + sLocation);
						
						if (hHandler.getResponselocation() != null) {
							sloHttpService.setResponseLocation(hHandler.getResponselocation());
						} else {
								sloHttpService.setResponseLocation(getRedirectURL() + sLocation);
						}
						ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not set location, maybe 'location' missing in metadata or handler missing 'resourcegroup'");
					}
				}
				// RH, 20200220, sn
				///////////////////////////////////////////////////
				if (ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					String sBInding = null;
					String forcedLocation = hHandler.getLocation();	// returns null if not set

					_systemLogger.log(Level.INFO, MODULE, sMethod, "Found ArtifactResolutionService taget in handler: " + getSpArtifactResolverTarget());
					if ( (getSpArtifactResolverTarget() != null) || (forcedLocation != null) ) {
						SAMLObjectBuilder<ArtifactResolutionService> artResolutionSeviceBuilder = (SAMLObjectBuilder<ArtifactResolutionService>) _oBuilderFactory
								.getBuilder(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
						ArtifactResolutionService artResolutionService = artResolutionSeviceBuilder.buildObject();

						_systemLogger.log(Level.INFO, MODULE, sMethod, hHandler.getBinding());
						// Create the ArtifactResolutionServic SOAP
						if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(hHandler.getBinding())) {
							sBInding = hHandler.getBinding();
						}	else {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Binding set to the only allowed binding: " + SAMLConstants.SAML2_SOAP11_BINDING_URI);
							sBInding = SAMLConstants.SAML2_SOAP11_BINDING_URI;
						}
						artResolutionService.setBinding(sBInding);
					
						if (forcedLocation != null) {	// RH, 20121228, sn
							artResolutionService.setLocation(forcedLocation);
						} else {
							artResolutionService.setLocation(getRedirectURL() + getSpArtifactResolverTarget());
						}
						if (hHandler.getIsdefault() != null) {
							artResolutionService.setIsDefault( hHandler.getIsdefault().booleanValue() );
						}
						if (hHandler.getIndex() != null) {
							artResolutionService.setIndex(hHandler.getIndex().intValue());
						}
						ssoDescriptor.getArtifactResolutionServices().add(artResolutionService);
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not set location, maybe 'location' missing in metadata or handler missing 'resourcegroup'");
					}
				}
				//////////////////////////////////////////////
				// RH, 20200220, en

				// RH, 20160429, sn
				if (AttributeConsumingService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(hHandler.getType()) ) {
					if (hHandler.getIndex() == null) {	// should not happen, must be caught by initialization
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Index cannot be null in metadata " +  hHandler.getType());
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
					}
					SAMLObjectBuilder<AttributeConsumingService> attrConsumingServiceBuilder = (SAMLObjectBuilder<AttributeConsumingService>) _oBuilderFactory
							.getBuilder(AttributeConsumingService.DEFAULT_ELEMENT_NAME);
					AttributeConsumingService attrConsumingService = attrConsumingServiceBuilder.buildObject();
					attrConsumingService.setIndex(hHandler.getIndex());
					if (hHandler.getIsdefault() != null) {
						attrConsumingService.setIsDefault( hHandler.getIsdefault().booleanValue() );
					}
					// <ServiceName>
					for (Map<String, ?> service : hHandler.getServices()) {
						SAMLObjectBuilder<ServiceName> serviceNameBuilder = (SAMLObjectBuilder<ServiceName>) _oBuilderFactory
								.getBuilder(ServiceName.DEFAULT_ELEMENT_NAME);
						ServiceName serviceName = serviceNameBuilder.buildObject();
						// localized name
						serviceName.setName( new LocalizedString((String)service.get("name"), (String)service.get("lang")) );
						attrConsumingService.getNames().add(serviceName);
					}
					// <ServiceDescription> // optional	// not implemented yet
					// <RequestedAttribute>	
					for (Map<String, ?> attribute : hHandler.getAttributes()) {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Adding RequestedAttribute: "+ attribute);
						SAMLObjectBuilder<RequestedAttribute> requestedAttributeBuilder = (SAMLObjectBuilder<RequestedAttribute>) _oBuilderFactory
								.getBuilder(RequestedAttribute.DEFAULT_ELEMENT_NAME);
						RequestedAttribute requestedAttribute = requestedAttributeBuilder.buildObject();
						// name
						requestedAttribute.setName( (String)attribute.get("name") );
						Boolean isrequired = (Boolean)attribute.get("isrequired");
						// isRequired 	// optional
						if (isrequired != null) {
							requestedAttribute.setIsRequired(isrequired);
						}
						// <saml:AttributeValue> optional	// not implemented yet	// RH, 20201029, o
						// RH, 20201029, sn
						// attributevalue implementation for eID SAML4.4
						// only single valued attributevalue allowed
						String sValue = (String)attribute.get("value");
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found attribute value: " + sValue);
						if (sValue != null && sValue.length()>0 ) {	// Should not be null nor length = 0
							
							XSString theAttributeValue = null;
							XMLObjectBuilderFactory newbuilderFactory = Configuration.getBuilderFactory();
							XSStringBuilder newstringBuilder = (XSStringBuilder)newbuilderFactory.getBuilder(XSString.TYPE_NAME);

//							XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);
//							XSStringBuilder stringBuilder = (XSStringBuilder)_oBuilderFactory.getBuilder(XSString.TYPE_NAME);
							theAttributeValue = (XSString)newstringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
							theAttributeValue.setValue(sValue);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "theAttributeValue: " + theAttributeValue);
							requestedAttribute.getAttributeValues().add(theAttributeValue);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "requestedAttribute.getAttributeValues().size() : " + requestedAttribute.getAttributeValues().size());
						} else {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Empty attribute value found, skipping empty");
						}
						// RH, 20201029, en

						attrConsumingService.getRequestAttributes().add(requestedAttribute);
					}
					ssoDescriptor.getAttributeConsumingServices().add(attrConsumingService);
				}
				// RH, 20160429, en
			}
		} else {	// publish all handlers in config 			// RH, 20110113, en
		// Create the AssertionConsumerService
		_systemLogger.log(Level.INFO, MODULE, sMethod, getAssertionConsumerTarget());
		if (getAssertionConsumerTarget() != null) {
			SAMLObjectBuilder<AssertionConsumerService> assResolutionSeviceBuilder = (SAMLObjectBuilder<AssertionConsumerService>) _oBuilderFactory
					.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
			AssertionConsumerService assResolutionService = assResolutionSeviceBuilder.buildObject();
			assResolutionService.setBinding(assertionConsumerServiceBindingConstantARTIFACT);
			assResolutionService.setLocation(getRedirectURL() + getAssertionConsumerTarget());
			assResolutionService.setIsDefault(true);
			assResolutionService.setIndex(0);
			ssoDescriptor.getAssertionConsumerServices().add(assResolutionService);
		}

		// Create the SingleLogoutService HTTP, creates Request and Response
		_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloHttpLocation());
		if (getSpSloHttpLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloHttpServiceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloHttpService = sloHttpServiceBuilder.buildObject();
			sloHttpService.setBinding(singleLogoutServiceBindingConstantREDIRECT);
			sloHttpService.setLocation(getRedirectURL() + getSpSloHttpLocation());
			if (getSpSloHttpResponse() != null)
				sloHttpService.setResponseLocation(getRedirectURL() + getSpSloHttpResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloHttpService);
		}

		// Create the SingleLogoutService SOAP, creates Request and Response
		_systemLogger.log(Level.INFO, MODULE, sMethod, getSpSloSoapLocation());
		if (getSpSloSoapLocation() != null) {
			SAMLObjectBuilder<SingleLogoutService> sloSoaperviceBuilder = (SAMLObjectBuilder<SingleLogoutService>) _oBuilderFactory
					.getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME);
			SingleLogoutService sloSoapService = sloSoaperviceBuilder.buildObject();
			sloSoapService.setBinding(singleLogoutServiceBindingConstantSOAP);
			sloSoapService.setLocation(getRedirectURL() + getSpSloSoapLocation());
			if (getSpSloSoapResponse() != null)
				sloSoapService.setResponseLocation(getRedirectURL() + getSpSloSoapResponse());

			ssoDescriptor.getSingleLogoutServices().add(sloSoapService);
		}
		
		// RH, 20200220, sn
		// Create the SP ArtifactResolutionService SOAP
		_systemLogger.log(Level.INFO, MODULE, sMethod, getSpArtifactResolverTarget());
		if(getSpArtifactResolverTarget() != null) {
			SAMLObjectBuilder<ArtifactResolutionService> artResolutionSeviceBuilder = (SAMLObjectBuilder<ArtifactResolutionService>) _oBuilderFactory
					.getBuilder(ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
			ArtifactResolutionService artResolutionService = artResolutionSeviceBuilder.buildObject();
			artResolutionService.setBinding(artifactResolutionServiceBindingConstantSOAP);
			artResolutionService.setLocation(getRedirectURL() + getSpArtifactResolverTarget());
			artResolutionService.setIsDefault(true);
			artResolutionService.setIndex(0);
			ssoDescriptor.getArtifactResolutionServices().add(artResolutionService);
		}
		// RH, 20200220, en
		
		}		// end publish all handlers in config 
				
		// Publish Organization info
//		if (partnerData != null && partnerData.getMetadata4partner().getMetaorgname() != null) {	// If Organization present name is mandatory, so check name
		if (metadata4partner != null && metadata4partner.getMetaorgname() != null) {	// If Organization present name is mandatory, so check name
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting Organization info");

			SAMLObjectBuilder<Organization> organizationBuilder = (SAMLObjectBuilder<Organization>) _oBuilderFactory
			.getBuilder(Organization.DEFAULT_ELEMENT_NAME);
			Organization organization = organizationBuilder.buildObject();
			SAMLObjectBuilder<OrganizationName> organizationNameBuilder = (SAMLObjectBuilder<OrganizationName>) _oBuilderFactory
			.getBuilder(OrganizationName.DEFAULT_ELEMENT_NAME);
			OrganizationName organizationName = organizationNameBuilder.buildObject();
			organizationName.setName(new LocalizedString(metadata4partner.getMetaorgname(), metadata4partner.getMetaorgnamelang()));
			organization.getOrganizationNames().add(organizationName);

			
			if (metadata4partner.getMetaorgdisplname() != null) {
				SAMLObjectBuilder<OrganizationDisplayName> organizationDisplayNameBuilder = (SAMLObjectBuilder<OrganizationDisplayName>) _oBuilderFactory
				.getBuilder(OrganizationDisplayName.DEFAULT_ELEMENT_NAME);
				OrganizationDisplayName organizationDisplayName = organizationDisplayNameBuilder.buildObject();
				organizationDisplayName.setName(new LocalizedString(metadata4partner.getMetaorgdisplname(), metadata4partner.getMetaorgdisplnamelang()));
				organization.getDisplayNames().add(organizationDisplayName);
			}

			if (metadata4partner.getMetaorgurl() != null) {
				SAMLObjectBuilder<OrganizationURL> organizationURLBuilder = (SAMLObjectBuilder<OrganizationURL>) _oBuilderFactory
				.getBuilder(OrganizationURL.DEFAULT_ELEMENT_NAME);
				OrganizationURL organizationURL = organizationURLBuilder.buildObject();
				organizationURL.setURL(new LocalizedString(metadata4partner.getMetaorgurl(), metadata4partner.getMetaorgurllang()));
				organization.getURLs().add(organizationURL);
			}
		
			entityDescriptor.setOrganization(organization);
		}		// End Publish Organization info

		
		//	publish ContactPerson info
		
//		if (partnerData != null && partnerData.getMetadata4partner().getMetacontacttype() != null) {	// If ContactPerson present  ContactType  is mandatory so check  ContactType
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting ContactPerson info");
//		if (partnerData != null && partnerData.getMetadata4partner().getContactInfo().size() > 0) {	// Get ContactPerson(s) to publish from partnerdata
		if (metadata4partner != null && metadata4partner.getContactInfo().size() > 0) {	// Get ContactPerson(s) to publish from partnerdata
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Using ContactInfo for ContactInfo");

			Enumeration<ContactInfo> eContactInfos = metadata4partner.getContactInfo().elements();
			while (eContactInfos.hasMoreElements()) {
				ContactInfo eContactInfo = eContactInfos.nextElement();

				SAMLObjectBuilder<ContactPerson> contactBuilder = (SAMLObjectBuilder<ContactPerson>) _oBuilderFactory
				.getBuilder(ContactPerson.DEFAULT_ELEMENT_NAME);
				ContactPerson contact = contactBuilder.buildObject();

//			if (ContactPersonTypeEnumeration.ADMINISTRATIVE.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
//				contact.setType(ContactPersonTypeEnumeration.ADMINISTRATIVE);
//			} else	if (ContactPersonTypeEnumeration.BILLING.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
//				contact.setType(ContactPersonTypeEnumeration.BILLING);
//			} else if (ContactPersonTypeEnumeration.SUPPORT.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
//				contact.setType(ContactPersonTypeEnumeration.SUPPORT);
//			} else 	if (ContactPersonTypeEnumeration.TECHNICAL.toString().equalsIgnoreCase(partnerData.getMetadata4partner().getMetacontacttype())) {
//				contact.setType(ContactPersonTypeEnumeration.TECHNICAL);
//			}	else {
//				contact.setType(ContactPersonTypeEnumeration.OTHER);
//			}

				if (ContactPersonTypeEnumeration.ADMINISTRATIVE.toString().equalsIgnoreCase(eContactInfo.getMetacontacttype())) {
					contact.setType(ContactPersonTypeEnumeration.ADMINISTRATIVE);
				} else	if (ContactPersonTypeEnumeration.BILLING.toString().equalsIgnoreCase(eContactInfo.getMetacontacttype())) {
					contact.setType(ContactPersonTypeEnumeration.BILLING);
				} else if (ContactPersonTypeEnumeration.SUPPORT.toString().equalsIgnoreCase(eContactInfo.getMetacontacttype())) {
					contact.setType(ContactPersonTypeEnumeration.SUPPORT);
				} else 	if (ContactPersonTypeEnumeration.TECHNICAL.toString().equalsIgnoreCase(eContactInfo.getMetacontacttype())) {
					contact.setType(ContactPersonTypeEnumeration.TECHNICAL);
				}	else {
					contact.setType(ContactPersonTypeEnumeration.OTHER);
				}
			
//			if (partnerData.getMetadata4partner().getMetacontactname() != null) {
//				SAMLObjectBuilder<GivenName> givenNameBuilder = (SAMLObjectBuilder<GivenName>) _oBuilderFactory
//				.getBuilder(GivenName.DEFAULT_ELEMENT_NAME);
//				GivenName givenName = givenNameBuilder.buildObject();
//				givenName.setName(partnerData.getMetadata4partner().getMetacontactname());
//				contact.setGivenName(givenName);
//			}
//
//			if (partnerData.getMetadata4partner().getMetacontactsurname() != null) {
//				SAMLObjectBuilder<SurName> surNameBuilder = (SAMLObjectBuilder<SurName>) _oBuilderFactory
//				.getBuilder(SurName.DEFAULT_ELEMENT_NAME);
//				SurName surName = surNameBuilder.buildObject();
//				surName.setName(partnerData.getMetadata4partner().getMetacontactsurname());
//				contact.setSurName(surName);
//			}
//
//			if (partnerData.getMetadata4partner().getMetacontactemail() != null) {
//				SAMLObjectBuilder<EmailAddress> emailBuilder = (SAMLObjectBuilder<EmailAddress>) _oBuilderFactory
//				.getBuilder(EmailAddress.DEFAULT_ELEMENT_NAME);
//				EmailAddress email = emailBuilder.buildObject();
//				email.setAddress(partnerData.getMetadata4partner().getMetacontactemail());
//				contact.getEmailAddresses().add(email);
//			}
//			
//			if (partnerData.getMetadata4partner().getMetacontactephone() != null) {
//				SAMLObjectBuilder<TelephoneNumber> phonelBuilder = (SAMLObjectBuilder<TelephoneNumber>) _oBuilderFactory
//				.getBuilder(TelephoneNumber.DEFAULT_ELEMENT_NAME);
//				TelephoneNumber phone = phonelBuilder.buildObject();
//				phone.setNumber(partnerData.getMetadata4partner().getMetacontactephone());
//				contact.getTelephoneNumbers().add(phone);
//			}
			
				if (eContactInfo.getMetacontactname() != null) {
					SAMLObjectBuilder<GivenName> givenNameBuilder = (SAMLObjectBuilder<GivenName>) _oBuilderFactory
					.getBuilder(GivenName.DEFAULT_ELEMENT_NAME);
					GivenName givenName = givenNameBuilder.buildObject();
					givenName.setName(eContactInfo.getMetacontactname());
					contact.setGivenName(givenName);
				}
	
				if (eContactInfo.getMetacontactsurname() != null) {
					SAMLObjectBuilder<SurName> surNameBuilder = (SAMLObjectBuilder<SurName>) _oBuilderFactory
					.getBuilder(SurName.DEFAULT_ELEMENT_NAME);
					SurName surName = surNameBuilder.buildObject();
					surName.setName(eContactInfo.getMetacontactsurname());
					contact.setSurName(surName);
				}
	
				if (eContactInfo.getMetacontactemail() != null) {
					SAMLObjectBuilder<EmailAddress> emailBuilder = (SAMLObjectBuilder<EmailAddress>) _oBuilderFactory
					.getBuilder(EmailAddress.DEFAULT_ELEMENT_NAME);
					EmailAddress email = emailBuilder.buildObject();
					email.setAddress(eContactInfo.getMetacontactemail());
					contact.getEmailAddresses().add(email);
				}
				
				if (eContactInfo.getMetacontactephone() != null) {
					SAMLObjectBuilder<TelephoneNumber> phonelBuilder = (SAMLObjectBuilder<TelephoneNumber>) _oBuilderFactory
					.getBuilder(TelephoneNumber.DEFAULT_ELEMENT_NAME);
					TelephoneNumber phone = phonelBuilder.buildObject();
					phone.setNumber(eContactInfo.getMetacontactephone());
					contact.getTelephoneNumbers().add(phone);
				}
				entityDescriptor.getContactPersons().add(contact);
			}
		}		//	End publish ContactPerson info

		
		// Create final EntityDescriptor
		ssoDescriptor.setWantAssertionsSigned(true);
		ssoDescriptor.setAuthnRequestsSigned(true);	// RH, 20120727, n. Actually we always sign the request. Just never told so
		
		if ( includesigningcertificate || includesigningkeyname || addkeyname /* backwards compatibility */ )
			ssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		if ( includeencryptioncertificate || includeencryptionkeyname )
			ssoDescriptor.getKeyDescriptors().add(keyDescriptorEncryption);	// RH, 20160223, n
		
		ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		entityDescriptor.getRoleDescriptors().add(ssoDescriptor);

		// RH, 20180918, sn
		PartnerData.Crypto specificCrypto = null;
//		if (partnerData != null) {
		if (crypto != null) {
			specificCrypto = crypto;	// might be null
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signing metadata with specific partner private key");
			// RH, 20180920, en
		}
		// RH, 20180918, en

//		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor);		// RH, 20110113, o
		// RH, 20110113, sn
		if (sign) {	// RH, 20210421, n
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Signing entityDescriptor");
//		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor,  usesha256 ? "sha256": "sha1",
//						addkeyname, addcertificate);	// RH, 20180918, o
		entityDescriptor = (EntityDescriptor) SamlTools.signSamlObject(entityDescriptor,  usesha256 ? "sha256": "sha1",
				addkeyname, addcertificate, specificCrypto);	// RH, 20180918, n
		}	// RH, 20210421, n
		// RH, 20110113, en

		// The Session Sync descriptor (PDPDescriptor?) would go here
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityDescriptor done");
		return entityDescriptor;
	}
}
