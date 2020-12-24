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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.PartnerData.HandlerInfo;
import org.aselect.server.request.handler.xsaml20.PartnerData.Metadata4Partner;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.opensaml.saml2.metadata.AttributeConsumingService;

/**
 * class MetaDataManagerIdp, this class is reading the aselect xml file. The aselect xml file contains the metadata xml
 * file information, this is the the location of the metadata xml file, this can be a pathname or URL
 */
/**
 * @author bauke
 *
 */
public class MetaDataManagerSp extends AbstractMetaDataManager
{
	private static MetaDataManagerSp metaDataManager = null;
	private final String sFederationIdpKeyword = "federation-idp";

	/**
	 * Private constructor --> singleton.
	 */
	private MetaDataManagerSp() {
	}

	/**
	 * Singleton.
	 * 
	 * @return the handle
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static MetaDataManagerSp getHandle()
	throws ASelectException
	{
		if (metaDataManager == null) {
			metaDataManager = new MetaDataManagerSp();
			metaDataManager.init();
		}
		return metaDataManager;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager#getMyRole()
	 */
	public String getMyRole()
	{
		return "SP";
	}
	
	/**
	 * Read Aselect.xml file This file contains the location of the metadata xml file
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	@Override
	protected void init()
	throws ASelectException
	{
		String sMethod = "init";

		super.init();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role=" + getMyRole() + " id=" + sFederationIdpKeyword);
		initializeMetaDataHandling();
	}

	/**
	 * Process an IdP section for it's metadata
	 * @param idpSection - the <resource> section
	 * @throws ASelectConfigException
	 * @throws ASelectException
	 */
//	public void processResourceSection(Object idpSection)	// RH, 20190321, o
	public void processResourceSection(String sResourceGroup, Object idpSection)	// RH, 20190321, n
	throws ASelectConfigException, ASelectException
	{
		String sMethod = "sp.processResourceSection";
		// Look for "id" "url" and "session_sync"
		String sId = _configManager.getParam(idpSection, "id");
		PartnerData idpData = new PartnerData(sId);
		
		try {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Resource id="+sId);
			String metadataUrl = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "url", true);
			if (metadataUrl != null)
				idpData.setMetadataUrl(metadataUrl);
			String specialSettings = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "special_settings", false);
			if (specialSettings != null)
				idpData.setSpecialSettings(specialSettings);
			String myIssuer = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "local_issuer", false);
			if (myIssuer != null)
				idpData.setLocalIssuer(myIssuer);
			String sRedirectSyncTime = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "redirect_sync_time", false);
			if (sRedirectSyncTime != null)
				idpData.setRedirectSyncTime(sRedirectSyncTime);
			String sRedirectPostForm = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "redirect_post_form", false);
			if (sRedirectPostForm != null)
				idpData.setRedirectPostForm(sRedirectPostForm);
			
			String sSessionSync = null;
			if (sId.equals("metadata")) { // 20091030: backward compatibility
				// Get from "saml20_sp_session_sync" handler
				Object oRequestsSection = _configManager.getSection(null, "requests");
				Object oHandlersSection = _configManager.getSection(oRequestsSection, "handlers");
				Object oHandler = _configManager.getSection(oHandlersSection, "handler", "id=saml20_sp_session_sync");
				sSessionSync = ASelectConfigManager.getSimpleParam(oHandler, "federation_url", true);
			}
			else {
				sSessionSync = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "session_sync", false);
			}
			if (sSessionSync != null) {
				idpData.setSessionSyncUrl(sSessionSync);
			}
			String destination = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "destination", false);
			if (destination != null)
				idpData.setDestination(destination);
			
			String assertionconsumerserviceindex = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "serviceindex", false);  // "assertionconsumerserviceindex", false);
			if (assertionconsumerserviceindex != null)
				idpData.setAssertionConsumerServiceindex(assertionconsumerserviceindex);
			String attributeconsumerserviceindex = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "attributeconsumerserviceindex", false);
			if (attributeconsumerserviceindex != null)
				idpData.setAttributeConsumerServiceindex(attributeconsumerserviceindex);
			String federationurl = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "federationurl", false);
			if (federationurl != null)
				idpData.setFederationurl(federationurl);

			String addkeyname = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "addkeyname", false);
			if (addkeyname != null)
				idpData.setAddkeyname(addkeyname);
			
			String addcertificate = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "addcertificate", false);
			if (addcertificate != null)
				idpData.setAddcertificate(addcertificate);

			String logoutSupport = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "logoutsupport", false);
			if (logoutSupport != null)
				idpData.setLogoutSupport(logoutSupport);

			// RH, 20180327, sn
			String suppressscoping = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "suppressscoping", false);
			if (suppressscoping != null)
				idpData.setSuppressscoping(suppressscoping);
			// RH, 20180327, en

			// RH, 20190412, sn
			String suppressforcedauthn = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "suppressforcedauthn", false);
			if (suppressforcedauthn != null)
				idpData.setSuppresssforcedauthn(suppressforcedauthn);
			// RH, 20190412, en

			// RH, 20200121, sn
			String sAssertionIssierPattern = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "assertionissuerpattern", false);
			if (sAssertionIssierPattern != null) {
				try {
					Pattern specificIssuer = Pattern.compile(sAssertionIssierPattern);
					idpData.setAssertionIssuerPattern(specificIssuer);
				} catch (PatternSyntaxException pex) {
					throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR, pex);
				}

			}
			// RH, 20200121, en
			
			// RH, 20200213, sn
			String sNameIDIssierPattern = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "nameidissuerpattern", false);
			if (sNameIDIssierPattern != null) {
				try {
					Pattern specificIssuer = Pattern.compile(sNameIDIssierPattern);
					idpData.setNameIDIssuerPattern(specificIssuer);
				} catch (PatternSyntaxException pex) {
					throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR, pex);
				}
			}
			// RH, 20200213, en

			// RH, 20181005, sn
			String idpentryproviderid = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "authnrequest_scoping", "authnrequest_providerid", false);
			if (idpentryproviderid != null)
				idpData.setIdpentryproviderid(idpentryproviderid);
			// RH, 20181005, en

			// RH, 20180810, sn
			HashMap<String, String> _htSamlLevels = new HashMap<String, String>(); // contains level -> urn
			_htSamlLevels = ASelectConfigManager.getTableFromConfig(idpSection,  _htSamlLevels, "authentication_method",
					"security", "level",/*->*/"uri", false/* mandatory */, false/* unique values */);
			if (_htSamlLevels != null) {
				HashMap<String, String> _htLoaLevels = new HashMap<String, String>(); // contains level -> urn
				_htLoaLevels = ASelectConfigManager.getTableFromConfig(idpSection,  _htLoaLevels, "authentication_method",
						"security", "level",/*->*/"loauri", false/* mandatory */, false/* unique values */);
				idpData.setSecurityLevels(SecurityLevel.getCustomLevels(_htSamlLevels, _htLoaLevels));
			}
			// RH, 20180810, sn
	
			// RH, 20180917, sn
			/////////////////////////////////////////////////
			// load the specific crypto info

			String workingDir = _configManager.getWorkingdir();	// RH, 20181102, n

			String keystoreName = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "keystore", "name", false);
			if (keystoreName != null) {
				 String keystorePw = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "keystore", "password", false);
				 String keystoreAlias = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "keystore", "alias", false);
//				 String workingDir = _configManager.getWorkingdir();	// RH, 20181102, o
				 try {
					 idpData.loadSpecificCrypto(workingDir, keystoreName, keystoreAlias, keystorePw);
				 } catch (ASelectException e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not load partner private key from: "+keystoreName+", alias="+keystoreAlias);
						throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
				 }
			}	// maybe load defaultprivatekey for every partner without keystorelocation ?
				// Would make more uniform signing calls
			// RH, 20180917, sn

			// RH, 20181102, sn
			String id_keyfile = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "id_keyfile", false);
			idpData.setId_keylocation(workingDir, id_keyfile);
			String pd_keyfile = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pd_keyfile", false);
			idpData.setPd_keylocation(workingDir, pd_keyfile);
			String pc_keyfile = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pc_keyfile", false);
			idpData.setPc_keylocation(workingDir, pc_keyfile);
			String i_point = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pi_point", false);
			idpData.setI_point(i_point);
			// RH, 20190314, sn
			String p_point = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pp_point", false);
			if (p_point == null) {	// backwards compatibility, pd_point is not a well chosen name, should be pp_point
				p_point = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pd_point", false);
			}
			// RH, 20190314, en
			// RH, 20190314, sn
//			String p_point = Utils.getParamFromSection(_configManager, _systemLogger, idpSection, "polymorf", "pd_point", false);// RH, 20190314, o
			idpData.setP_point(p_point);
			// RH, 20181102, en
			
			// Set specific metadata for this partner
			Object metadataSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "metadata", false);
			Metadata4Partner metadata4partner = idpData.getMetadata4partner();
			loadPartnerMetadata(metadataSection, sId, idpData, specialSettings, metadata4partner);
			// End Set specific metadata for this partner

			// start load metadata_dvs
			Object metadataDVsSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "metadata_dvs", false);
			if (metadataDVsSection != null) {
				Object metadataDVSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataDVsSection, "metadata", false);
				if (metadataDVSection != null) {
					while (metadataDVSection != null) {
						String entityID =  Utils.getSimpleParam(_configManager, _systemLogger, metadataDVSection, "id", true);
						Metadata4Partner metadata4dv = idpData.getMetadataDV(entityID);
						loadPartnerMetadata(metadataDVSection, entityID, idpData, specialSettings, metadata4dv);
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Loaded metadataDV for : "+ entityID);
						metadataDVSection = _configManager.getNextSection(metadataDVSection);
					}
				} else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "metadata section missing for metadata_dvs in resource: "+ sId);
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
			} else {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "no metadata_dvs section for resource: "+ sId + ", continuing");
			}
			// end load metadata_dvs
			

			//  Start Set PEPS/STORK extensions data for this partner
			Object extensionsdataSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "storkextensions", false);
			if (extensionsdataSection != null) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "storkextensionsdataSection section found for: "+ sId);

				String extensions_qualityauthenticationassurancelevel = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "qualityauthenticationassurancelevel", false);
				if (extensions_qualityauthenticationassurancelevel != null) { // if not null, value will be used, otherwise requested auth level will be used
					try {	// if not null, must be number, should be between 1 and 4 inclusive
							idpData.getExtensionsdata4partner().setQualityAuthenticationAssuranceLevel(Integer.parseInt(extensions_qualityauthenticationassurancelevel));
					} catch (NumberFormatException nfe) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "if provided, qualityauthenticationassurancelevel must be a number for resource: "+ sId);
						throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR, nfe);
					}
				}

				String extensions_spsector = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "spsector", false);
				if (extensions_spsector != null) {	// length should be between 1 and 20 inclusive
					idpData.getExtensionsdata4partner().setSpSector(extensions_spsector);
				}				
				String extensions_spinstitution = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "spinstitution", false);
				if (extensions_spinstitution != null) {	// not in STORK specs
					idpData.getExtensionsdata4partner().setSpInstitution(extensions_spinstitution);
				}				
				String extensions_spapplication = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "spapplication", false);
				if (extensions_spapplication != null) {	// length should be between 1 and 100 inclusive
					idpData.getExtensionsdata4partner().setSpApplication(extensions_spapplication);
				}				
				String extensions_spcountry = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "spcountry", false);
				if (extensions_spcountry != null) {	// should be xs:token "[A-Z{2}"
					idpData.getExtensionsdata4partner().setSpCountry(extensions_spcountry);
				}				
				
				String extensions_eidsectorshare = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "eidsectorshare", false);
				if (extensions_eidsectorshare != null) {	// should be true or false
					idpData.getExtensionsdata4partner().seteIDSectorShare(Boolean.parseBoolean(extensions_eidsectorshare));
				}				
				
				String extensions_eidcrosssectorshare = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "eidcrosssectorshare", false);
				if (extensions_eidcrosssectorshare != null) {	// should be true or false
					idpData.getExtensionsdata4partner().seteIDCrossSectorShare(Boolean.parseBoolean(extensions_eidcrosssectorshare));
				}				
				
				String extensions_eidcrossbordershare = Utils.getSimpleParam(_configManager, _systemLogger, extensionsdataSection, "eidcrossbordershare", false);
				if (extensions_eidcrossbordershare != null) {	// should be true or false
					idpData.getExtensionsdata4partner().seteIDCrossBorderShare(Boolean.parseBoolean(extensions_eidcrossbordershare));
				}				
				
				Object extensions_requestedattributes = Utils.getSimpleSection(_configManager, _systemLogger, extensionsdataSection, "requestedattributes", false);
				if (extensions_requestedattributes != null) {
					Object extensions_requestedattribute = Utils.getSimpleSection(_configManager, _systemLogger, extensions_requestedattributes, "requestedattribute", false);
					if (extensions_requestedattribute != null) {
						ArrayList <Map<String, Object>> reqAttributes = new  ArrayList <Map<String, Object>>();
						while (extensions_requestedattribute != null) {
							Map<String, Object> reqAttr = new Hashtable<String, Object>();
							String  extensions_requestedattribute_name = Utils.getSimpleParam(_configManager, _systemLogger, extensions_requestedattribute, "name", true);
							reqAttr.put("name", extensions_requestedattribute_name);
							String extensions_requestedattribute_nameformat = Utils.getSimpleParam(_configManager, _systemLogger, extensions_requestedattribute, "nameformat", false);
							if ( extensions_requestedattribute_nameformat == null ) {
								_systemLogger.log(Level.CONFIG, MODULE, sMethod, "nameformat not provided, using default" );
								extensions_requestedattribute_nameformat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";	// set a reasonable default
							}
							reqAttr.put("nameformat", extensions_requestedattribute_nameformat);
							String extensions_requestedattribute_isrequired = Utils.getSimpleParam(_configManager, _systemLogger, extensions_requestedattribute, "isrequired", false);
							Boolean bextensions_requestedattribute_isrequired = null;
							if (extensions_requestedattribute_isrequired != null) {
								bextensions_requestedattribute_isrequired = Boolean.parseBoolean(extensions_requestedattribute_isrequired);
							}
							reqAttr.put("isrequired", bextensions_requestedattribute_isrequired);
							// attributevalues not implemented (yet)
							
							reqAttributes.add(reqAttr);
							extensions_requestedattribute = _configManager.getNextSection(extensions_requestedattribute);

						}
						idpData.getExtensionsdata4partner().setRequestedAttributes(reqAttributes);
					} else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "At least one requested attribute needed for resource: "+ sId);
						throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
					}
				
				} else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "requestedattributes section missing for resource: "+ sId);
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Using extensionsdataSection : "+ idpData.getExtensionsdata4partner().toString());

			} else {
//				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No extensionsdataSection section found for: "+ sId);	// RH, 20200629, o
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No storkextensionsdataSection section found for: "+ sId);	// RH, 20200629, n
			}
			//  End Set PEPS/STORK extension data for this partner

			// RH, 20200629, sn
			//  Start Set eID extensions data for this partner
			Object eIDextensionsdataSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "eidextensions", false);
			if (eIDextensionsdataSection != null) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "eidextensionsdataSection section found for: "+ sId);
				Object extensions_attributes = Utils.getSimpleSection(_configManager, _systemLogger, eIDextensionsdataSection, "attributes", false);
				if (extensions_attributes != null) {
					Map<String, String> attrs = new HashMap<String, String>();
					Object extensions_attribute = Utils.getSimpleSection(_configManager, _systemLogger, extensions_attributes, "attribute", false);
					if (extensions_attribute != null) {
						while (extensions_attribute != null) {
							String  extensions_attribute_name = Utils.getSimpleParam(_configManager, _systemLogger, extensions_attribute, "name", true);
							String  extensions_attribute_value = Utils.getSimpleParam(_configManager, _systemLogger, extensions_attribute, "value", true);
							attrs.put(extensions_attribute_name, extensions_attribute_value);
							extensions_attribute = _configManager.getNextSection(extensions_attribute);
						}
					} else {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "At least one attribute needed for resource: "+ sId);
						throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
					}
					idpData.getExtensionsdata4partner().seteIDAttributes(attrs);
				} else {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, "attributes section missing for resource: "+ sId);
					throw new ASelectConfigException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Using extensionsdataSection : "+ idpData.getExtensionsdata4partner().toString());


			} else {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No eidextensionsdataSection section found for: "+ sId);
			}
			//  End Set eID extension data for this partner
			// RH, 20200629, en

			
			// Set specific testdata for this partner
			Object testdataSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "testdata", false);
			if (testdataSection != null) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "testdate section found for: "+ sId);
				// signon
				String tst_issueinstant = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "issueinstant", false);
				if (tst_issueinstant != null)
					idpData.getTestdata4partner().setIssueInstant(tst_issueinstant);
				
				String tst_issuer = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "issuer", false);
				if (tst_issuer != null)
					idpData.getTestdata4partner().setIssuer(tst_issuer);
				
				String tst_authncontextclassrefuri = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "authncontextclassrefuri", false);
				if (tst_authncontextclassrefuri != null)
					idpData.getTestdata4partner().setAuthnContextClassRefURI(tst_authncontextclassrefuri);

				String tst_authncontextcomparisontypeenumeration = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "authncontextcomparisontypeenumeration", false);
				if (tst_authncontextcomparisontypeenumeration != null)
					idpData.getTestdata4partner().setAuthnContextComparisonTypeEnumeration(tst_authncontextcomparisontypeenumeration);
				
				String tst_forceauthn = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "forceauthn", false);
				if (tst_forceauthn != null)
					idpData.getTestdata4partner().setForceAuthn(tst_forceauthn);
				
				String tst_providername = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "providername", false);
				if (tst_providername != null)
					idpData.getTestdata4partner().setProviderName(tst_providername);

				String tst_assertionconsumerserviceindex = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "assertionconsumerserviceindex", false);
				if (tst_assertionconsumerserviceindex != null)
					idpData.getTestdata4partner().setAssertionConsumerServiceIndex(tst_assertionconsumerserviceindex);
				
				String tst_assertionconsumerserviceurl = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "assertionconsumerserviceurl", false);
				if (tst_assertionconsumerserviceurl != null)
					idpData.getTestdata4partner().setAssertionConsumerServiceURL(tst_assertionconsumerserviceurl);

				String tst_destination = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "destination", false);
				if (tst_destination != null)
					idpData.getTestdata4partner().setDestination(tst_destination);

				// logout
				String tst_issueinstant_logout = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "issueinstant_logout", false);
				if (tst_issueinstant_logout != null)
					idpData.getTestdata4partner().setIssueInstantLogout(tst_issueinstant_logout);

				String tst_issuer_logout = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "issuer_logout", false);
				if (tst_issuer_logout != null)
					idpData.getTestdata4partner().setIssuerLogout(tst_issuer_logout);

				String tst_destination_logout = Utils.getSimpleParam(_configManager, _systemLogger, testdataSection, "destination_logout", false);
				if (tst_destination_logout != null)
					idpData.getTestdata4partner().setDestinationLogout(tst_destination_logout);

				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Using testdata : "+ idpData.getTestdata4partner().toString());

			} else {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No testdata section found for: "+ sId);
			}
			
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + "<>" + idpData);
//			storeAllIdPData.put(sId, idpData);	// RH, 20190321, o
			storeAllIdPData.put(new AbstractMap.SimpleEntry<>(sResourceGroup ,sId), idpData);	// RH, 20190321, n
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Metadata retrieval failed", e);
			// maybe throw more serious error here
		}
	}

	/**
	 * @param metadataSection
	 * @param sId
	 * @param idpData
	 * @param specialSettings
	 * @param sMethod
	 * @throws ASelectConfigException
	 * @throws ASelectException
	 */
	protected void loadPartnerMetadata(Object metadataSection, String sId, PartnerData idpData,
			String specialSettings, Metadata4Partner metadata) throws ASelectConfigException, ASelectException {
		
		String sMethod = "loadPartnerMetadata";

		if (metadataSection != null) {
			// get handlers to publish
			Object metaHandler = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "handler", false);
			if (metaHandler == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No handlers found in metadata section for: "+ sId);
			}
			while (metaHandler != null) {
				String metahandlertype = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "type", false);
				// RM_72_01
				String metahandlerbinding = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "binding", false);
				// RM_72_02
				String metahandlerisdefault = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "isdefault", false);
				Boolean bMetahandlerisdefault = null;
				if (metahandlerisdefault != null) {
					metahandlerisdefault = metahandlerisdefault.toLowerCase();
					bMetahandlerisdefault = new Boolean(metahandlerisdefault);
				}
				String metahandlerindex = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "index", false);
				Integer iMetahandlerindex = null;
				if (metahandlerindex != null) {
					iMetahandlerindex = new Integer(metahandlerindex);
				}
				
				// RH, 20120703, sn, Added optional location
				String metahandlerlocation = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "location", false);
				// RH, 20120703, en

				String metahandlerresponselocation = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "responselocation", false);
				
				// RH, 20160419, sn, get optional attributeconsumingservice
				HandlerInfo handerInfo = idpData.new HandlerInfo(metahandlertype,metahandlerbinding,  bMetahandlerisdefault,  iMetahandlerindex, metahandlerresponselocation, metahandlerlocation);
				if (AttributeConsumingService.DEFAULT_ELEMENT_LOCAL_NAME.equalsIgnoreCase(metahandlertype)) {
					Object servicesSection = Utils.getSimpleSection(_configManager, _systemLogger, metaHandler, "services", true);
					while (servicesSection != null) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "services section section found for: "+ sId);

						Object serviceSection = Utils.getSimpleSection(_configManager, _systemLogger, servicesSection, "service", true);
						while (serviceSection != null) {
									Map<String, Object> reqService = new Hashtable<String, Object>();
									String  attributeconsumingservice_service_name = Utils.getSimpleParam(_configManager, _systemLogger, serviceSection, "name", true);
									reqService.put("name", attributeconsumingservice_service_name);
									String  attributeconsumingservice_service_lang = Utils.getSimpleParam(_configManager, _systemLogger, serviceSection, "lang", true);
									reqService.put("lang", attributeconsumingservice_service_lang);

									handerInfo.getServices().add(reqService);
									serviceSection = _configManager.getNextSection(serviceSection);
						}
						servicesSection = _configManager.getNextSection(servicesSection);
					}

					Object attributesSection = Utils.getSimpleSection(_configManager, _systemLogger, metaHandler, "attributes", true);
					while (attributesSection != null) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "attributes section section found for: "+ sId);

						Object attributeSection = Utils.getSimpleSection(_configManager, _systemLogger, attributesSection, "attribute", true);
						while (attributeSection != null) {
									Map<String, Object> reqAttr = new Hashtable<String, Object>();
									String  attributeconsumingservice_attribute_name = Utils.getSimpleParam(_configManager, _systemLogger, attributeSection, "name", true);
									reqAttr.put("name", attributeconsumingservice_attribute_name);
									String  attributeconsumingservice_attribute_required = Utils.getSimpleParam(_configManager, _systemLogger, attributeSection, "isrequired", false);
									if (attributeconsumingservice_attribute_required != null) {
										reqAttr.put("isrequired", Boolean.valueOf(attributeconsumingservice_attribute_required));
									}

									// attributevalues not implemented, RH, 20201029, o
									// RH, 20201029, sn
									// attributevalue implementation for eID SAML4.4
									// only single valued attributevalue allowed
									String  attributeconsumingservice_attribute_value = Utils.getSimpleParam(_configManager, _systemLogger, attributeSection, "value", false);
									if (attributeconsumingservice_attribute_value != null && attributeconsumingservice_attribute_value.length()>0 ) {	// Should not be null nor length = 0
										reqAttr.put("value", attributeconsumingservice_attribute_value);
									} else {
										_systemLogger.log(Level.FINEST, MODULE, sMethod, "Empty attribute value found, skipping empty value for key: "+ attributeconsumingservice_attribute_name);
									}
									// RH, 20201029, en
									handerInfo.getAttributes().add(reqAttr);
						
									attributeSection = _configManager.getNextSection(attributeSection);

						}
						attributesSection = _configManager.getNextSection(attributesSection);
					}
				}
				// RH, 20160419, en
				
//					idpData.getMetadata4partner().getHandlers().add(idpData.new HandlerInfo(metahandlertype,metahandlerbinding,  bMetahandlerisdefault,  iMetahandlerindex, metahandlerresponselocation, metahandlerlocation) );	// RH, 20160428, o
				metadata.getHandlers().add( handerInfo );	// RH, 20160428, n
				metaHandler = _configManager.getNextSection(metaHandler);
			}

			// RH, 20140320, sn, get optional entitydescriptorextension
			Object extensionSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "entitydescriptorextension", false);
			if (extensionSection != null) {
				Object metaNamespace = Utils.getSimpleSection(_configManager, _systemLogger, extensionSection, "namespace", false);
				if (metaNamespace == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No namespace element found in entitydescriptorextension section for: "+ sId);
				}
				while (metaNamespace != null) {
					String metaNamespacePrefix = Utils.getSimpleParam(_configManager, _systemLogger, metaNamespace, "prefix", false);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "prefix found in entitydescriptorextension section: "+ metaNamespacePrefix);
					String metaNamespaceUri = Utils.getSimpleParam(_configManager, _systemLogger, metaNamespace, "uri", false);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "uri found in entitydescriptorextension section: "+ metaNamespaceUri);
					if ( metaNamespacePrefix != null && metaNamespaceUri != null ) {
						Object metaAttribute = Utils.getSimpleSection(_configManager, _systemLogger, metaNamespace, "attribute", false);
						if (metaAttribute == null) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "No attribute element found in entitydescriptorextension section for uri: "+ metaNamespaceUri);
						}
						Hashtable<String, String> attributes = new Hashtable<String, String>();
						while (metaAttribute != null) {
							String metaAttributeValue = Utils.getSimpleParam(_configManager, _systemLogger, metaAttribute, "value", false);
							String metaAttributeLocalPart = Utils.getSimpleParam(_configManager, _systemLogger, metaAttribute, "localpart", false);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "localpart found in attribute section: "+ metaAttributeLocalPart + " with value: " + metaAttributeValue);
							if ( metaAttributeValue != null && metaAttributeLocalPart != null) {
								attributes.put(metaAttributeLocalPart, metaAttributeValue);
							} else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "one of localpart or value == null section with uri: "+ metaNamespaceUri);
							}
							metaAttribute = _configManager.getNextSection(metaAttribute);
						}
						metadata.getNamespaceInfo().add(idpData.new NamespaceInfo(metaNamespacePrefix, metaNamespaceUri, attributes));
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "one of prefix or uri == null namespace section");
					}
					metaNamespace = _configManager.getNextSection(metaNamespace);
				}
			} else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No entitydescriptorextension found in metadata section for: "+ sId);
			}
			// RH, 20140320, en
			
			
			
			
			String metaaddkeyname = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "addkeyname", false);
			if (metaaddkeyname != null)
				metadata.setAddkeyname(metaaddkeyname);

			String metaaddcertificate = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "addcertificate", false);
			if (metaaddcertificate != null)
				metadata.setAddcertificate(metaaddcertificate);
			// RH, 20160225, sn
			Object keyDescriptorSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "keydescriptor", false);
			if (keyDescriptorSection == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No keydescriptorsection element found in metadata section for: "+ sId + ", using defaults");
			}
			while (keyDescriptorSection != null) {
				String usage = Utils.getSimpleParam(_configManager, _systemLogger, keyDescriptorSection, "usage", false);
				if ("signing".equalsIgnoreCase(usage) ) {
					String includesigningcertificate = Utils.getParamFromSection(_configManager, _systemLogger, keyDescriptorSection, "keyinfo", "includecertificate", false);
					if (includesigningcertificate != null)
						metadata.setIncludesigningcertificate(includesigningcertificate);
					String includesigningkeyname = Utils.getParamFromSection(_configManager, _systemLogger, keyDescriptorSection, "keyinfo", "includekeyname", false);
					if (includesigningkeyname != null)
						metadata.setIncludesigningkeyname(includesigningkeyname);
				}
				if ("encryption".equalsIgnoreCase(usage) ) {
					String includeencryptioncertificate = Utils.getParamFromSection(_configManager, _systemLogger, keyDescriptorSection, "keyinfo", "includecertificate", false);
					if (includeencryptioncertificate != null)
						metadata.setIncludeencryptioncertificate(includeencryptioncertificate);
					String includeencryptionkeyname = Utils.getParamFromSection(_configManager, _systemLogger, keyDescriptorSection, "keyinfo", "includekeyname", false);
					if (includeencryptionkeyname != null)
						metadata.setIncludeencryptionkeyname(includeencryptionkeyname);
				}
				keyDescriptorSection = _configManager.getNextSection(keyDescriptorSection);
			}
			// RH, 20160225, en

			String metaspecialSettings = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "special_settings", false);
			if (metaspecialSettings != null)
				metadata.setSpecialsettings(specialSettings);

			Object orgSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "organization", false);
			if (orgSection != null) {
				String metaorgname = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationname", false);
				String metaorgnamelang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationname", "lang", false);
				String metaorgdisplname = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationdisplayname", false);
				String metaorgdisplnamelang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationdisplayname", "lang", false);
				String metaorgurl = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationurl", false);
				String metaorgurllang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationurl", "lang", false);
				
				metadata.setOrganizationInfo(metaorgname, metaorgnamelang, metaorgdisplname, metaorgdisplnamelang, metaorgurl, metaorgurllang);
			} else {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No organization found in metadata section for: "+ sId);
			}

			Object contactSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "contactperson", false);
//				if (contactSection != null) {
			if (contactSection == null) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No contactperson found in metadata section for: "+ sId);
			}
			while (contactSection != null) {
				String metacontacttype = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "contacttype", false);
				if (metacontacttype == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No contacttype found in metadata section for: "+ sId + ", contacttype is mandatory if contactperson present !");
				}
				String metacontactname = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "givenname", false);
				String metacontactsurname = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "surname", false);
				String metacontactemail = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "emailaddress", false);
				String metacontactephone = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "telephonenumber", false);

//					idpData.getMetadata4partner().setContactInfo(metacontacttype, metacontactname, metacontactsurname, metacontactemail, metacontactephone);
				metadata.addContactInfo(idpData.new ContactInfo(metacontacttype, metacontactname, metacontactsurname, metacontactemail, metacontactephone));
				
				contactSection = _configManager.getNextSection(contactSection);
			}	
//				} else {
//					_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No contactperson found in metadata section for: "+ sId);
//				}
		} else {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No metadata section found for: "+ sId);
		}
	}
	
	public void logIdPs()
	{
		_systemLogger.log(Level.INFO, MODULE, "logIdPs", "storeAllIdPData="+storeAllIdPData);
	}
}

