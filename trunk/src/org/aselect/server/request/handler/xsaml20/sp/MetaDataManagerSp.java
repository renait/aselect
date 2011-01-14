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

import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.PartnerData.HandlerInfo;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;

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
		String sMethod = "init()";
		Object sam = null;
		Object agent = null;
		Object idpSection = null;

		super.init();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Role=" + getMyRole() + " id=" + sFederationIdpKeyword);

		sam = _configManager.getSection(null, "sam");
		agent = _configManager.getSection(sam, "agent");
		try {
			Object metaResourcegroup = _configManager.getSection(agent, "resourcegroup", "id=" + sFederationIdpKeyword);
			idpSection = _configManager.getSection(metaResourcegroup, "resource");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No resourcegroup: "+sFederationIdpKeyword+" configured");
		}

		while (idpSection != null) {
			// Look for "id" "url" and "session_sync"
			String sId = _configManager.getParam(idpSection, "id");
			PartnerData idpData = new PartnerData(sId);
			try {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "id="+sId);
				String metadataUrl = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "url", true);
				if (metadataUrl != null)
					idpData.setMetadataUrl(metadataUrl);
				
				String specialSettings = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "special_settings", false);
				if (specialSettings != null)
					idpData.setSpecialSettings(specialSettings);
				String myIssuer = Utils.getSimpleParam(_configManager, _systemLogger, idpSection, "local_issuer", false);
				if (myIssuer != null)
					idpData.setLocalIssuer(myIssuer);
				
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
				Object acsSection = Utils.getSimpleSection(_configManager,_systemLogger, idpSection, "serviceindex",
						false);
				
				
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

				// Set specific metadata for this partner
				Object metadataSection = Utils.getSimpleSection(_configManager, _systemLogger, idpSection, "metadata", false);
				Object metaHandler = _configManager.getSection(metadataSection, "handler");
				// get handlers to publish
				while (metaHandler != null) {
					String metahandlertype = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "type", false);
					// todo check for valid type
					String metahandlerbinding = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "binding", false);
					// todo check for valid binding
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
					String metahandlerresponselocation = Utils.getSimpleParam(_configManager, _systemLogger, metaHandler, "responselocation", false);

					idpData.getMetadata4partner().getHandlers().add(idpData.new HandlerInfo(metahandlertype,metahandlerbinding,  bMetahandlerisdefault,  iMetahandlerindex, metahandlerresponselocation) );
					metaHandler = _configManager.getNextSection(metaHandler);
				}
				
				// maybe push this up one level if possible or even better, move to PartnerData
				
				// todo  and addcertificate for metadata
				String metaaddkeyname = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "addkeyname", false);
				if (metaaddkeyname != null)
					idpData.getMetadata4partner().setAddkeyname(metaaddkeyname);

				String metaaddcertificate = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "addcertificate", false);
				if (metaaddcertificate != null)
					idpData.getMetadata4partner().setAddcertificate(metaaddcertificate);
				String metaspecialSettings = Utils.getSimpleParam(_configManager, _systemLogger, metadataSection, "special_settings", false);
				if (metaspecialSettings != null)
					idpData.getMetadata4partner().setSpecialsettings(specialSettings);


				Object orgSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "organization", false);
				
				String metaorgname = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationname", false);
				String metaorgnamelang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationname", "lang", false);
				String metaorgdisplname = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationdisplayname", false);
				String metaorgdisplnamelang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationdisplayname", "lang", false);
				String metaorgurl = Utils.getSimpleParam(_configManager, _systemLogger, orgSection, "organizationurl", false);
				String metaorgurllang = Utils.getParamFromSection(_configManager, _systemLogger, orgSection, "organizationurl", "lang", false);
				
				idpData.getMetadata4partner().setOrganizationInfo(metaorgname, metaorgnamelang, metaorgdisplname, metaorgdisplnamelang, metaorgurl, metaorgurllang);
				
				Object contactSection = Utils.getSimpleSection(_configManager, _systemLogger, metadataSection, "contactperson", false);
				String metacontacttype = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "contacttype", false);
				
				String metacontactname = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "givenname", false);
				String metacontactsurname = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "surname", false);
				String metacontactemail = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "emailaddress", false);
				String metacontactephone = Utils.getSimpleParam(_configManager, _systemLogger, contactSection, "telephonenumber", false);

				idpData.getMetadata4partner().setContactInfo(metacontacttype, metacontactname, metacontactsurname, metacontactemail, metacontactephone);
				
				// End Set specific metadata for this partner

				
				_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + sId + "<>" + idpData);
				storeAllIdPData.put(sId, idpData);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Metadata retrieval failed", e);
				// maybe throw more serious error here
			}
			idpSection = _configManager.getNextSection(idpSection);
		}
		initializeMetaDataHandling();
	}
}
