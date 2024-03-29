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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.SoapLogoutRequestSender;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.handler.MemoryStorageHandler;
import org.aselect.system.utils.Utils;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

/*
 * NOTE: Code differs from the idp-version.
 * NOTE: Code is identical to MemoryStorageHandlerTimeOut (except for class-names of course).
 */
public class MemoryStorageHandlerTimeOut extends MemoryStorageHandler
{
	private final static String MODULE = "MemoryStorageHandlerTimeOut";
	private TGTManager _oTGTManager;
	private ConfigManager _oConfigManager;
	private ASelectSystemLogger _oSystemLogger;
	private String _serverUrl;
	private String _sFederationUrl = null;
	private boolean _bVerifySignature = false;

	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.MemoryStorageHandler#init(java.lang.Object, org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger, org.aselect.system.sam.agent.SAMAgent)
	 */
	@Override
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
	throws ASelectStorageException
	{
		String sMethod = "init";

		super.init(oConfigSection, oConfigManager, systemLogger, oSAMAgent);
		_oSystemLogger = (ASelectSystemLogger) systemLogger;
		_oConfigManager = oConfigManager;
		_oTGTManager = TGTManager.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigManager=" + oConfigManager + " ConfigSection="+oConfigSection);

		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_serverUrl = _oConfigManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		// 20091207: default if not available in TgT, only available for backward compatibility
		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_sFederationUrl = _oConfigManager.getParam(aselectSection, "federation_url");
		}
		catch (ASelectConfigException e) {
			// 20091207: systemLogger.log(Level.INFO, MODULE, sMethod,
			// "No config item 'federation_url' found in 'aselect' section", e);
			// 20091207: throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		set_bVerifySignature(false);
		try {
			Object _oTicketSection = _oConfigManager.getSection(null, "storagemanager", "id=tgt");
			String sVerifySignature = _oConfigManager.getParam(_oTicketSection, "verify_signature");
			if ("true".equalsIgnoreCase(sVerifySignature)) {
				set_bVerifySignature(true);
			}
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "storagemanager id=\"tgt\": verify_signature = " + is_bVerifySignature());
		}
		catch (ASelectConfigException e) {
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "storagemanager id=\"tgt\": verify_signature not found, set to = "
					+ is_bVerifySignature());
		}
	}

	// Bauke: replacement
	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.MemoryStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	@Override
	public void put(Object oKey, Object oValue, Long lTimestamp)
	throws ASelectStorageException
	{
		String _sMethod = "put";
		HashMap htValue = (HashMap) oValue;

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "MSHT " + this.getClass());
		// We'll use a small (not most beautiful) trick to speed up the "put" later on
//		if (!_oTGTManager.containsKey(oKey) || htValue.get("createtime") == null) {	// RH, 20111114, o
		boolean hasKey = _oTGTManager.containsKey(oKey);	// RH, 20111114, n
		if (!hasKey || htValue.get("createtime" ) == null) {	// RH, 20111114, n
			long now = new Date().getTime();
			htValue.put("createtime", String.valueOf(now));
			htValue.put("sessionsynctime", String.valueOf(now));
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "ADD createtime/sessionsync/timestamp=" + now);
		}

		// Special hack to prevent that the Timestamp is updated when only the "sessionsynctime" is changed
		String upd = (String) htValue.get("updatetimestamp");
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "updatetimestamp=" + upd);
		if (upd != null && upd.equals("no")) {
			lTimestamp = _oTGTManager.getTimestamp(oKey);
			htValue.remove("updatetimestamp");
		}
		super.put(oKey, oValue, lTimestamp);
		// don't use the Jdbc construction here!!!!
		// super.put(oKey, oValue, lTimestamp, hasKey ? UpdateMode.UPDATEFIRST : UpdateMode.INSERTFIRST);		// RH, 20111114, n
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.MemoryStorageHandler#cleanup(java.lang.Long)
	 */
	@Override
	public void cleanup(Long lTimestamp)
	throws ASelectStorageException
	{
		String _sMethod = "cleanup";
		long now = new Date().getTime();

		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CLEANUP { now="+now+" lTimestamp="+lTimestamp+" diff="+(now-lTimestamp));
		determineTimeOut();
		// Only the TGT Manager should use this class, therefore do not call super.cleanup()
		// super.cleanup(lTimestamp);
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "} CLEANUP");
	}

	// When the TGT is expired, we need to send a Soap Logout Request to the Federation
	/**
	 * Determine time out.
	 * 
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	@SuppressWarnings("unchecked")
	private void determineTimeOut()
	throws ASelectStorageException
	{
		String _sMethod = "determineTimeOut";

		HashMap allTgts = new HashMap();
		if (_oTGTManager != null) {
			allTgts = _oTGTManager.getAll();
		}
		if (allTgts == null || allTgts.size() == 0)
			return;
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO _serverUrl="+_serverUrl+" - TGT Count="+allTgts.size());
		Long updateInterval = -1L;
		try {
			HashMap htResult = SessionSyncRequestSender.getSessionSyncParameters(_oSystemLogger);
			updateInterval = (Long) htResult.get("update_interval");
			if (updateInterval == null) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "No 'update_interval' available");
				updateInterval = -1L;
			}
		}
		catch (ASelectException ase) {
			throw new ASelectStorageException(ase.toString());
		}

		// For all TGT's
		Set keys = allTgts.keySet();
		for (Object s : keys) {
			String key = (String) s;
			HashMap htTGTContext = (HashMap) _oTGTManager.get(key);
			String sNameID = (String) htTGTContext.get("name_id");
			String sSync = (String) htTGTContext.get("sessionsynctime");
			long lastSync = (sSync==null)? 0: Long.parseLong(sSync);
			Boolean bForcedAuthn = (Boolean) htTGTContext.get("forced_authenticate");
			if (bForcedAuthn == null)
				bForcedAuthn = false;
			Long expireTime = _oTGTManager.getExpirationTime(key);
			Long timeStamp = _oTGTManager.getTimestamp(key);
			Long now = new Date().getTime();

			String sKey = Utils.firstPartOf(key, 30);
			_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO - NameID="+Utils.firstPartOf(sNameID,20)+
					" Age="+(now-timeStamp)+" Time left="+(expireTime-now)+" Last Sync="+(now-lastSync)+" Key="+sKey);

			String sAuthspType = (String) htTGTContext.get("authsp_type");
			Boolean bToFed = (sAuthspType != null && sAuthspType.equals("saml20"));
			// Check Ticket Expiration
			if (now >= expireTime) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO: Remove TGT, Key="+sKey);
				_oTGTManager.remove(key);

				// 20090622, Bauke, if forced_authenticate, the IdP does not have a ticket
				if (bToFed && !bForcedAuthn) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO: saml20 and forced="+bForcedAuthn);
					sendLogoutToFederation(sNameID, htTGTContext);
				}
			}

			// Check Session Sync
			// Since the last Session Sync also updates the TGT's timestamp
			// also skip a few seconds after lastSync
			if (bToFed && updateInterval>0 && timeStamp>lastSync+10 && now>=lastSync+updateInterval) {
				// Perform a Session Sync to the Federation
				_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO Skip this SessionSync");
			}
		}
	}

	/**
	 * Send logout to federation.
	 * 
	 * @param sNameID
	 *            the s name id
	 * @param htTGTContext
	 *            the ht tgt context
	 * @return true, if successful
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 */
	private boolean sendLogoutToFederation(String sNameID, HashMap htTGTContext)
	throws ASelectStorageException
	{
		String _sMethod = "sendLogoutToFederation";

		String sFederationUrl = (String) htTGTContext.get("federation_url");
		String sResourcegroup = (String) htTGTContext.get("federation_group");	// RH, 20190325, n

		Vector<String> sessionIndexes = (Vector<String>)  htTGTContext.get("remote_sessionlist");	// can be null	// RH, 20120201, n

		if (sFederationUrl == null)
			 // RM_54_01
			sFederationUrl = _sFederationUrl;
		if (sFederationUrl == null || sFederationUrl.equals("")) {
			_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No \"federation_url\" available in TGT");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO ("+_serverUrl+") - NameID to timeout = "+Utils.firstPartOf(sNameID, 30));
		SoapLogoutRequestSender logout = new SoapLogoutRequestSender();
		String url = null;
		MetaDataManagerSp metadataManager = null;
		try {
			metadataManager = MetaDataManagerSp.getHandle();
//			url = metadataManager.getLocation(sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190325, o
			url = metadataManager.getLocation(sResourcegroup, sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,	// RH, 20190325, n
					SAMLConstants.SAML2_SOAP11_BINDING_URI);
		}
		catch (ASelectException e1) {
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		String issuerUrl = _serverUrl;
		List<PublicKey> pkeys = null;	// RH, 20181119, n
		if (is_bVerifySignature()) {
//			pkeys = metadataManager.getSigningKeyFromMetadata(sFederationUrl);	// RH, 20181119, n	// RH, 20190325, o
			pkeys = metadataManager.getSigningKeyFromMetadata(sResourcegroup, sFederationUrl);	// RH, 20181119, n	// RH, 20190325, n
			if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181119, n
				_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No valid public key in metadata");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		
		// RH, 20180918, sn
		PartnerData partnerData = null;
		PartnerData.Crypto specificCrypto = null;
		try {
//			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sFederationUrl);	// RH, 20190325, o
			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sResourcegroup, sFederationUrl);	// RH, 20190325, n
			if (partnerData != null) {
				specificCrypto = partnerData.getCrypto();	// might be null
			}
		} catch (ASelectException e1) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Could not get handle to MetaDataManagerSp, not signing with specific private key");
		}
		// RH, 20180918, en

		try {
//			logout.sendSoapLogoutRequest(url, issuerUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout", pkey);	// RH, 20120201, o
//			logout.sendSoapLogoutRequest(url, issuerUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout", pkey, sessionIndexes, specificCrypto);	// RH, 20120201, n	// RH, 20181119, o
			logout.sendSoapLogoutRequest(url, issuerUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout", pkeys, sessionIndexes, specificCrypto);	// RH, 20120201, n	// RH, 20181119, n
		}
		catch (ASelectException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Exception trying to send Logout message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return false;
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
}
