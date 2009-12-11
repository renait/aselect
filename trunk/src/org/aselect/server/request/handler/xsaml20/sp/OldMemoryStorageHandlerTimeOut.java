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

import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

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
import org.aselect.system.storagemanager.handler.OldMemoryStorageHandler;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

// TODO: Auto-generated Javadoc
/*
 * NOTE: Code is identical to JDBCStorageHandlerTimeOut (except for class-names of course)
 */
public class OldMemoryStorageHandlerTimeOut extends OldMemoryStorageHandler
{
	private final static String MODULE = "OldMemoryStorageHandlerTimeOut";
	private TGTManager _oTGTManager;
	private ConfigManager _oConfigManager;
	private ASelectSystemLogger _oSystemLogger;
	private String _serverUrl;
	private String _sFederationUrl = null;
	private boolean _bVerifySignature = false;

	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.OldMemoryStorageHandler#init(java.lang.Object, org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger, org.aselect.system.sam.agent.SAMAgent)
	 */
	@Override
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
		throws ASelectStorageException
	{
		String sMethod = "init()";

		super.init(oConfigSection, oConfigManager, systemLogger, oSAMAgent);
		_oSystemLogger = (ASelectSystemLogger) systemLogger;
		_oConfigManager = oConfigManager;
		_oTGTManager = TGTManager.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "ConfigManager=" + oConfigManager + " ConfigSection="
				+ oConfigSection);

		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_serverUrl = _oConfigManager.getParam(aselectSection, "redirect_url");
		}
		catch (ASelectConfigException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_url' found in 'aselect' section", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		try {
			Object aselectSection = _oConfigManager.getSection(null, "aselect");
			_sFederationUrl = _oConfigManager.getParam(aselectSection, "federation_url");
		}
		catch (ASelectConfigException e) {
			// 20091207: systemLogger.log(Level.WARNING, MODULE, sMethod,
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
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature = " + is_bVerifySignature());
		}
		catch (ASelectConfigException e) {
			_oSystemLogger.log(Level.INFO, MODULE, sMethod, "verify_signature not found, set to = "
					+ is_bVerifySignature());
		}
	}

	// Bauke: replacement
	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.OldMemoryStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	@Override
	public void put(Object oKey, Object oValue, Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "put";
		HashMap htValue = (HashMap) oValue;

		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "MSHT " + this.getClass());
		if (!_oTGTManager.containsKey(oKey) || htValue.get("createtime") == null) {
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
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.storagemanager.handler.OldMemoryStorageHandler#cleanup(java.lang.Long)
	 */
	@Override
	public void cleanup(Long lTimestamp)
		throws ASelectStorageException
	{
		String _sMethod = "cleanup";
		Long now = new Date().getTime();

		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "CLEANUP { lTimestamp=" + (lTimestamp - now) + " class="
				+ this.getClass());
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
		if (allTgts == null)
			return;
		_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO _serverUrl=" + _serverUrl + " - TGT Count="
				+ allTgts.size());
		Long updateInterval = -1L;
		try {
			HashMap htResult = SessionSyncRequestSender.getSessionSyncParameters(_oSystemLogger);
			updateInterval = (Long) htResult.get("update_interval");
			if (updateInterval == null) {
				_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "No 'update_interval' available");
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
			// for (Enumeration<String> e = allTgts.keys(); e.hasMoreElements();) {
			// String key = e.nextElement();
			HashMap htTGTContext = (HashMap) _oTGTManager.get(key);
			String sNameID = (String) htTGTContext.get("name_id");
			String sSync = (String) htTGTContext.get("sessionsynctime");
			Long lastSync = Long.parseLong(sSync);
			Long expireTime = _oTGTManager.getExpirationTime(key);
			Long timeStamp = _oTGTManager.getTimestamp(key);
			Long now = new Date().getTime();

			String sKey = (key.length() > 30) ? key.substring(0, 30) + "..." : key;
			_oSystemLogger.log(Level.FINER, MODULE, _sMethod, "SPTO - NameID=" + sNameID + " TimeStamp="
					+ (timeStamp - now) + " Left=" + (expireTime - now) + " lastSync=" + (lastSync - now) + " Key="
					+ sKey);

			// Check Ticket Expiration
			if (now >= expireTime) {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO Remove TGT and send Logout, Key=" + sKey);
				_oTGTManager.remove(key);
				sendLogoutToFederation(sNameID, htTGTContext);
			}

			// Check Session Sync
			// Since the last Session Sync also update the TGT's timestamp
			// also skip a few seconds after lastSync
			if (updateInterval > 0 && timeStamp > lastSync + 10 && now >= lastSync + updateInterval) {
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
		if (sFederationUrl == null)
			sFederationUrl = _sFederationUrl; // TODO: remove later on
		if (sFederationUrl == null || sFederationUrl.equals("")) {
			_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No \"federation_url\" available in TGT");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SPTO (" + _serverUrl + ") - NameID to timeout = " + sNameID);
		SoapLogoutRequestSender logout = new SoapLogoutRequestSender();
		String url = null;
		MetaDataManagerSp metadataManager = null;
		try {
			metadataManager = MetaDataManagerSp.getHandle();
			url = metadataManager.getLocation(sFederationUrl, SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME,
					SAMLConstants.SAML2_SOAP11_BINDING_URI);
		}
		catch (ASelectException e1) {
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		String issuerUrl = _serverUrl;
		PublicKey pkey = null;
		if (is_bVerifySignature()) {
			pkey = metadataManager.getSigningKeyFromMetadata(sFederationUrl);
			if (pkey == null || "".equals(pkey)) {
				_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "No valid public key in metadata");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
		}
		try {
			logout
					.sendSoapLogoutRequest(url, issuerUrl, sNameID, "urn:oasis:names:tc:SAML:2.0:logout:sp-timeout",
							pkey);
		}
		catch (ASelectException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "exception trying to send Logout message", e);
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
