/*
 * Created on 20161129
 *
 */
package org.aselect.server.authspprotocol.handler;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import net.bankid.merchant.library.AssuranceLevel;
import net.bankid.merchant.library.AuthenticationRequest;
import net.bankid.merchant.library.AuthenticationResponse;
import net.bankid.merchant.library.Communicator;
import net.bankid.merchant.library.Configuration;
import net.bankid.merchant.library.DirectoryResponse;
import net.bankid.merchant.library.SamlResponse;
import net.bankid.merchant.library.ServiceIds;
import net.bankid.merchant.library.StatusRequest;
import net.bankid.merchant.library.StatusResponse;

import org.apache.commons.lang.StringEscapeUtils;
import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.log.IdinLoggerFactory;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;

/**
 * The IdinAuthSPHandler. <br>
 * <br>
 * <b>Description:</b>
 * <br>
 * The IdinAuthSPHandler implements the iDIN bank protocol <br>
 * 
 * @author Bauke Hiemstra - www.anoigo.nl
 */
public class IdinAuthSPHandler  extends AbstractAuthSPProtocolHandler  implements IAuthSPProtocolHandler
{
	private static final String DEFAULT_URN_NL_BVN_BANKID_1_0_CONSUMER_BIN = "urn:nl:bvn:bankid:1.0:consumer.bin";
	private static final String DEFAULT_URN_NL_BVN_BANKID_1_0_STATUS_SUCCESS = "urn:nl:bvn:bankid:1.0:status:Success";
	private static final String DEFAULT_LANGUAGE = "en";
	private static final AssuranceLevel DEFAULT_ASSURANCELEVEL = AssuranceLevel.Loa3;
//	private static final int DEFAULT_SERVICEIDS = ServiceIds.IsEighteenOrOlder|ServiceIds.Address;
	private static final int DEFAULT_SERVICEIDS = ServiceIds.IsEighteenOrOlder|ServiceIds.ConsumerBin;
	
	private static final String DEFAULT_ENTRANCE_CODE = "entranceCode";
	private final static String MODULE = "IdinAuthSPHandler";
	private ASelectConfigManager _configManager;
//	private SessionManager _sessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	//private IClientCommunicator _oClientCommunicator;

	private String _sAuthSPId;
//	private String _sAuthSPUrl;
	private String _sASelectAuthSPServerId;
	private String _sDefaultBetrouwbaarheidsNiveau;

	private HashMap<String, String> _htBetrouwbaarheidsNiveaus;
	private HashMap<String, String> _htSharedSecrets;

	public String getLocalRidName() { return "local_rid"; }
	
	/* iDIN parameters */
	private String merchantID;
	private int merchantSubID;
	private String merchantReturnUrl;
	private String keyStoreLocation;
	private String keyStorePassword;
	private String merchantCertificateAlias;
	private String merchantCertificatePassword;
	private String acquirerCertificateAlias;
	private String acquirerDirectoryURL;
	private String acquirerTransactionURL;
	private String acquirerStatusURL;
	private boolean logsEnabled;
	private boolean serviceLogsEnabled;
	private String serviceLogsLocation;
	private String serviceLogsPattern;
	private static HashMap<String, String> _hmAvailableIssuers = new HashMap<String, String>();

	private static DateTime _lastDirectoryRead = null;
	private int _iRefreshDirectory = 604800;  // 7 days
	private String _entranceCode = DEFAULT_ENTRANCE_CODE;
	private AssuranceLevel _assuranceLevel = DEFAULT_ASSURANCELEVEL;
	private int _serviceIds = DEFAULT_SERVICEIDS;
	private String _language = DEFAULT_LANGUAGE;
	private String _bankidSecondLevelStatusSuccess = DEFAULT_URN_NL_BVN_BANKID_1_0_STATUS_SUCCESS;
	private String _bankidConsumerBinAttribute = DEFAULT_URN_NL_BVN_BANKID_1_0_CONSUMER_BIN;

	/**
	 * Initializes the IdinAuthSPHandler. <br>
	 * Resolves the following config items:<br>
	 * - The IdinAuthSP id<br>
	 * - The url to the authsp (from the resource)<br>
	 * - The server id from the A-Select main config<br>
	 * <br>
	 * 
	 * @param oAuthSPConfig
	 *            the AuthSP config
	 * @param oAuthSPResource
	 *            the AuthSP resourcegroup
	 * @throws ASelectAuthSPException
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";
		
		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			_authenticationLogger = ASelectAuthenticationLogger.getHandle();
			_configManager = ASelectConfigManager.getHandle();
//			_sessionManager = SessionManager.getHandle();

			_sAuthSPId = ASelectConfigManager.getSimpleParam(oAuthSPConfig, "id", true);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "id=" + _sAuthSPId);

			// ---- Get configuration data from the resource group
			merchantID = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "merchantID", true/*mandatory*/);
			merchantSubID = Utils.getSimpleIntParam(_configManager, _systemLogger, oAuthSPResource, "merchantSubID", true/*mandatory*/);
			merchantReturnUrl = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "merchantReturnUrl", true/*mandatory*/);
			keyStoreLocation = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "keyStoreLocation", true/*mandatory*/);
			keyStorePassword = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "keyStorePassword", true/*mandatory*/);
			merchantCertificateAlias = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "merchantCertificateAlias", true/*mandatory*/);
			merchantCertificatePassword = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "merchantCertificatePassword", true/*mandatory*/);
			acquirerCertificateAlias = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "acquirerCertificateAlias", true/*mandatory*/);
			acquirerDirectoryURL = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "acquirerDirectoryURL", true/*mandatory*/);
			acquirerTransactionURL = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "acquirerTransactionURL", true/*mandatory*/);
			acquirerStatusURL = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "acquirerStatusURL", true/*mandatory*/);
			String sLogsEnabled = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "logsEnabled", true/*mandatory*/);
			logsEnabled = Boolean.parseBoolean(sLogsEnabled);
			String sServiceLogsEnabled = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "serviceLogsEnabled", true/*mandatory*/);
			logsEnabled = Boolean.parseBoolean(sServiceLogsEnabled);
			serviceLogsLocation = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "serviceLogsLocation", true/*mandatory*/);
			serviceLogsPattern = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "serviceLogsPattern", true/*mandatory*/);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "merchantReturnUrl=" + merchantReturnUrl);
			// End of resource group config

			// ---- Get configuration data from the AuthSP section: <authsp>
			_iRefreshDirectory = Utils.getSimpleIntParam(_configManager, _systemLogger, oAuthSPConfig, "refreshDirectory", true/*mandatory*/);
//			_sDefaultBetrouwbaarheidsNiveau = _configManager.getParam(oAuthSPConfig, "default_betrouwbaarheidsniveau");
			_sDefaultBetrouwbaarheidsNiveau = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "default_betrouwbaarheidsniveau", true/*mandatory*/);
			_sASelectAuthSPServerId = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "server_id", true/*mandatory*/);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ServerId=" + _sASelectAuthSPServerId);

			//_oClientCommunicator = Tools.initClientCommunicator(_configManager, _systemLogger, oAuthSPConfig);

			Object oBetrouwbaarheidsNiveaus = null;
			try {
				oBetrouwbaarheidsNiveaus = _configManager.getSection(oAuthSPConfig, "betrouwbaarheidsniveaus");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'betrouwbaarheidsniveaus' found",e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			Object oBetrouwbaarheidsNiveau = null;
			try {
				oBetrouwbaarheidsNiveau = _configManager.getSection(oBetrouwbaarheidsNiveaus, "betrouwbaarheidsniveau");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section 'betrouwbaarheidsniveau' found",e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_htBetrouwbaarheidsNiveaus = new HashMap<String, String>();
			_htSharedSecrets = new HashMap<String, String>();

			while (oBetrouwbaarheidsNiveau != null) {
				loadBetrouwbaarheidsNiveau(oBetrouwbaarheidsNiveau);
				oBetrouwbaarheidsNiveau = _configManager.getNextSection(oBetrouwbaarheidsNiveau);
			}
			
			// Get optional testdata from configuration
			String _sEntranceCode = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "entrancecode", false/*mandatory*/);
			if (_sEntranceCode != null) {	// any data will be accepted so beware
				_entranceCode = _sEntranceCode;
			}
			// Get optional assurancelevel from configuration
			String _sAssuranceLevel = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "assurancelevel", false/*mandatory*/);
			if (_sAssuranceLevel != null && "loa2".equalsIgnoreCase(_sAssuranceLevel)) {
				_assuranceLevel = AssuranceLevel.Loa2;
			}
			// Get optional serviceids from configuration
			// We might be wanting to make this runtime configurable later
			String _sServiceIds = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "serviceids", false/*mandatory*/);
			if (_sServiceIds != null) {
				_serviceIds = calculateServiceIds(_sServiceIds, ServiceIds.None );
			}
			// Get optional user language from configuration
			// We might be wanting to make this runtime configurable later
			String _sLanguage = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "language", false/*mandatory*/);
			if (_sLanguage != null) {	// any data will be accepted so beware
				_language = _sLanguage;
			}

			// Get optional user secondlevel status success from configuration
			String _sSecondLevelSuccess = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "bankidsecondlevelsuccess", false/*mandatory*/);
			if (_sSecondLevelSuccess != null) {	// any data will be accepted so beware
				_bankidSecondLevelStatusSuccess = _sSecondLevelSuccess;
			}

			// Get optional user consumer bin attribute name status success from configuration
			String _sConsumerBinAttribute = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPConfig, "bankidconsumerbinattribute", false/*mandatory*/);
			if (_sConsumerBinAttribute != null) {	// any data will be accepted so beware
				_bankidConsumerBinAttribute = _sConsumerBinAttribute;
			}

			// Get the directory of Issuers (=banks)
//			DateTime now = new DateTime();
			if (_lastDirectoryRead==null || _lastDirectoryRead.plusSeconds(_iRefreshDirectory).isBeforeNow()) {  // out-dated issuer list
				_systemLogger.log(Level.FINE, MODULE, sMethod, "getDirectory needed lastDirectoryRead="+_lastDirectoryRead);
//				if (false) {
				
//				Configuration.defaultInstance().Setup(
//					new Configuration(merchantID, merchantSubID, merchantReturnUrl,
//							keyStoreLocation, keyStorePassword, merchantCertificateAlias,
//							merchantCertificatePassword, acquirerCertificateAlias,
//							acquirerDirectoryURL, acquirerTransactionURL, acquirerStatusURL,
//							logsEnabled, serviceLogsEnabled, serviceLogsLocation, serviceLogsPattern, null/*ILoggerFactory*/)
//				);

//				Configuration.defaultInstance().setLogsEnabled(true);;
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "bankidConfig loging enabled");
				
				Configuration bankidConfig = new Configuration(merchantID, merchantSubID, merchantReturnUrl,
//				IdinConfiguration bankidConfig = new IdinConfiguration(_systemLogger, merchantID, merchantSubID, merchantReturnUrl,
						keyStoreLocation, keyStorePassword, merchantCertificateAlias,
						merchantCertificatePassword, acquirerCertificateAlias,
						acquirerDirectoryURL, acquirerTransactionURL, acquirerStatusURL,
					//	logsEnabled, serviceLogsEnabled, null /* serviceLogsLocation */, serviceLogsPattern, new IdinLoggerFactory() /*ILoggerFactory*/);
						// use TLS v1.2
//						logsEnabled, serviceLogsEnabled, null /* serviceLogsLocation */, serviceLogsPattern, true, new IdinLoggerFactory() /*ILoggerFactory*/);
						logsEnabled, serviceLogsEnabled, serviceLogsLocation, serviceLogsPattern, true /* use tlsv1.2 */, new IdinLoggerFactory(_systemLogger) /*ILoggerFactory*/);
				
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "bankidConfig="+bankidConfig);
				
				
				Configuration.defaultInstance().Setup(bankidConfig);
//				IdinConfiguration.defaultInstance().Setup(bankidConfig);
				
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "bankidConfig Setup succeseeded");
				
//				Communicator iDinCom = new Communicator();
				_systemLogger.log(Level.FINE, MODULE, sMethod, "getDirectory");
//				DirectoryResponse res = iDinCom.getDirectory();
				DirectoryResponse res = new Communicator().getDirectory();
				_systemLogger.log(Level.FINE, MODULE, sMethod, "gotDirectory");
				if (res.getIsError()) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error returned from library: " + res.getErrorResponse().getErrorMessage());
				}
				else {
					for (DirectoryResponse.Issuer issuer : res.getIssuers()) {
						_systemLogger.log(Level.FINE, MODULE, sMethod, "From idin: issuer Country, ID, Name: " + issuer.getIssuerCountry()+", "+
								issuer.getIssuerID()+", "+issuer.getIssuerName());
						_hmAvailableIssuers.put(issuer.getIssuerID(), issuer.getIssuerName());
					}
					_lastDirectoryRead = new DateTime();
					_systemLogger.log(Level.FINE, MODULE, sMethod, "getDirectory done lastDirectoryRead="+_lastDirectoryRead);
				}
//				}
			}
		}
		catch (ASelectAuthSPException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * @param _sServiceIds
	 * 
	 * @return calculated bitpaatern int
	 */
	protected int calculateServiceIds(String _sServiceIds, int defaultServiceIds) {
		int iServiceIds = defaultServiceIds;
		_sServiceIds = _sServiceIds.toUpperCase();
		if (_sServiceIds.contains("ADDRESS")) {
			iServiceIds |= ServiceIds.Address;
		}
		if (_sServiceIds.contains("BSN")) {
			iServiceIds |= ServiceIds.BSN;
		}
		if (_sServiceIds.contains("CONSUMERBIN")) {
			iServiceIds |= ServiceIds.ConsumerBin;
		}
		if (_sServiceIds.contains("CONSUMERTRANSIENTID")) {
			iServiceIds |= ServiceIds.ConsumerTransientId;
		}
		if (_sServiceIds.contains("DATEOFBIRTH")) {
			iServiceIds |= ServiceIds.DateOfBirth;
		}
		if (_sServiceIds.contains("EMAIL")) {
			iServiceIds |= ServiceIds.Email;
		}
		if (_sServiceIds.contains("GENDER")) {
			iServiceIds |= ServiceIds.Gender;
		}
		if (_sServiceIds.contains("ISEIGHTEENOROLDER")) {
			iServiceIds |= ServiceIds.IsEighteenOrOlder;
		}
		if (_sServiceIds.contains("NAME")) {
			iServiceIds |= ServiceIds.Name;
		}
		if (_sServiceIds.contains("TELEPHONE")) {
			iServiceIds |= ServiceIds.Telephone;
		}
		return iServiceIds;
	}

	/**
	 * Generate an Issuer <select> element
	 * 	<select id="idin_bank" name="idin_bank_select">
			<option value="">Kies je bank...</option>
			...<option value="ASNBNL21">ASN Bank</option>...
			<option value="INGBNL2A" selected="selected">ING</option>...
			<option value="TRIONL2U">Triodos Bank</option>...
		</select>
	 */
	@Override
	public String inquireSubselect(Map map)
	{
		if (_hmAvailableIssuers.isEmpty()) {	// Some defaults for testing
//			_hmAvailableIssuers.put("ASNBNL21", "ASN Bank");
//			_hmAvailableIssuers.put("TRIONL2U", "Triodos Bank");
//			_hmAvailableIssuers.put("BANKNL2Y", "ABN AMRO iDIN issuer simulatie");
			// We should try again
			
		}
		StringBuffer sb = new StringBuffer("<select id=\"idin_bank_select\" name=\"idin_bank_select\">");
		Set<String> keySet = _hmAvailableIssuers.keySet();
		Iterator<String> it = keySet.iterator();
		while(it.hasNext()) {
			String sIssuerId = it.next();
			String sIssuerName = _hmAvailableIssuers.get(sIssuerId);
			sb.append("<option value=\"").append(sIssuerId).append("\">").append(StringEscapeUtils.escapeHtml(sIssuerName));
			sb.append("</option>");
		}
		sb.append("</select>");
		return sb.toString();
	}

	/**
	 * Load betrouwbaarheidsniveau.
	 * 
	 * @param oBetrouwbaarheidsNiveau
	 *            the o betrouwbaarheids niveau
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadBetrouwbaarheidsNiveau(Object oBetrouwbaarheidsNiveau)
	throws ASelectException
	{
		String sMethod = "loadBetrouwbaarheidsNiveau";

		String sNiveau;
		try {
			sNiveau = _configManager.getParam(oBetrouwbaarheidsNiveau, "id");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No attribute 'id' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sApplication;
		try {
			sApplication = _configManager.getParam(oBetrouwbaarheidsNiveau, "application");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No section 'application' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		String sSharedSecret;
		try {
			sSharedSecret = _configManager.getParam(oBetrouwbaarheidsNiveau, "shared_secret");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No section 'shared_secret' in config section 'betrouwbaarheidsniveau' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "BetrouwbaarheidsNiveau: '" + sNiveau + "', Application: '"
				+ sApplication + "', Shared secret: '" + sSharedSecret.substring(0, 6) + "...'");
		_htBetrouwbaarheidsNiveaus.put(sNiveau, sApplication);
		_htSharedSecrets.put(sNiveau, sSharedSecret);
	}

	/**
	 * Sends an authentication request to the authsp.
	 * 
	 * @param sRid
	 *            the rid
	 * @param htSessonContext
	 *            the session context
	 * @return the hash map
	 */
	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String, java.util.HashMap)
	 */
	@SuppressWarnings("unchecked")
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";

		HashMap htMethodResponse = new HashMap();
		htMethodResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "started");
		try {
			// 20120403, Bauke: passes as parameter: HashMap htSessionContext = _sessionManager.getSessionContext(sRid);
			if (htSessionContext == null) {
				StringBuffer sbBuffer = new StringBuffer("Could not fetch session context for rid: ");
				sbBuffer.append(sRid);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionContext=" + htSessionContext);

			// 20090110, Bauke changed requested_betrouwbaarheidsniveau to required_level
			String sBetrouwbaarheidsNiveau = (String) htSessionContext.get("required_level");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "requested required_level=" + sBetrouwbaarheidsNiveau
					+ " default level=" + _sDefaultBetrouwbaarheidsNiveau);
			if (sBetrouwbaarheidsNiveau == null || sBetrouwbaarheidsNiveau.equals("empty")) {
				// if betrouwbaarheidsniveau was not specified, we use the default.
				sBetrouwbaarheidsNiveau = _sDefaultBetrouwbaarheidsNiveau;
			}
			String sAppId = _htBetrouwbaarheidsNiveaus.get(sBetrouwbaarheidsNiveau);
			String sSharedSecret = _htSharedSecrets.get(sBetrouwbaarheidsNiveau);
			if (sAppId == null) {
				// RM_22_01
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No <application> found for level=" + sBetrouwbaarheidsNiveau);
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
			}
			if (sSharedSecret == null) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No <betrouwbaarheidsniveau> found for level="
						+ sBetrouwbaarheidsNiveau);
				throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
			}

			// ---- Send AcquirerTrxReq to iDIN, provide the bank chosen by the user, provide the merchantReturnURL (that's us)
			String sSelectedBank = (String) htSessionContext.get("idin_bank_select");
			if (sSelectedBank == null && !_hmAvailableIssuers.isEmpty()) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "htSessionContext idin_bank_select empty, using first from: " + _hmAvailableIssuers);
				sSelectedBank = _hmAvailableIssuers.keySet().iterator().next(); // Take first (and probably only) by default
			}
			String _sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
			String sMerchantReturnUrl = _sServerUrl + "?local_rid=" + sRid + "&authsp=" + _sAuthSPId;

			_systemLogger.log(Level.INFO, MODULE, sMethod, "setMerchantReturnUrl: " + sMerchantReturnUrl);
			Configuration.defaultInstance().setMerchantReturnUrl(sMerchantReturnUrl);
//			IdinConfiguration.defaultInstance().setMerchantReturnUrl(sMerchantReturnUrl);
			AuthenticationResponse response = null;
			Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);  // 20120215, possible session update
			try {
				//htResponse = _oClientCommunicator.sendMessage(htRequest, sASelectServerUrl);
				byte[] baRandomBytes = new byte[10];
				CryptoEngine.nextRandomBytes(baRandomBytes);
				// Still have to store the merchantReference
				String merchantReference = "S" + Utils.byteArrayToHexString(baRandomBytes);	// must start with [a-zA-Z]
				
				AuthenticationRequest nar = new AuthenticationRequest(
						_entranceCode, _serviceIds,
//						null, AssuranceLevel.Loa2, "en", null);
//						sSelectedBank, _assuranceLevel, "en", null);
						sSelectedBank, _assuranceLevel, _language, merchantReference);
				response = new Communicator().newAuthenticationRequest(nar);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "merchantReference=" + merchantReference);
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not send authentication request");
				throw new ASelectException(Errors.ERROR_ASELECT_IO);
			}
			finally {
				// Time in between should be attributed to iDin
				Tools.resumeSensorData(_configManager, _systemLogger, htSessionContext);  // 20120215, possible session update
			}
			
			// ---- Analyse the result
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Result=" + response);
			if (response == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No response received");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			else if (response.getIsError()) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, response.getErrorResponse().getErrorMessage());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}
			else {
				// redirect to response.getIssuerAuthenticationURL()
				// we should save the TransactionID for later verification
				_systemLogger.log(Level.FINE, MODULE, sMethod, "TransactionID="+response.getTransactionID()); 
				_systemLogger.log(Level.INFO, MODULE, sMethod, "IssuerAuthenticationURL="+response.getIssuerAuthenticationURL()); 
			}
			
				// We will regain control at:
				// https://my.idp.nl/aselectserver/server?local_rid=4A83AB89E64B6A20&authsp=IdinAuthSP&
				// rid=120127592091747E2EEBC3F0AA366&a-select-server=digidasdemo1&aselect_credentials=7C664...

			// ---- Assemble our redirection URL
			htMethodResponse.put("redirect_url", response.getIssuerAuthenticationURL());
			htMethodResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectAuthSPException e) {
			htMethodResponse.put("result", e.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not authenticate", e);
			htMethodResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htMethodResponse;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */
	@SuppressWarnings("unchecked")
	public HashMap verifyAuthenticationResponse(HashMap htResponse, HashMap htSessionContext)
	{
		String sMethod = "verifyAuthenticationResponse";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "====");

		HashMap<String, Object> result = new HashMap<String, Object>();
		String resultCode = Errors.ERROR_ASELECT_INTERNAL_ERROR;

		try {
			String sLocalRid = (String) htResponse.get("local_rid");
//			String sDigidRid = (String) htResponse.get("rid");
//			String credentials = (String) htResponse.get("aselect_credentials");
			String sLocalAppId = null;
			
			String ec = (String) htResponse.get("ec");
			// We should verify the trxid with our previous retrieved trxid
			String trxid = (String) htResponse.get("trxid");
			

			// To determine which shared secret to use, we need to know the 'betrouwbaarheidsniveau'.
			// This is stored in the session, which we can get via the local_rid.
			// If its not found, we use the default betrouwbaarheidsniveau to determine the shared secret.
			String sReqLevel = _sDefaultBetrouwbaarheidsNiveau;
			String sharedSecret = _htSharedSecrets.get(_sDefaultBetrouwbaarheidsNiveau);
			
			// 20120403, Bauke: session is available as a parameter
			// 20090110, Bauke changed requested_betrouwbaarheidsniveau to required_level
			// required_level not in session (yet)
			sReqLevel = (String)htSessionContext.get("required_level");
			Integer intLevel = (Integer)htSessionContext.get("level");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "required_level=" + sReqLevel + " level=" + intLevel);
			if (sReqLevel == null || sReqLevel.equals("empty"))
				sReqLevel = _sDefaultBetrouwbaarheidsNiveau;
			sharedSecret = _htSharedSecrets.get(sReqLevel);
			sLocalAppId = (String)htSessionContext.get("app_id");

//			HashMap reqParams = new HashMap();
//			reqParams.put("request", "verify_credentials");
//			reqParams.put("a-select-server", _sASelectAuthSPServerId);
//			reqParams.put("rid", sDigidRid);
//			reqParams.put("aselect_credentials", credentials);
//			reqParams.put("shared_secret", sharedSecret);
//
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sendMessage to " + _sAuthSPUrl + " request=" + reqParams);
//			//HashMap<String, Object> response = null;
//			//response = _oClientCommunicator.sendMessage(reqParams, _sAuthSPUrl);
			
//			StatusRequest statRequest = new StatusRequest("1234567890");
			StatusRequest statRequest = new StatusRequest(trxid);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sendMessage to idin");
			
			StatusResponse statResponse = new Communicator().getResponse(statRequest);
			String msg = null;
			if (statResponse == null) {
				msg = "No response received";
				_systemLogger.log(Level.WARNING, MODULE, sMethod, msg);
//				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			} else if (statResponse.getIsError()) {
				msg = "Error response received: "+statResponse.getErrorResponse();
				_systemLogger.log(Level.WARNING, MODULE, sMethod, msg);
//				resultCode = Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE;
				resultCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
			} else if ( !StatusResponse.Success.equals(statResponse.getStatus()) ) {
				msg = "Response not succesful: " + statResponse.getStatus();
				_systemLogger.log(Level.WARNING, MODULE, sMethod, msg);
				if ( StatusResponse.Cancelled.equals(statResponse.getStatus()) ) {
					resultCode = Errors.ERROR_ASELECT_SERVER_CANCEL;
				} else if ( StatusResponse.Expired.equals(statResponse.getStatus())  ) {
					resultCode = Errors.ERROR_ASELECT_SERVER_AUTH_EXPIRED;
				} else if ( StatusResponse.Open.equals(statResponse.getStatus())  ) {
					resultCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
				} else if ( StatusResponse.Failure.equals(statResponse.getStatus())  ) {
					resultCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
				} else if ( StatusResponse.Pending.equals(statResponse.getStatus())  ) {
					resultCode = Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
				} else {
					resultCode = Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE;
				}
			}
			// ---- Extract information from the response if it's there
			SamlResponse saml = statResponse.getSamlResponse();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "saml=" + saml);
			// DigiD should respond with:
			// Response={organization=DigiDDemo, laatst_ingelogd=1201183703000, betrouwbaarheidsniveau=10, asp=NAVWW1,
			// asp_level=10, result_code=0000, a-select-server=digidasdemo1, uid=923005716, app_id=ABCDE.my_org.nl,
			// app_level=5, tgt_exp_time=1201304729377, rid=120127592091747E2EEBC3F0AA366}

//			HashMap<String, Object> response = null;
//			resultCode = (String) response.get("result_code");
			if (saml != null) {
				String statusFirstLevel = (String) saml.getStatus().getStatusCodeFirstLevel();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "statusFirstLevel=" + statusFirstLevel);
				if ("urn:oasis:names:tc:SAML:2.0:status:Success".equals(statusFirstLevel)) {	// Still to find the appropriate constant
					// Maybe also check statusSecondLevel
					String statusSecondLevel = (String) saml.getStatus().getStatusCodeSecondLevel();
					if (_bankidSecondLevelStatusSuccess.equals(statusSecondLevel)) {
						resultCode = Errors.ERROR_ASELECT_SUCCESS;
					} else {
						resultCode = Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED;
						_systemLogger.log(Level.WARNING, MODULE, sMethod, statusSecondLevel);
					}
				} else {
					resultCode = Errors.ERROR_ASELECT_AUTHSP_ACCESS_DENIED;
					// set other statuscodes here
					_systemLogger.log(Level.WARNING, MODULE, sMethod, statusFirstLevel);
					// do not throw exception yet
					// throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
				}
			}
//			String sServerId = (String) htSessionContext.get("a-select-server");
			String sUid = null;
			String sBetrouwbaarheidsniveau = (String) htSessionContext.get("betrouwbaarheidsniveau");
			if (sBetrouwbaarheidsniveau == null)
//				sBetrouwbaarheidsniveau = (String) htSessionContext.get("authsp_level"); // if not DigiD
			// idin does not deliver a sort of "level"
			// for now we use the requested level
				sBetrouwbaarheidsniveau = String.valueOf(intLevel);	// level is int
			
			
//			String sRid = (String) htSessionContext.get("rid");
			String sOrganization = (String) htSessionContext.get("organization");
			String sAuthsp = (String) htSessionContext.get("authsp");
						
			//
			// Also match sBetrouwbaarheidsniveau against the requested level
			//
			Integer reqLevel = -1, idinLevel = -1;
			if (sBetrouwbaarheidsniveau != null) {
				idinLevel = Integer.parseInt(sBetrouwbaarheidsniveau);
				reqLevel = Integer.parseInt(sReqLevel);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "idinLevel=" + idinLevel + " reqLevel=" + reqLevel);
				if (idinLevel < reqLevel) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "IDIN LEVEL NOT HIGH ENOUGH (config error)");
					throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
				}
			}
			// We should also verify trxid and possibly ec here
//			if ((resultCode != null) && (sUid != null) && sServerId != null && sBetrouwbaarheidsniveau != null
//					&& (sRid != null) && (sServerId.equals(_sASelectAuthSPServerId)) && (sRid.equals(sLocalRid))
//					&& (digidLevel >= reqLevel) && (resultCode.equals(Errors.ERROR_ASELECT_SUCCESS))) {
			if ( (resultCode != null) && sBetrouwbaarheidsniveau != null 
					 && (resultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) ) {
				// Bauke: not sure which one it should be: user_id / uid
//				result.put("uid", sUid);
//				result.put("user_id", sUid);
				result.put("betrouwbaarheidsniveau", sBetrouwbaarheidsniveau);
				// 20100106, added, but can be overwritten later by the level from the AuthSp configuration
				result.put("authsp_level", sBetrouwbaarheidsniveau);
				result.put("sel_level", sBetrouwbaarheidsniveau);  // 20100321, Bauke: added the level selected by the user

				result.put("authsp", sAuthsp);
				result.put("organisation", sOrganization);
				
				result.put("ec", ec);  // idin specific
				result.put("trxid", trxid);  // idin specific
				
//				Utils.copyHashmapValue("attributes", result, response);
//				_systemLogger.log(Level.INFO, MODULE, sMethod, "Copy attributes=" + result.get("attributes"));
				
//				Object oAttributes = response.get("attributes");
				Map<String,String> oAttributes = saml.getAttributes();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Set attributes=" + Auxiliary.obfuscate( (oAttributes.toString()) ));
				if (oAttributes != null) {
					result.put("attributes", Utils.serializeAttributes(oAttributes));
					sUid = oAttributes.get(_bankidConsumerBinAttribute);
					result.put("uid", sUid);
					result.put("user_id", sUid);
				}
				_authenticationLogger.log(new Object[] {
					MODULE, Auxiliary.obfuscate(sUid), htResponse.get("client_ip"), sOrganization, sLocalAppId, "granted"
				});
			}
			else {
				// find out what code resolves to Cancel
//				resultCode = ("0040".equals(resultCode)) ? Errors.ERROR_ASELECT_SERVER_CANCEL
//						: Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
				_authenticationLogger.log(new Object[] {
					MODULE, Auxiliary.obfuscate(sUid), htResponse.get("client_ip"), sOrganization, sLocalAppId, "denied", resultCode
				});
			}
			result.put("rid", sLocalRid);
			result.put("authsp_type", "idin");
			result.put("result", resultCode);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "result=" + resultCode);
		}
		catch (ASelectException e) {  // do not throw an exception
			result.put("result", e.getMessage());
		}
		return result;
	}
	
	
}
