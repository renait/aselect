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

import java.io.StringReader;
//import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

//import org.apache.xml.serialize.OutputFormat;
//import org.apache.xml.serialize.XMLSerializer;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SoapManager;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

// Can only be used by an SP
public class SessionSyncRequestSender
{
	private TGTManager _oTGTManager = TGTManager.getHandle();
	protected ASelectConfigManager _configManager;
	private static final String RESPONSE = "Response";
	private final String _AuthzDecisionStatement = "AuthzDecisionStatement";

	private String _sRedirectUrl;
	private String _sFederationUrl;
	private long _lUpdateInterval;
	private String _sSamlMessageType;

	private ASelectSystemLogger _oSystemLogger;
	private final String MODULE = "SessionSyncRequestSender";
//	private PublicKey _pkey = null;
	private List <PublicKey> _pkeys = null;
	// RM_56_01
	private Long _maxNotBefore = null;
	private Long _maxNotOnOrAfter = null;
	private boolean _checkValidityInterval = false;

	private static HashMap<String, Object> htSessionSyncParameters = null;

	// For backward compatibility
	/**
	 * Instantiates a new session sync request sender.
	 * 
	 * @param systemLogger
	 *            the system logger
	 * @param redirectUrl
	 *            the redirect url
	 * @param updateInterval
	 *            the update interval
	 * @param samlMessageType
	 *            the saml message type
	 * @param federationUrl
	 *            the federation url
	 */
	public SessionSyncRequestSender(ASelectSystemLogger systemLogger, String redirectUrl, long updateInterval,
			String samlMessageType, String federationUrl) {
		this(systemLogger, redirectUrl, updateInterval, samlMessageType, federationUrl, null);
	}

	// For backward compatibility
	/**
	 * Instantiates a new session sync request sender.
	 * 
	 * @param systemLogger
	 *            the system logger
	 * @param redirectUrl
	 *            the redirect url
	 * @param updateInterval
	 *            the update interval
	 * @param samlMessageType
	 *            the saml message type
	 * @param federationUrl
	 *            the federation url
	 * @param pkey
	 *            the pkey
	 */
	public SessionSyncRequestSender(ASelectSystemLogger systemLogger, String redirectUrl, long updateInterval,
			String samlMessageType, String federationUrl, List <PublicKey> pkeys) {
		this(systemLogger, redirectUrl, updateInterval, samlMessageType, federationUrl, pkeys, null, null, false);
	}

	/**
	 * Instantiates a new session sync request sender.
	 * 
	 * @param systemLogger
	 *            the system logger
	 * @param redirectUrl
	 *            the redirect url
	 * @param updateInterval
	 *            the update interval
	 * @param samlMessageType
	 *            the saml message type
	 * @param federationUrl
	 *            the federation url
	 * @param pkey
	 *            the pkey
	 * @param maxNotBefore
	 *            the max not before
	 * @param maxNotOnOrAfter
	 *            the max not on or after
	 * @param checkValidityInterval
	 *            the check validity interval
	 */
	public SessionSyncRequestSender(ASelectSystemLogger systemLogger, String redirectUrl, long updateInterval,
			String samlMessageType, String federationUrl, List<PublicKey> pkeys, Long maxNotBefore, Long maxNotOnOrAfter,
			boolean checkValidityInterval) {
		String sMethod = "SessionSyncRequestSender";

		_oSystemLogger = systemLogger;
		_sRedirectUrl = redirectUrl;
		_lUpdateInterval = updateInterval;
		_sSamlMessageType = samlMessageType;
		_sFederationUrl = federationUrl;
		_pkeys = pkeys;

		_maxNotBefore = maxNotBefore;
		_maxNotOnOrAfter = maxNotOnOrAfter;
		_checkValidityInterval = checkValidityInterval;
		_oSystemLogger.log(Level.INFO, MODULE, sMethod, "Url=" + _sFederationUrl + " _pkeys:" + getPkeys()
				+ " _maxNotBefore:" + get_maxNotBefore() + "_maxNotOnOrAfter:" + get_maxNotOnOrAfter()
				+ "_checkValidityInterval:" + is_checkValidityInterval());
	}

	//
	// Retrieve the Session Sync parameters from the "saml20_sp_session_sync" section
	//
	/**
	 * Gets the session sync parameters.
	 * 
	 * @param mySystemLogger
	 *            the my system logger
	 * @return the session sync parameters
	 * @throws ASelectException
	 *             the a select exception
	 */
	static public HashMap getSessionSyncParameters(ASelectSystemLogger mySystemLogger)
	throws ASelectException
	{
		String MODULE = "SessionSyncRequestSender";
		String sMethod = "getSessionSyncParameters";
		ASelectConfigManager myConfigManager = ASelectConfigManager.getHandle();
		if (htSessionSyncParameters != null)
			return htSessionSyncParameters;

		try {
			Object oRequestsSection = myConfigManager.getSection(null, "requests");
			Object oHandlersSection = myConfigManager.getSection(oRequestsSection, "handlers");

			// 20090304, Bauke: cache the results in htSessionSyncParameters
			// Not present yet, so get the parameters
			htSessionSyncParameters = new HashMap<String, Object>();
			mySystemLogger.log(Level.INFO, MODULE, sMethod, "Scan handlers");
			Object oHandler = myConfigManager.getSection(oHandlersSection, "handler");
			for (; oHandler != null;) {
				try {
					String sId = myConfigManager.getParam(oHandler, "id");
					mySystemLogger.log(Level.FINEST, MODULE, sMethod, "Scan handler " + sId);
					if (sId.equals("saml20_sp_session_sync")) {
						// String sFederationUrl = ASelectConfigManager.getSimpleParam(oHandler, "federation_url", true);
						// htSessionSyncParameters.put("federation_url", sFederationUrl); // 20091030: backward compat

						String _sUpdateInterval = ASelectConfigManager.getSimpleParam(oHandler, "update_interval", true);
						Long updateInterval = Long.parseLong(_sUpdateInterval);
						updateInterval = updateInterval * 1000;
						mySystemLogger.log(Level.INFO, MODULE, sMethod, "Update interval on SP = " + updateInterval);
						htSessionSyncParameters.put("update_interval", updateInterval);

						String samlMessageType = ASelectConfigManager.getSimpleParam(oHandler, "message_type", true);
						htSessionSyncParameters.put("message_type", samlMessageType);

						String verify_signature = ASelectConfigManager.getSimpleParam(oHandler, "verify_signature", false);
						htSessionSyncParameters.put("verify_signature", (verify_signature == null) ? "false": verify_signature);

						String verify_interval = ASelectConfigManager.getSimpleParam(oHandler, "verify_interval", false);
						htSessionSyncParameters.put("verify_interval", (verify_interval == null) ? "false": verify_interval);

						String max_notbefore = ASelectConfigManager.getSimpleParam(oHandler, "max_notbefore", false);
						if (max_notbefore != null) {
							max_notbefore = (new Long(Long.parseLong(max_notbefore) * 1000)).toString();
							htSessionSyncParameters.put("max_notbefore", max_notbefore);
						}

						String max_notonorafter = ASelectConfigManager.getSimpleParam(oHandler, "max_notonorafter", false);
						if (max_notonorafter != null) {
							max_notonorafter = (new Long(Long.parseLong(max_notonorafter) * 1000)).toString();
							htSessionSyncParameters.put("max_notonorafter", max_notonorafter);
						}
					}
				}
				catch (ASelectConfigException e) {
					mySystemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'id' config item found", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
				oHandler = myConfigManager.getNextSection(oHandler);
			}
		}
		catch (ASelectConfigException e) {
			mySystemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'handler' found in 'aselect' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		return htSessionSyncParameters;
	}

	// Bauke: rewritten
	// Returns: ERROR_ASELECT_SUCCESS or error code upon failure
	//
	/**
	 * Synchronize session.
	 * 
	 * @param sTgT
	 *            the TGT key
	 * @param htTGTContext
	 *            the tgt context
	 * @param updateTgt
	 *            also update the ticket?
	 * @return successful?
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String synchronizeSession(String sTgT, HashMap<String, Object> htTGTContext, boolean updateTgt)
	throws ASelectException
	{
		String _sMethod = "synchronizeSession";
		boolean bTgtUpdated = false;

		// 20090811, Bauke: Only saml20 needs this type of session sync
		String sAuthspType = (String) htTGTContext.get("authsp_type");
		if (sAuthspType == null || !sAuthspType.equals("saml20"))
			return Errors.ERROR_ASELECT_SUCCESS;

		Long now = new Date().getTime();
		String ssTime = (String) htTGTContext.get("sessionsynctime");
		Long lastSync = (ssTime == null) ? -1 : Long.parseLong(ssTime);
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "update_interval=" + _lUpdateInterval + " LastSync="
				+ (lastSync - now) + " Left=" + (lastSync + _lUpdateInterval - now));

		if (ssTime == null) {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - Session Sync NOT ACTIVATED (no TimeOut handler?)");
		}
		else if (now >= lastSync + _lUpdateInterval) {
			// Session Sync needed
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - Session Sync, type=" + _sSamlMessageType + " now="+now);
			String sNameID = (String) htTGTContext.get("name_id");
			if (sNameID != null) {
				boolean success = false;
				try {
					if (_sSamlMessageType.equals("xacml"))
						success = sendXACMLMessageToFederation(sNameID, sTgT);
					else
						success = sendSAMLUpdateToFederation(sNameID, sTgT);
				}
				catch (ASelectException e) {
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}

				if (!success) { // don't continue
					_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to send update to federation");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				}
				// success
			}
			else {
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "No user found with credentials=" + sTgT);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_SESSION);
			}

			// If successful, update the ticket granting ticket (timestamp will be set to "now")
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Update TGT sessionsynctime=" + now);
			htTGTContext.put("sessionsynctime", Long.toString(now));
			// Setting "updatetimestamp" prevents the regular Timestamp update
			htTGTContext.put("updatetimestamp", "no");
			_oTGTManager.updateTGT(sTgT, htTGTContext);
			bTgtUpdated = true;
		}
		else {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "SP - No SessionSync Yet");
		}
		
		// Update when requested by caller and not done here yet
		if (!bTgtUpdated && updateTgt) { // updates at least the timestamp
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Update TICKET context=" + Auxiliary.obfuscate(htTGTContext));
			_oTGTManager.updateTGT(sTgT, htTGTContext);
		}
		return Errors.ERROR_ASELECT_SUCCESS;
	}

	/**
	 * Build a SAML message and sent it to the federation.
	 * 
	 * @param sNameID
	 *            the s name id
	 * @param sTgT
	 *            the s tg t
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
	@SuppressWarnings("unchecked")
	private boolean sendSAMLUpdateToFederation(String sNameID, String sTgT)
	throws ASelectException
	{
		String _sMethod = "sendSAMLUpdateToFederation";
		TGTManager tgtmanager = TGTManager.getHandle();	// RH, 20190325, n

		// Build AuthzDecisionQuery SAML
		XMLObjectBuilderFactory oBuilderFactory = Configuration.getBuilderFactory();
		SAMLObjectBuilder<AuthzDecisionQuery> authzBuilder = (SAMLObjectBuilder<AuthzDecisionQuery>) oBuilderFactory
				.getBuilder(AuthzDecisionQuery.DEFAULT_ELEMENT_NAME);
		AuthzDecisionQuery authz = authzBuilder.buildObject();

		// Build Subject
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();

		// Build NameID
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(sNameID);
		subject.setNameID(nameId);
		// Build SubjectConfirmation
		SAMLObjectBuilder<SubjectConfirmation> confirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) oBuilderFactory
				.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation sconf = confirmationBuilder.buildObject();

		sconf.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

		// Build SubjectConfirmationData
		SAMLObjectBuilder<SubjectConfirmationData> confirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) oBuilderFactory
				.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData sconfdata = confirmationDataBuilder.buildObject();
		SamlTools.setValidityInterval(sconfdata, new DateTime(), get_maxNotBefore(), get_maxNotOnOrAfter());
		sconfdata.setRecipient(_sFederationUrl);

		// Add validityInterval data to the subject
		sconf.setSubjectConfirmationData(sconfdata);
		subject.getSubjectConfirmations().add(sconf);

		// Build Action
		SAMLObjectBuilder<Action> actionBuilder = (SAMLObjectBuilder<Action>) oBuilderFactory
				.getBuilder(Action.DEFAULT_ELEMENT_NAME);
		Action action = actionBuilder.buildObject();
		action.setAction(Action.HTTP_GET_ACTION);

		List<Action> actions = authz.getActions();
		actions.add(action);

		// Build Issuer
		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "sp url: " + _sRedirectUrl);
		issuer.setValue(_sRedirectUrl);

		// Fill Authz obj
		authz.setVersion(SAMLVersion.VERSION_20);
		authz.setSubject(subject);
		authz.setID(SamlTools.generateIdentifier(_oSystemLogger, MODULE));
		authz.setIssueInstant(new DateTime());
		authz.setResource(_sFederationUrl);
		authz.setIssuer(issuer);

		// RH, 20180918, sn
		PartnerData partnerData = null;
		PartnerData.Crypto specificCrypto = null;
		try {
//			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sFederationUrl);	// RH, 20190325, o
			// RH, 20190325, sn
			// We must get the resourcegroup from the tgt
			HashMap htTGTContext = tgtmanager.getTGT(sTgT);
			String resourceGroup = null;
			if (htTGTContext != null) {
				resourceGroup = (String) htTGTContext.get("federation_group");
			}
			partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(resourceGroup, _sFederationUrl);	
			// RH, 20190325, en
			if (partnerData != null) {
				specificCrypto = partnerData.getCrypto();	// might be null
			}
		} catch (ASelectException e1) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Could not get handle to MetaDataManagerSp, not signing with specific private key");
		}
		// RH, 20180918, en
		
		// Sign the sessionsync
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Sign the sessionSync >======");
//		authz = (AuthzDecisionQuery) SamlTools.signSamlObject(authz);	// RH, 20180918, o
		authz = (AuthzDecisionQuery) SamlTools.signSamlObject(authz, specificCrypto);	// RH, 20180918, n
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Signed the sessionSync ======<");

		SAMLObject saml = authz;
		SoapManager soapmanager = new SoapManager();

		// Build the SOAP message
		Envelope envelope = soapmanager.buildSOAPMessage(saml);
		Element envelopeElem = null;
		try {
			envelopeElem = SamlTools.marshallMessage(envelope);
		}
		catch (MessageEncodingException e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "MessageEncodingException!", e);
			e.printStackTrace();
		}
		_oSystemLogger.log(Level.FINEST, MODULE, _sMethod, "FederationUrl=" + _sFederationUrl + " SOAP message:"
				+ Auxiliary.obfuscate(XMLHelper.nodeToString(envelopeElem), Auxiliary.REGEX_PATTERNS));
		return sendMessageToFederation(XMLHelper.nodeToString(envelopeElem), sNameID, sTgT);
	}

	/*
	 * Methode haalt de timestamp van de tgt op aan de hand van de meegegeven credentials.
	 */
	/*
	 * private long getTimeStamp(String credentials) throws ASelectStorageException { String _sMethod = "getTimeStamp";
	 * HashMap htTGT = null; Long setTime = 0L; // get time from tgt manager if (_oTGTManager.containsKey(credentials))
	 * { htTGT = (HashMap) _oTGTManager.get(credentials); setTime = (Long) htTGT.get("lastsync"); if (setTime == null) {
	 * _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "CIO - lastsync was not set!"); setTime =
	 * _oTGTManager.getTimestamp(credentials); } long expireTime = _oTGTManager.getExpirationTime(credentials);
	 * _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Timestamp = " + setTime + "(" + this.getReadableDate(setTime) +
	 * ")"); _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Expire Time = " + expireTime + "(" +
	 * this.getReadableDate(expireTime) + ")"); } else { _oSystemLogger.log(Level.INFO, MODULE, _sMethod,
	 * "There is no TGT with key " + credentials); } return setTime; }
	 */
	/*
	 * Methode haalt aan de hand van de credentials de betreffende uid op.
	 */
	/*
	 * private String getUser(String credentials) { String _sMethod = "getUser"; String user = null; try { // get time
	 * from tgt manager String decodedCredentials = decodeCredentials(credentials); if
	 * (_oTGTManager.containsKey(decodedCredentials)) { HashMap hash = (HashMap) _oTGTManager.get(decodedCredentials);
	 * user = (String) hash.get("uid"); _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "User = " + user); } } catch
	 * (ASelectStorageException asse) { _oSystemLogger.log(Level.WARNING, MODULE, _sMethod,
	 * "fails to get user from TGT manager", asse); } return user; }
	 */
	/**
	 * Destroy.
	 */
	public void destroy()
	{
	}

	/*
	 * Build a XACML message and send it to the federation. NOTE: no signing takes place
	 */
	/**
	 * Send xacml message to federation.
	 * 
	 * @param user
	 *            the user
	 * @param sTgT
	 *            the s tg t
	 * @return true, if successful
	 */
	private boolean sendXACMLMessageToFederation(String user, String sTgT)
	{
		String _sMethod = "sendXACMLMessageToFederation";
		String action = "GET";
		String var1 = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
		String var2 = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
		String var6 = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
		String var7 = "http://www.w3.org/2001/XMLSchema#anyURI";
		String var8 = "urn:oasis:names:tc:xacml:1.0:action:action-id";
		String var9 = "http://www.w3.org/2001/XMLSchema#string";

		String xacmlRequest = "<soap:Envelope xmlns:xsi=\" http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\" http://schemas.xmlsoap.org/soap/envelope/\">"
				+ "<soap:Body>" + "<Request>" + "<Subject>" + "<Attribute AttributeId=\""
				+ var1
				+ "\""
				+ " DataType=\""
				+ var2
				+ "\">"
				+ "<AttributeValue>"
				+ user
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Subject>"
				+ "<Resource>"
				+ "<Attribute AttributeId=\""
				+ var6
				+ "\""
				+ " DataType=\""
				+ var7
				+ "\">"
				+ "<AttributeValue>"
				+ _sRedirectUrl
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Resource>"
				+ "<Action>"
				+ "<Attribute AttributeId=\""
				+ var8
				+ "\""
				+ " DataType=\""
				+ var9
				+ "\">"
				+ "<AttributeValue>"
				+ action
				+ "</AttributeValue>"
				+ "</Attribute>"
				+ "</Action>" + "</Request>" + "</soap:Body>" + "</soap:Envelope>";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send message: " + xacmlRequest);
		return sendMessageToFederation(xacmlRequest, user, sTgT);
	}

	/**
	 * Send message to federation.
	 * 
	 * @param message
	 *            the message
	 * @param sNameID
	 *            the s name id
	 * @param sTgT
	 *            the s tg t
	 * @return true
	 * 		if the Message was sent successful
	 */
	private boolean sendMessageToFederation(String message, String sNameID, String sTgT)
	{
		String _sMethod = "sendMessageToFederation";
		SoapManager soapmanager = new SoapManager();
		TGTManager tgtmanager = TGTManager.getHandle();
		String sResponse = "";
		boolean tgtKilled = false;
		boolean saml = false;

		try {
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Send message for " + sNameID + " to " + _sFederationUrl);
			// Send/Receive the SOAP message
			sResponse = soapmanager.sendSOAP(message, _sFederationUrl /* set in the creator */);
			// 20090624: don't: sResponse = URLDecoder.decode(soapmanager.sendSOAP(message, _sFederationUrl), "UTF-8");
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Received response from IDP: " + sResponse);
			try {
				saml = determineMessageType(sResponse);
			}
			catch (ASelectException e) {  // Bad or no response from partner
				_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for " + sNameID);
				tgtmanager.remove(sTgT);
				return false; // Bauke: no need to continue
			}
			if (saml) {
				tgtKilled = handleSAMLResponse(sResponse);
				if (tgtKilled == true) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "RESPONSE is correct no need to kill tgt");
					return true;
				}
				else {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "RESPONSE not correct)");
					String samlNameID = getNameIdFromSAMLResponse(sResponse);
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for " + samlNameID);
					tgtmanager.remove(sTgT);
					return false;
				}
			}
			else {
				tgtKilled = handleXACMLResponse(sResponse);
				if (tgtKilled == true) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "RESPONSE is correct no need to kill tgt");
					return true;
				}
				else {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod,
							"RESPONSE contains deny (IDP has not processed update correct)");
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for " + sNameID);
					tgtmanager.remove(sTgT);
					return false;
				}
			}
		}
		catch (Exception ex) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to send message to federation", ex);
		}
		return false;
	}

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde gegevens uit het bericht.
	 */
	/**
	 * Handle saml response.
	 * 
	 * @param sMessage
	 *            the s message
	 * @return true, if successful
	 */
	private boolean handleSAMLResponse(String sMessage)
	{

		String _sMethod = "handleSAMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process SAML message");
		Response response = null;
		try {
			// Build XML Document
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_oSystemLogger);
			dbFactory.setNamespaceAware(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedResponse = builder.parse(inputSource);

			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Get AuthzDecision");
			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedResponse.getDocumentElement();
			Node eltArtifactResolve = SamlTools.getNode(elementReceivedSoap, RESPONSE);

			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Unmarshall " + eltArtifactResolve);
			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			response = (Response) unmarshaller.unmarshall((Element) eltArtifactResolve);
			if (getPkeys() != null) { // If pkey supplied from calling method then check signature
				if (SamlTools.checkSignature(response, getPkeys())) {
					_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "response was signed OK");
				}
				else {
					_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "response was NOT signed OK");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			else {
				_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "No signature verification required on response");
			}
			_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "_checkValidityInterval:" + is_checkValidityInterval());

			if (is_checkValidityInterval()) {
				if (!SamlTools.checkValidityInterval(response)) {
					_oSystemLogger.log(Level.SEVERE, MODULE, _sMethod, "response validity interval was NOT valid");
					throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
				}
			}
			else { // RH, 20080717, sn
				_oSystemLogger.log(Level.WARNING, MODULE, _sMethod,
						"No validity interval verification required on response");
			} // RH, 20080717, en
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to process SAML message", e);
			return false;
		}
		boolean updateWasSucces = true;
		List lijst = response.getAssertions();
		if (lijst.size() == 1) {
			Assertion assertion = (Assertion) lijst.get(0);
			// RM_56_02
			// object wants us to verify (from aselect.xml), this is (for the moment) only known
			// by the calling object
			List authzLijst = assertion.getAuthzDecisionStatements();
			if (authzLijst.size() == 1) {
				AuthzDecisionStatement authz = (AuthzDecisionStatement) authzLijst.get(0);
				DecisionTypeEnumeration decision = authz.getDecision();
				if (decision.toString().equals("Deny")) {
					_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "SAML message contains \"Deny\"");
					updateWasSucces = false;
				}
			}
		}
		return updateWasSucces;
	}

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde gegevens uit het bericht.
	 */
	/**
	 * Handle xacml response.
	 * 
	 * @param sMessage
	 *            the s message
	 * @return true, if successful
	 */
	private boolean handleXACMLResponse(String sMessage)
	{

		String _sMethod = "handleXACMLResponse";
		_oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Process XACML message");
		Document docReceivedResponse = null;
		try {
			// Build XML Document
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_oSystemLogger);
			dbFactory.setNamespaceAware(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			docReceivedResponse = builder.parse(inputSource);
		}
		catch (Exception ex) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to build Document", ex);
			return false;
		}

		Node node = docReceivedResponse.getFirstChild();
		String decision = SamlTools.getNode(node, "Decision").getTextContent();

		boolean updateWasSucces = true;
		if (decision.equals("Deny")) {
			updateWasSucces = false;
		}
		return updateWasSucces;
	}

	/**
	 * Determine message type.
	 * 
	 * @param request
	 *            the request
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
	private boolean determineMessageType(String request)
	throws ASelectException
	{
		String _sMethod = "determineMessageType";
		boolean saml = true;
		try {
			// Build XML Document
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_oSystemLogger);
			dbFactory.setNamespaceAware(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(request);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedSoap = builder.parse(inputSource);

			// print document
			// RH, 20210930, so
//			// Serialize the document
//			OutputFormat format = new OutputFormat(docReceivedSoap);
//			format.setLineWidth(65);
//			format.setIndenting(true);
//			format.setIndent(2);
//			XMLSerializer serializer = new XMLSerializer(System.out, format);
//			serializer.serialize(docReceivedSoap);
			// RH, 20210930, eo

			// RH, 20210930, sn
			String sDoc = XMLHelper.prettyPrintXML(docReceivedSoap);
			_oSystemLogger.log(Level.FINEST, MODULE, _sMethod, "docReceivedSoap: " + Auxiliary.obfuscate(sDoc));
			// RH, 20210930, en

			// Get AuthzDecision obj

			Node node = docReceivedSoap.getFirstChild();
			Node doesAuthzExist = SamlTools.getNode(node, _AuthzDecisionStatement);
			if (doesAuthzExist == null) {
				saml = false;
			}
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed to determine message", e);
			throw new ASelectException("Cannot determine message type");
		}
		return saml;
	}

	/*
	 * Methode killt de tgt aan de hand van een deny response.
	 */
	/*
	 * private void killTgt(String uid) throws ASelectStorageException { String _sMethod = "killTgt"; TGTManager
	 * tgtmanager = TGTManager.getHandle(); _oSystemLogger.log(Level.INFO, MODULE, _sMethod, "Kill tgt for user: " +
	 * uid); tgtmanager.remove(UserToTgtMapper.getTgtId(uid)); _oSystemLogger.log(Level.INFO, MODULE, _sMethod,
	 * "Does sp contain uid?: " + tgtmanager.containsKey(UserToTgtMapper.getTgtId(uid))); }
	 */

	/*
	 * Deze methode vangt het SAML bericht op van de IDP en haalt de benodigde gegevens uit het bericht.
	 */
	/**
	 * Gets the name id from saml response.
	 * 
	 * @param sMessage
	 *            the s message
	 * @return the name id from saml response
	 */
	private String getNameIdFromSAMLResponse(String sMessage)
	{

		String _sMethod = "getUserFromSAMLResponse";
		String sNameID = null;
		Response response = null;
		try {
			// Build XML Document
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_oSystemLogger);
			dbFactory.setNamespaceAware(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			DocumentBuilder builder = dbFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(sMessage);
			InputSource inputSource = new InputSource(stringReader);
			Document docReceivedResponse = builder.parse(inputSource);

			// Get AuthzDecision obj
			Element elementReceivedSoap = docReceivedResponse.getDocumentElement();
			Node eltArtifactResolve = SamlTools.getNode(elementReceivedSoap, RESPONSE);

			// Unmarshall to the SAMLmessage
			UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller((Element) eltArtifactResolve);
			response = (Response) unmarshaller.unmarshall((Element) eltArtifactResolve);
		}
		catch (Exception e) {
			_oSystemLogger.log(Level.WARNING, MODULE, _sMethod, "Failed too process SAML message", e);
			e.printStackTrace();
		}

		List lijst = response.getAssertions();
		if (lijst.size() == 1) {
			Assertion assertion = (Assertion) lijst.get(0);
			// RM_56_03
			// object wants us to verify (from aselect.xml), this is (for the moment) only known
			// by the calling object

			Subject subject = assertion.getSubject();
			NameID nameid = subject.getNameID();
			sNameID = nameid.getValue();
		}
		return sNameID;
	}

	/**
	 * Gets the pkey.
	 * 
	 * @return the pkey
	 */
	public synchronized List <PublicKey> getPkeys()
	{
		return _pkeys;
	}

	/**
	 * Sets the pkey.
	 * 
	 * @param pkey
	 *            the new pkey
	 */
	public synchronized void setPkeys(List <PublicKey> pkeys)
	{
		this._pkeys = pkeys;
	}

	/**
	 * Checks if is _check validity interval.
	 * 
	 * @return true, if is _check validity interval
	 */
	public synchronized boolean is_checkValidityInterval()
	{
		return _checkValidityInterval;
	}

	/**
	 * Sets the _check validity interval.
	 * 
	 * @param validityInterval
	 *            the new _check validity interval
	 */
	public synchronized void set_checkValidityInterval(boolean validityInterval)
	{
		_checkValidityInterval = validityInterval;
	}

	/**
	 * Gets the _max not before.
	 * 
	 * @return the _max not before
	 */
	public synchronized Long get_maxNotBefore()
	{
		return _maxNotBefore;
	}

	/**
	 * Sets the _max not before.
	 * 
	 * @param notBefore
	 *            the new _max not before
	 */
	public synchronized void set_maxNotBefore(Long notBefore)
	{
		_maxNotBefore = notBefore;
	}

	/**
	 * Gets the _max not on or after.
	 * 
	 * @return the _max not on or after
	 */
	public synchronized Long get_maxNotOnOrAfter()
	{
		return _maxNotOnOrAfter;
	}

	/**
	 * Sets the _max not on or after.
	 * 
	 * @param notOnOrAfter
	 *            the new _max not on or after
	 */
	public synchronized void set_maxNotOnOrAfter(Long notOnOrAfter)
	{
		_maxNotOnOrAfter = notOnOrAfter;
	}
}
