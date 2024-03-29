/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 * Generic abstract request handler to support different protocols
 * Currently also collects methods that should go to a more general library (like system)
 */
package org.aselect.server.request.handler;

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

//import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.security.signature.XMLSignature;
import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.idp.MetaDataManagerIdp;
import org.aselect.server.session.SessionManager;
import org.aselect.server.tgt.TGTIssuer;
import org.aselect.server.tgt.TGTManager;
import org.aselect.server.utils.AttributeSetter;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSubject;
import org.opensaml.common.SignableSAMLObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.validation.ValidationException;

//
//
//
public abstract class ProtoRequestHandler extends AbstractRequestHandler
{
	public final static String MODULE = "ProtoRequestHandler";
	protected final static String DEFAULT_CHARSET = "UTF8";
	protected TGTManager _tgtManager;
	protected Saml11Builder _saml11Builder = null;
	protected String _sASelectServerID;
	protected String _sASelectOrganization;
	protected String _sFriendlyName = "";
	protected String _sServerUrl;

	protected Vector _vIdPUrls;
	protected HashMap _htIdPs;
	
//	protected boolean _bCheckClientIP = false;	// RH, 20161101, n	// RH, 20180517, o
	

	// The local version of the session,
	// it functions as a local cache. Updates are done in the local cache,
	// and saved to storage at the end of the handler's life time
	// The entry "status" in the session maintains the action to be taken.
	// Also the "rid" value is stored in the session, while locally cached.
	// Both values will be removed before storing the session.
	protected HashMap _htSessionContext = null;

	// Localization
	protected String _sUserLanguage = "";
	protected String _sUserCountry = "";

	protected LinkedList<AttributeSetter> attributeSetters = new LinkedList<AttributeSetter>();	// RH, 20160301, n

	
	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		try {
			super.init(oServletConfig, oConfig);
			_tgtManager = TGTManager.getHandle();
			_sServerUrl = ASelectConfigManager.getParamFromSection(null, "aselect", "redirect_url", true);
			_sASelectServerID = ASelectConfigManager.getParamFromSection(null, "aselect", "server_id", true);
			_sASelectOrganization = ASelectConfigManager.getParamFromSection(null, "aselect", "organization", true);
			_sFriendlyName = ASelectConfigManager.getParamFromSection(null, "aselect", "organization_friendly_name", true);

			// RH, 20161101, sn
			String sCheckClientIP = ASelectConfigManager.getParamFromSection(null, "aselect", "check_client_ip", false); 
			_bCheckClientIP = Boolean.parseBoolean(sCheckClientIP);
			// RH, 20161101, en

			// Initialize assertion building, if needed
			if (useConfigToCreateSamlBuilder())
				_saml11Builder = createSAML11Builder(oConfig, getSessionIdPrefix());
			else
				_saml11Builder = new Saml11Builder(); // object only
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		
		// RH, 20160301, sn
		AttributeSetter.initAttributesConfig(_configManager, oConfig, attributeSetters, _systemLogger);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "attributeSetters size="+attributeSetters.size());
		// RH, 20160301, en

	}

	// To be overridden
	/**
	 * Serialize these attributes.
	 * 
	 * @param htAttribs
	 *            the ht attribs
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String serializeTheseAttributes(HashMap htAttribs)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, MODULE, "serializeTheseAttributes", "No OVERRIDE for this method!!");
		return "";
	}

	// Default implementation
	// In Subclasses you can redefine this method:
	// - return false if you need a SamlBuilder object only
	// - return true if you also want to recognize config parameters:
	// <assertion expire="600"/>
	// <attribute namespace="..." send_statement="true"/>
	/**
	 * Use config to create saml builder.
	 * 
	 * @return true, if successful
	 */
	protected boolean useConfigToCreateSamlBuilder()
	{
		return false;
	}

	// Define the prefix used to create a RID-key
	// Default is an empty prefix
	/**
	 * Gets the session id prefix.
	 * 
	 * @return the session id prefix
	 */
	protected String getSessionIdPrefix()
	{
		return "";
	}

	// Look for the "aselect_credentials" cookie
	// Retrieve TGT and TGT Context
	// Gather attributes and copy them over the TGT Context Attributes
	// Return all data as Credentials
	//
	// Bauke 20081209: getCredentialsFromCookie now returns a string
	//
	/**
	 * Gets the a select credentials.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @return the a select credentials
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected HashMap getASelectCredentials(HttpServletRequest servletRequest)
	throws ASelectException
	{
		String sMethod = "getAselectCredentials";

		// Check for credentials that might be present
		String sTgt = getCredentialsFromCookie(servletRequest);

		if (sTgt == null)
			return null;

		HashMap htTGTContext = getContextFromTgt(sTgt, true); // Check expiration
		if (htTGTContext == null)
			return null;
		String sUserId = (String) htTGTContext.get("uid");
		if (sUserId == null)
			return null;

		String sRid = (String) htTGTContext.get("rid"); // Bauke: added
		if (sRid == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "tgt context sRid==null, returning null");
			return null;
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Gathering Attributes for sUserId=" + Auxiliary.obfuscate(sUserId) + " rid=" + sRid);

		// Gather attributes, but also use the attributes from the ticket context
		HashMap htAllAttributes = getAttributesFromTgtAndGatherer(htTGTContext);

		// And assemble the credentials
		HashMap htCredentials = new HashMap();
		htCredentials.put("rid", sRid);
		htCredentials.put("uid", sUserId);
		htCredentials.put("a-select-server", _sASelectServerID); // sServerId);
		htCredentials.put("tgt", sTgt);
		String sPar = (String) htTGTContext.get("tgt_exp_time");
		if (sPar != null)
			htCredentials.put("tgt_exp_time", sPar);
		sPar = (String) htTGTContext.get("app_id");
		if (sPar != null)
			htCredentials.put("app_id", sPar);
		sPar = (String) htTGTContext.get("organization");
		if (sPar != null)
			htCredentials.put("organization", sPar);
		sPar = (String) htTGTContext.get("app_level");
		if (sPar != null)
			htCredentials.put("app_level", sPar);
		sPar = (String) htTGTContext.get("authsp_level");
		if (sPar != null) {
			htCredentials.put("authsp_level", sPar);
			htAllAttributes.put("authsp_level", sPar);
		}
		sPar = (String) htTGTContext.get("authsp");
		if (sPar != null) htCredentials.put("authsp", sPar);

		// Bauke, 20081209 added for ADFS / WS-Fed
		String sPwreply = (String) htTGTContext.get("wreply");
		if (sPwreply != null)
			htCredentials.put("wreply", sPwreply);
		String sPwtrealm = (String) htTGTContext.get("wtrealm");
		if (sPwtrealm != null)
			htCredentials.put("wtrealm", sPwtrealm);
		String sPwctx = (String) htTGTContext.get("wctx");
		if (sPwctx != null)
			htCredentials.put("wctx", sPwctx);

		// RH, 20180503, sn
		String sPwauth = (String) htTGTContext.get("wauth");
		if (sPwauth != null)
			htCredentials.put("wauth", sPwauth);
		// RH, 20180503, en

		// And put the attributes back where they belong
		String sSerializedAttributes = serializeTheseAttributes(htAllAttributes);
		if (sSerializedAttributes != null)
			htCredentials.put("attributes", sSerializedAttributes);
		htCredentials.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
		return htCredentials;
	}

	/**
	 * Gets the attributes from tgt and gatherer.
	 * 
	 * @param htTGTContext
	 *            the tgt context
	 * @return the attributes from tgt and gatherer
	 * @throws ASelectException
	 */
	public HashMap getAttributesFromTgtAndGatherer(HashMap htTGTContext)
	throws ASelectException
	{
		String sMethod = "getAttributesFromTgtAndGatherer";
		
		String sTgtAttributes = (String) htTGTContext.get("attributes");
		HashMap htTgtAttributes = org.aselect.server.utils.Utils.deserializeAttributes(sTgtAttributes);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Attributes from TGT-\"attributes\"=" + Auxiliary.obfuscate(htTgtAttributes));

		AttributeGatherer oAttributeGatherer = AttributeGatherer.getHandle();
		HashMap htAttribs = oAttributeGatherer.gatherAttributes(htTGTContext);
		if (htAttribs == null)
			htAttribs = new HashMap();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Attributes after Gathering=" + Auxiliary.obfuscate(htAttribs));
		// Can be empty, can contain multi-valued attributes in Vectors

		// Copy the gathered attributes over the ticket context attributes
		Set keys = htAttribs.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			htTgtAttributes.put(sKey, htAttribs.get(sKey));
		}
		return htTgtAttributes;
	}

	/**
	 * Gets the context from tgt.
	 * 
	 * @param sTgt
	 *            the s tgt
	 * @param checkExpiration
	 *            the check expiration
	 * @return the context from tgt
	 * @throws ASelectException
	 *             the a select exception
	 */
	public HashMap getContextFromTgt(String sTgt, boolean checkExpiration)
	throws ASelectException
	{
		String sMethod = "getContextFromTgt";
		TGTManager _tgtManager = TGTManager.getHandle();

		int len = sTgt.length();
		_systemLogger.log(Level.FINER, MODULE, sMethod, "getTGT(" + sTgt.substring(0, (len < 30) ? len : 30) + "...)");
		HashMap htTGTContext = _tgtManager.getTGT(sTgt);
		if (htTGTContext == null)
			return null;

		if (checkExpiration) {
			long lExpTime = 0;
			try {
				lExpTime = _tgtManager.getExpirationTime(sTgt);
			}
			catch (ASelectStorageException eAS) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not fetch TGT timeout", eAS);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
			}
			if (lExpTime <= System.currentTimeMillis()) { // TGT no longer valid
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "TGT expired");
				return null;
			}
			// Pass along as well
			htTGTContext.put("tgt_exp_time", new Long(lExpTime).toString());
		}
		return htTGTContext;
	}

	// Bauke 20081209: getCredentialsFromCookie now returns a string
	//
	/**
	 * Gets the credentials from cookie.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @return the credentials from cookie
	 */
	public String getCredentialsFromCookie(HttpServletRequest servletRequest)
	{
		String sMethod = "getCredentialsFromCookie";

		String sCredentialsCookie = HandlerTools.getCookieValue(servletRequest, "aselect_credentials", _systemLogger);
		if (sCredentialsCookie == null)
			return null;

		_systemLogger.log(Level.FINER, MODULE, sMethod, "sCredentialsCookie=" + sCredentialsCookie);
		/*
		 * Bauke, 20081209: Cookie only contains tgt-value HashMap htCredentialsParams =
		 * Utils.convertCGIMessage(sCredentialsCookie); _systemLogger.log(Level.INFO, MODULE, sMethod,
		 * "CredentialsParams="+htCredentialsParams); return htCredentialsParams;
		 */
		return sCredentialsCookie;
	}

	/**
	 * Read template from config.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sName
	 *            the s name
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected String readTemplateFromConfig(Object oConfig, String sName)
	throws ASelectException
	{
		String sMethod = "readTemplateFromConfig";
		String sTemplateName = null;
		try {
			sTemplateName = _configManager.getParam(oConfig, sName);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '" + sName + "' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		
		return Utils.loadTemplateFromFile(_systemLogger, _configManager.getWorkingdir(),
					_sUserLanguage, sTemplateName, null, _sFriendlyName, null/*version*/);
	}

	/*
	 * Read an xml config structure like: <authentication_method> <security level=5
	 * urn="urn:oasis:names:tc:SAML:1.0:cm:unspecified"> <security level=10
	 * urn="urn:oasis:names:tc:SAML:1.0:cm:password"> <security level=20 urn="urn:oasis:names:tc:SAML:1.0:cm:sms">
	 * <security level=30 urn="urn:oasis:names:tc:SAML:1.0:cm:smartcard"> </authentication_method>
	 */
	/**
	 * Gets the table from config.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param vAllKeys
	 *            the v all keys
	 * @param htAllKeys_Values
	 *            the ht all keys_ values
	 * @param sMainSection
	 *            the s main section
	 * @param sSubSection
	 *            the s sub section
	 * @param sKeyName
	 *            the s key name
	 * @param sValueName
	 *            the s value name
	 * @param mandatory
	 *            the mandatory
	 * @param uniqueValues
	 *            the unique values
	 * @return the table from config
	 * @throws ASelectException
	 *             the a select exception
	 * @throws ASelectConfigException
	 *             the a select config exception
	 *             
	 */
	protected void getTableFromConfig(Object oConfig, Vector vAllKeys, HashMap htAllKeys_Values, String sMainSection,
			String sSubSection, String sKeyName, String sValueName, boolean mandatory, boolean uniqueValues)
	throws ASelectException, ASelectConfigException
	{
		String sMethod = "getTableFromConfig";

		Object oProviders = null;
		try {
			oProviders = _configManager.getSection(oConfig, sMainSection);
		}
		catch (ASelectConfigException e) {
			if (!mandatory)
				return;
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config section '" + sMainSection + "' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		Object oProvider = null;
		try {
			oProvider = _configManager.getSection(oProviders, sSubSection);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not even one config section '" + sSubSection
					+ "' found in the '" + sMainSection + "' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		while (oProvider != null) {
			String sValue = null;
			try {
				sValue = _configManager.getParam(oProvider, sValueName);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '" + sValueName + "' found in '"
						+ sSubSection + "' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sKey = null;
			try {
				sKey = _configManager.getParam(oProvider, sKeyName);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item '" + sKeyName + "' found in '"
						+ sSubSection + "' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// Key must be unique
			if (htAllKeys_Values.containsKey(sKey)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Provider '" + sKeyName + "' is not unique: " + sKey);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			if (uniqueValues) {
				// Also check for unique values
				if (htAllKeys_Values.containsValue(sValue)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Provider '" + sValueName + "' isn't unique: "
							+ sValue);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
			}
			if (vAllKeys != null)
				vAllKeys.add(sKey);
			htAllKeys_Values.put(sKey, sValue);

			oProvider = _configManager.getNextSection(oProvider);
		}
	}

	/**
	 * Shows the main A-Select Error page with the appropriate errors. <br>
	 * <br>
	 * 
	 * @param sErrorCode
	 *            the s error code
	 * @param htSessionContext
	 *            the ht session context
	 * @param pwOut
	 *            the pw out
	 */
	protected void showErrorPage(String sErrorCode, HashMap htSessionContext, PrintWriter pwOut, HttpServletRequest request)
	{
		String sMethod = "showErrorPage";

		String sErrorMessage = _configManager.getErrorMessage(MODULE, sErrorCode, _sUserLanguage, _sUserCountry);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "FORM[error] " + sErrorCode + ":" + sErrorMessage);
		try {
			String sErrorForm = _configManager.getHTMLForm("error", _sUserLanguage, _sUserCountry);
			sErrorForm = Utils.replaceString(sErrorForm, "[error]", sErrorCode);  // obsoleted 20100817
			sErrorForm = Utils.replaceString(sErrorForm, "[error_code]", sErrorCode);
			sErrorForm = Utils.replaceString(sErrorForm, "[error_message]", sErrorMessage);
			sErrorForm = Utils.replaceString(sErrorForm, "[language]", _sUserLanguage);

			String sAppUrl = (String)htSessionContext.get("app_url");
			sErrorForm = Utils.handleAllConditionals(sErrorForm, Utils.hasValue(sErrorMessage), sAppUrl, _systemLogger);
			sErrorForm = _configManager.updateTemplate(sErrorForm, htSessionContext, request);
			Tools.pauseSensorData(_configManager, _systemLogger, htSessionContext);  //20111102
			pwOut.println(sErrorForm);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not display error page, error=" + sErrorCode, e);
		}
	}

	//
	// Present IdP choice to the user
	//
	/**
	 * Handle show form.
	 * 
	 * @param sTemplate
	 *            the s template
	 * @param sSelectedIdP
	 *            the s selected id p
	 * @param sAction
	 *            the s action
	 * @param sPassContext
	 *            the s pass context
	 * @param sReplyTo
	 *            the s reply to
	 * @param sCurrentTime
	 *            the s current time
	 * @param sAselectUrl
	 *            the s aselect url
	 * @param sRid
	 *            the s rid
	 * @param sAselectServer
	 *            the s aselect server
	 * @param servletResponse
	 *            the response
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void handleShowForm(String sTemplate, String sSelectedIdP, String sAction, String sPassContext,
			String sReplyTo, String sCurrentTime, String sAselectUrl, String sRid, String sAselectServer,
			HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handleShowForm";
		PrintWriter pwOut = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Form Action=" + sAction + " Context=" + sPassContext
				+ " ReplyTo=" + sReplyTo + " AselectUrl=" + sAselectUrl + " Rid=" + sRid + " Server=" + sAselectServer);

		try {
			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

			StringBuffer sbSelection = new StringBuffer();
			for (int i = 0; _vIdPUrls != null && i < _vIdPUrls.size(); i++) {
				String sURL = (String) _vIdPUrls.get(i);
				String sAlias = (String) _htIdPs.get(sURL);

				sbSelection.append("<OPTION VALUE=");
				sbSelection.append(sURL);

				if (sSelectedIdP != null && sURL.equals(sSelectedIdP))
					sbSelection.append(" SELECTED");

				sbSelection.append(">");
				sbSelection.append(sAlias);
				sbSelection.append("</OPTION>\n");
			}
			sTemplate = Utils.replaceString(sTemplate, "[form_action]", sAction);
			if (sReplyTo != null)
				sTemplate = Utils.replaceString(sTemplate, "[reply_to]", sReplyTo);
			if (sPassContext != null)
				sTemplate = Utils.replaceString(sTemplate, "[pass_context]", sPassContext);
			if (sCurrentTime != null)
				sTemplate = Utils.replaceString(sTemplate, "[current_time]", sCurrentTime);
			sTemplate = Utils.replaceString(sTemplate, "[options]", sbSelection.toString());

			// DigiD and local login
			sTemplate = Utils.replaceString(sTemplate, "[aselect_url]", sAselectUrl);
			sTemplate = Utils.replaceString(sTemplate, "[rid]", sRid);
			sTemplate = Utils.replaceString(sTemplate, "[a-select-server]", sAselectServer);

			_systemLogger.log(Level.FINER, MODULE, sMethod, "Form " + sTemplate);
			pwOut.print(sTemplate);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not show form", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}

	/**
	 * Handle post form.
	 * 
	 * @param sTemplate
	 *            the form template
	 * @param sAction
	 *            the action
	 * @param sInputLines
	 *            the input lines
	 * @param servletResponse
	 *            the response
	 * @throws ASelectException
	 */
	protected void handlePostForm(String sTemplate, String sAction, String sInputLines,
			HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ASelectException
	{
		String sMethod = "handlePostForm";
		PrintWriter pwOut = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "POST FORM: Action=" + sAction);

		try {
			sTemplate = Utils.replaceString(sTemplate, "[form_action]", sAction);
			sTemplate = Utils.replaceString(sTemplate, "[input_area]", sInputLines);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sTemplate=" + Utils.firstPartOf(sTemplate, 160));

			pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);
			pwOut.print(sTemplate);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not POST form", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			if (pwOut != null)
				pwOut.close();
		}
	}

	// No longer used
	/**
	 * Extract aselect server url.
	 * 
	 * @param request
	 *            the request
	 * @return the string
	 */
	protected String extractAselectServerUrl(HttpServletRequest request)
	{
		String sRequestURL = request.getRequestURL().toString();
		String sContextPath = request.getContextPath();
		int iLocation = sRequestURL.indexOf(sContextPath); // Initial URL part
		String sStartURL = sRequestURL.substring(0, iLocation);
		return sStartURL + sContextPath + request.getServletPath();
	}

	/**
	 * Perform authenticate request.
	 * 
	 * @param sASelectURL
	 *            the s a select url
	 * @param sPathInfo
	 *            the s path info
	 * @param sReturnSuffix
	 *            the s return suffix
	 * @param sAppId
	 *            the s app id
	 * @param checkSignature
	 *            the check signature
	 * @param iClientComm
	 *            the i client comm
	 * @return the hash map
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected HashMap<String, Object> performAuthenticateRequest(String sASelectURL, String sPathInfo, String sReturnSuffix,
			String sAppId, boolean checkSignature, IClientCommunicator iClientComm)
	throws ASelectException
	{
		String sMethod = "performAuthenticateRequest";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "AUTHN { " + sASelectURL + " - " + sPathInfo + " - "
				+ sReturnSuffix);

		HashMap<String, String> hmRequest = new HashMap<String, String>();
		hmRequest.put("request", "authenticate");
		hmRequest.put("app_id", sAppId);
		hmRequest.put("app_url", sASelectURL + sPathInfo + sReturnSuffix); // My return address
		hmRequest.put("a-select-server", _sASelectServerID);
		// 20110407, Bauke: use checkSignature flag:
		hmRequest.put("check-signature", Boolean.toString(checkSignature));
		// if checkSignature is true, caller must supply a signature as well

		// 20090606: Bauke: changed external call to direct method call
		_systemLogger.log(Level.FINER, MODULE, sMethod, "hmRequest=" + hmRequest);
		HashMap<String, Object> hmResponse = handleAuthenticateAndCreateSession(hmRequest, null);
		_systemLogger.log(Level.FINER, MODULE, sMethod, "hmResponse=" + hmResponse);

		/*
		 * try { hmResponse = iClientComm.sendMessage(hmRequest, sASelectURL); } catch (Exception e) {
		 * _systemLogger.log(Level.INFO, MODULE, sMethod, "} AUTHN Could not send authentication request"); throw new
		 * ASelectException(Errors.ERROR_ASELECT_IO); }
		 */
		String sResultCode = (String) hmResponse.get("result_code");
		if (!sResultCode.equals(Errors.ERROR_ASELECT_SUCCESS)) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"} AUTHN Authentication request was not successful, result_code=" + sResultCode);
			throw new ASelectException(Errors.ERROR_ASELECT_IO);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "} AUTHN");
		return hmResponse;
	}

	// Convenience method
	/**
	 * Inits the client communicator.
	 * 
	 * @param oConfig
	 *            the o config
	 * @return the i client communicator
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected IClientCommunicator initClientCommunicator(Object oConfig)
	throws ASelectException
	{
		return Tools.initClientCommunicator(ASelectConfigManager.getHandle(), _systemLogger, oConfig);
	}

	/**
	 * Decrypt credentials.
	 * 
	 * @param encrypted
	 *            the encrypted credentials
	 * @return the decrypted result
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String decryptCredentials(String encrypted)
	throws ASelectException
	{
		String sMethod = "decryptCredentials";
		try {
			byte[] baTgtBytes = CryptoEngine.getHandle().decryptTGT(encrypted);
			return Utils.byteArrayToHexString(baTgtBytes);
		}
		catch (ASelectException eAC) // decrypt failed
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not decrypt TGT", eAC);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, eAC);
		}
		catch (Exception e) // HEX conversion fails
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not decrypt TGT", e);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID, e);
		}
	}

	/**
	 * Store session data with rid.
	 * 
	 * @param response
	 *            the response
	 * @param htSessionMoreData
	 *            more data for the session 
	 * @param htSessionContext
	 *            the session context, can be null
	 * @param sPrefix
	 *            the rid prefix
	 * @param sRid
	 *            the rid
	 * @throws ASelectException
	 */
	protected HashMap<String, Object> storeSessionDataWithRid(HttpServletResponse response, HashMap htSessionMoreData,
				HashMap<String, Object> htSessionContext, String sPrefix, String sRid)
	throws ASelectException
	{
		String sMethod = "storeRidSessionData";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Update Session: "+sPrefix+sRid +
				" htSessionMoreData="+htSessionMoreData);

		// This method is now only used by idff and wsfed
		// Bauke 20081209 Update the session instead of always creating a new one
		// 20120404, Bauke: removed: HashMap htSessionData = _oSessionManager.getSessionContext(sPrefix + sRid);
		if (htSessionContext == null)
			_oSessionManager.createSession(sPrefix+sRid, htSessionMoreData, true/*start paused*/);  // create with a pre-defined RID
		else {
			htSessionContext.putAll(htSessionMoreData);
			_oSessionManager.updateSession(sPrefix+sRid, htSessionContext);
		}

		// Also return the rid used in a cookie
		String sCookieDomain = _configManager.getCookieDomain();
		HandlerTools.putCookieValue(response, sPrefix+"rid", sRid, sCookieDomain, null, -1, 1/*httpOnly*/, _systemLogger);
		return htSessionContext;
	}

	/**
	 * Retrieve session data from rid. The rid is taken from a cookie.
	 * 
	 * @param request
	 *            the request
	 * @param sPrefix
	 *            the prefix
	 * @return the session context
	 */
	protected HashMap retrieveSessionDataFromRid(HttpServletRequest request, String sPrefix)
	{
		String sMethod = "retrieveRidSessionData";

		String sRidCookie = HandlerTools.getCookieValue(request, sPrefix + "rid", _systemLogger);
		if (sRidCookie == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot find 'rid' in cookie '" + sPrefix + "rid'");
			return null;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Find session:" + sPrefix + sRidCookie);
		HashMap htSessionData = _oSessionManager.getSessionContext(sPrefix + sRidCookie);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "htSessionData=" + htSessionData);

		if (htSessionData != null)
			htSessionData.put("session_rid", sRidCookie); // in case we need it
		return htSessionData;
	}

	/**
	 * Creates the sam l11 builder.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sPrefix
	 *            the s prefix
	 * @return the saml11 builder
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected Saml11Builder createSAML11Builder(Object oConfig, String sPrefix)
	throws ASelectException
	{
		String sMethod = "createSAML11Builder";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "sPrefix=" + sPrefix);
		String sSendStatement = ASelectConfigManager.getParamFromSection(oConfig, "attribute", "send_statement", true);
		if (!sSendStatement.equalsIgnoreCase("true") && !sSendStatement.equalsIgnoreCase("false")) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'send_statement' in 'attribute' section must be 'true' or 'false'");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		boolean bSendAttributeStatement = new Boolean(sSendStatement).booleanValue();

		String sAttrNameSpace = ASelectConfigManager.getParamFromSection(oConfig, "attribute", "namespace", true);
		String sAssertionExpireTime = ASelectConfigManager.getParamFromSection(oConfig, "assertion", "expire", true);
		long lExpire = 0;
		try {
			lExpire = Long.parseLong(sAssertionExpireTime);
		}
		catch (NumberFormatException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'expire' in 'assertion' section isn't a number: " + sAssertionExpireTime);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		if (lExpire < 1) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Config item 'expire' in 'assertion' section must be higher than 0 and not: "
							+ sAssertionExpireTime);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		return new Saml11Builder(sAttrNameSpace, bSendAttributeStatement, lExpire * 1000, _sASelectServerID, sPrefix);
	}

	/**
	 * Builds the html input.
	 * 
	 * @param sName
	 *            the s name
	 * @param sValue
	 *            the s value
	 * @return the string
	 */
	public String buildHtmlInput(String sName, String sValue)
	{
		if (sValue == null)
			return "";
		return "<input type=\"hidden\" name=\"" + sName + "\" value=\"" + sValue + "\"/>\n";
	}

	// RH, 20211006, sn
	/**
	 * 
	 * @param sName
	 * @param sValue
	 * @param sType
	 * @return
	 */
	public String buildHtmlInput(String sName, String sValue, String sType)
	{
		return "<input" + (sType == null ? "" : " type=\"" + sType + "\"")  + " name=\"" + sName + "\"" +
				(sValue == null ? "" : " value=\"" + sValue + "\"") + " />\n";
	}
	// RH, 20211006, en

	
	/**
	 * 
	 * @param sSrc
	 * 		must contain or point to a valid img
	 * @param sAlt
	 * 		alternate string
	 * @param sWidth
	 * 		preferred width of image
	 * @param sHeight
	 * 		preferred height of image
	 * @return
	 */
	public String buildHtmlImg(String sSrc, String sAlt, String sWidth, String sHeight)
	{
		if (sSrc == null)
			return "";
		// We don't use sHeight and sWidth yet, use scale = 0 for now
		return "<img scale=\"0\"  src=\"" + sSrc + "\" alt=\"" + sAlt + "\"/>\n";
	}

	// The policy to extract Uid and Attributes from an Assertion
	//
	/**
	 * Extract uid and attributes.
	 * 
	 * @param sAssertion
	 *            the s assertion
	 * @return the hash map
	 */
	protected HashMap extractUidAndAttributes(String sAssertion)
	{
		HashMap htAttributes = extractAllAttributes(sAssertion);
		//String sUid = (String) htAttributes.get("digid_uid");
		//if (sUid == null)
		String sUid = (String) htAttributes.get("uid");
		if (sUid == null)
			sUid = (String) htAttributes.get("cn");
		if (sUid == null) {
			sUid = extractNameIdentifier(sAssertion);
		}
		if (sUid != null && htAttributes.get("uid") == null) {
			// We want at least the "uid" attribute, so other A-Select servers can work with the result
			htAttributes.put("uid", sUid);
		}
		_systemLogger.log(Level.FINEST, MODULE, "extractUidAndAttributes", "htAttributes=" + Auxiliary.obfuscate(htAttributes));
		return htAttributes;
	}

	/**
	 * Extract name identifier.
	 * 
	 * @param sAssertion
	 *            the s assertion
	 * @return the string
	 */
	protected String extractNameIdentifier(String sAssertion)
	{
		String sResult = Tools.extractFromXml(sAssertion, "saml:NameIdentifier", true);
		_systemLogger.log(Level.FINER, MODULE, "extractNameIdentifier", "sResult=" + sResult);
		if (sResult == null) {
			sResult = Tools.extractFromXml(sAssertion, "NameIdentifier", true);
			_systemLogger.log(Level.FINER, MODULE, "extractNameIdentifier", "sResult=" + sResult);
		}
		return sResult;
	}

	/**
	 * Extract all attributes.
	 * 
	 * @param sAssertion
	 *            the s assertion
	 * @return the hash map
	 */
	protected HashMap extractAllAttributes(String sAssertion)
	{
		final String ATTRNAME = "AttributeName=";
		final String ATTRVALUE = "AttributeValue>";
		final String ATTRVALUE2 = "saml:AttributeValue>";
		String sMethod = "extractAllAttributes";
		HashMap htResult = new HashMap();
		int nIdx, nEnd;
		String sAttrName, sAttrValue;
		int aNameLen = ATTRNAME.length();
		int aValueLen = ATTRVALUE.length();

		for (nIdx = 0;;) {
			nIdx = sAssertion.indexOf(ATTRNAME, nIdx);
			if (nIdx < 0)
				break;
			nIdx += aNameLen;
			if (sAssertion.charAt(nIdx) == '"')
				nIdx++;
			for (nEnd = nIdx;; nEnd++) {
				if (sAssertion.charAt(nEnd) == '"' || sAssertion.charAt(nEnd) == ' ' || sAssertion.charAt(nEnd) == '\t'
						|| sAssertion.charAt(nEnd) == '\r' || sAssertion.charAt(nEnd) == '\n')
					break;
			}
			if (nEnd <= nIdx)
				continue;
			sAttrName = sAssertion.substring(nIdx, nEnd);
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeName="+sAttrName);

			nIdx = sAssertion.indexOf(ATTRVALUE, nEnd);
			if (nIdx < 0)
				break;
			nIdx += aValueLen; // Start of value
			nEnd = sAssertion.indexOf("</" + ATTRVALUE, nIdx);
			if (nEnd < 0) {
				nEnd = sAssertion.indexOf("</" + ATTRVALUE2, nIdx);
				if (nEnd < 0)
					continue;
			}
			sAttrValue = sAssertion.substring(nIdx, nEnd);
			// _systemLogger.log(Level.INFO, MODULE, sMethod, "AttributeValue="+sAttrValue);
			nIdx = nEnd + 2 + aValueLen;

			htResult.put(sAttrName, sAttrValue);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "htResult=" + htResult);
		return htResult;
	}

	/**
	 * Creates the context and issues a TGT.
	 * 
	 * @param response
	 *            the HttpServletResponse
	 * @param sRid
	 *            the rid, can be null
	 * @param htSessionContext
	 *            the session context if available, can be null
	 * @param sServerId
	 *            the server id
	 * @param sOrg
	 *            the organization name
	 * @param sAppId
	 *            the application id
	 * @param sTgt
	 *            the TGT (can be null if not present yet)
	 * @param htAttributes
	 *            the input attributes to be serialized
	 * @return the TGT that was created
	 * @throws ASelectException
	 */
	// 20120403, Bauke: added htSessionContext to save on session reads
	public String createContextAndIssueTGT(HttpServletResponse response, String sRid/*can be null*/, HashMap htSessionContext/*can be null*/,
			String sServerId, String sOrg, String sAppId, String sTgt, HashMap htAttributes)
	throws ASelectException
	{
		String sMethod = "createContextAndIssueTGT";
		SessionManager _sessionManager = SessionManager.getHandle(); // RH, 20080617, n
		if (sRid != null && htSessionContext == null)
			htSessionContext = _sessionManager.getSessionContext(sRid);

		// Extract uid and security level
		String sUserId = (String) htAttributes.get("uid");
		if (sUserId == null)
			sUserId = (String) htAttributes.get("cn");

		String sAuthspLevel = (String) htAttributes.get("authsp_level");
		String sSecLevel = (String) htAttributes.get("sel_level");
		if (sSecLevel == null) sSecLevel = (String) htAttributes.get("betrouwbaarheidsniveau");
		if (sSecLevel == null) sSecLevel = sAuthspLevel;
		if (sSecLevel == null) sSecLevel = "5";
		_systemLogger.log(Level.FINER, MODULE, sMethod, "UserId=" + Auxiliary.obfuscate(sUserId) + ", secLevel=" + sSecLevel);

		htAttributes.put("uid", sUserId);
		htAttributes.put("betrouwbaarheidsniveau", sSecLevel);
		htAttributes.put("sel_level", sSecLevel);

		// RM_32_01
		HashMap htTGTContext = new HashMap();
		htTGTContext.put("attributes", org.aselect.server.utils.Utils.serializeAttributes(htAttributes));
		htTGTContext.put("uid", sUserId);
		htTGTContext.put("betrouwbaarheidsniveau", sSecLevel);
		htTGTContext.put("sel_level", sSecLevel);
		htTGTContext.put("authsp_level", sSecLevel);  // should be taken from configuration
		htTGTContext.put("authsp", "SAML");
		htTGTContext.put("organization", sOrg);
		Utils.copyHashmapValue("authsp", htTGTContext, htAttributes);  // overwrite
		Utils.copyHashmapValue("authsp_type", htTGTContext, htAttributes);
		Utils.copyHashmapValue("social_login", htTGTContext, htAttributes);  // 20140219, Bauke: new
		htTGTContext.put("app_id", sAppId);
		htTGTContext.put("app_level", "2");  // should be taken from the application config OR session
		if (sRid != null)
			htTGTContext.put("rid", sRid);

		if (htSessionContext != null) {
			Utils.copyHashmapValue("client_ip", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("user_agent", htTGTContext, htSessionContext);
			Utils.copyHashmapValue("authsp_type", htTGTContext, htSessionContext);
			// 20120606, Bauke: connect sessions
			Utils.copyHashmapValue("usi", htTGTContext, htSessionContext);
			// 20120706, Bauke: for Digid4 "session sync"
			Utils.copyHashmapValue("redirect_sync_time", htTGTContext, htSessionContext);
		}
		
		if (sTgt == null) {
			sTgt = _tgtManager.createTGT(htTGTContext);
		}
		else {
			_tgtManager.updateTGT(sTgt, htTGTContext);
		}

		// We don't need the session any more
		if (htSessionContext != null) {
			Tools.calculateAndReportSensorData(ASelectConfigManager.getHandle(), _systemLogger, "srv_pro", sRid, htSessionContext, sTgt, true);
			_sessionManager.deleteSession(sRid, htSessionContext);
		}

		// create cookie if single sign-on is enabled
		if (_configManager.isSingleSignOn()) {
			TGTIssuer tgtIssuer = new TGTIssuer(sServerId);
			String sIdent = (String)htTGTContext.get("udb_user_ident");
			if (Utils.hasValue(sIdent)) {
				tgtIssuer.setUdbIdentCookie(sIdent, response);
			}
			tgtIssuer.setASelectCookie(sTgt, sUserId, response);
		}
		return sTgt;
	}

	//	RH, 20130924, sn
	// Convenience backward compatibility wrapper for createRequestorToken
	protected String createRequestorToken(HttpServletRequest request, String sProviderId, String sUid,
			String sUserDomain, String sNameIdFormat, String sAudience, HashMap htAttributes, String sAuthMeth)
	throws ASelectException, SAMLException
	{
		return createRequestorToken( request, sProviderId, sUid,
				sUserDomain, sNameIdFormat, sAudience, htAttributes, sAuthMeth, null);
	}
	//	RH, 20130924, en
	
	/**
	 * Creates the requestor token.
	 * 
	 * @param request
	 *            the request
	 * @param sProviderId
	 *            the s provider id
	 * @param sUid
	 *            the s uid
	 * @param sUserDomain
	 *            the s user domain
	 * @param sNameIdFormat
	 *            the s name id format
	 * @param sAudience
	 *            the s audience
	 * @param htAttributes
	 *            the ht attributes
	 * @param sAuthMeth
	 *            the s subj conf
	 * @param sSignAlg
	 *            the s signature algorithm to use sha1, sha256, sha384, sha256, null (defaults to sha1)
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 * @throws SAMLException
	 *             the SAML exception
	 */
	protected String createRequestorToken(HttpServletRequest request, String sProviderId, String sUid,
			String sUserDomain, String sNameIdFormat, String sAudience, HashMap htAttributes, String sAuthMeth,
			String sSignAlg)
	throws ASelectException, SAMLException
	{
		String sMethod = "createRequestorToken";
		String sIP = request.getRemoteAddr();
		String sHost = request.getRemoteHost();
		if (sAuthMeth == null)
			sAuthMeth = SAMLSubject.CONF_BEARER;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Uid=" + Auxiliary.obfuscate(sUid) + " IP=" + sIP + " Host=" + sHost
//				+ " _saml11Builder=" + _saml11Builder + " SubjConf=" + sAuthMeth);
		+ " _saml11Builder=" + _saml11Builder + " AuthenticationMethod=" + sAuthMeth);

		if (_saml11Builder == null) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "_saml11Builder not set");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (sUid.indexOf('@') < 0) {
			sUid += ((sUserDomain.startsWith("@")) ? "" : "@") + sUserDomain;
		}
		SAMLAssertion oSAMLAssertion = _saml11Builder.createMySAMLAssertion(sProviderId, sUid, sNameIdFormat, sIP,
				sHost, sAuthMeth, sAudience, htAttributes);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "oSAMLAssertion=" + oSAMLAssertion);

		// Sign the assertion
		Vector vCertificatesToInclude = new Vector();
		vCertificatesToInclude.add(_configManager.getDefaultCertificate());

		_systemLogger.log(Level.FINER, MODULE, sMethod, "Sign");
//		oSAMLAssertion.sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, _configManager.getDefaultPrivateKey(),
//				vCertificatesToInclude);	//	RH, 20130924, o
		oSAMLAssertion.sign(getXMLSignatureAlg(sSignAlg), _configManager.getDefaultPrivateKey(),
				vCertificatesToInclude);	//	RH, 20130924, n
		// String sAdfs = "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">" +
		// "<wsa:EndpointReference xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" +
		// "<wsa:Address>http://www.anoigo.nl/wsfed_idp.xml</wsa:Address>" +
		// "</wsa:EndpointReference></wsp:AppliesTo>";

		return "<wst:RequestSecurityTokenResponse " + "xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" "
				+ "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" + "<wst:RequestedSecurityToken>"
				+ oSAMLAssertion.toString() + "</wst:RequestedSecurityToken>" + // sAdfs +
				"</wst:RequestSecurityTokenResponse>";
	}

//	public void getKeyAndCheckSignature(String sIssuer, SignableSAMLObject samlObject)	// RH, 20190322, o
	public void getKeyAndCheckSignature(String resourceGroup, String sIssuer, SignableSAMLObject samlObject)	// RH, 20190322, n
	throws ASelectException
	{
		String sMethod = "getKeyAndCheckSignature";
		
//		PublicKey pkey = retrievePublicSigningKey(sIssuer);	// RH, 20181116, o
//		List <PublicKey> pkeys = retrievePublicSigningKey(sIssuer);	// RH, 20181116, n	// RH, 20190322, o
		List <PublicKey> pkeys = retrievePublicKeys(resourceGroup, sIssuer);	// RH, 20181116, n	// RH, 20190322, n
		if (pkeys == null || pkeys.isEmpty()) {	// RH, 20181116, n
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No valid public key in metadata for "+sIssuer);
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		
		if (checkSignature(samlObject, pkeys)) {	// RH, 20181116, n
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Message was signed OK");
		}
		else {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Message was NOT signed OK");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
	}

	/**
	 * NOTE: IDP is used, metadata is taken from the <applications> section
	 * @param sEntityId
	 * @return
	 * @throws ASelectException
	 */
	public List <PublicKey> retrievePublicKeys(String resourceGroup, String sEntityId)	// RH, 20210812, n
	throws ASelectException
	{
		return retrievePublicKeys(resourceGroup, sEntityId, UsageType.SIGNING);
	}
	
	/**
	 * NOTE: IDP is used, metadata is taken from the <applications> section
	 * @param sEntityId
	 * @return
	 * @throws ASelectException
	 */
//	public PublicKey retrievePublicSigningKey(String sEntityId)	// RH, 20181116, o
//	public List <PublicKey> retrievePublicSigningKey(String sEntityId)	// RH, 20181116, n	// RH, 20190322, o
	public List <PublicKey> retrievePublicKeys(String resourceGroup, String sEntityId, UsageType usageType)	// RH, 20181116, n	// RH, 20190322, n
	throws ASelectException
	{
		String sMethod = "retrievePublicSigningKey";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Metadata Key for: "+sEntityId);
		MetaDataManagerIdp metadataManager = MetaDataManagerIdp.getHandle();
//		PublicKey publicKey = metadataManager.getSigningKeyFromMetadata(sEntityId);	// RH, 20181116, o
//		List <PublicKey> publicKeys = metadataManager.getSigningKeyFromMetadata(sEntityId);	// RH, 20181116, n	// RH, 20190322, o
//		List <PublicKey> publicKeys = metadataManager.getSigningKeyFromMetadata(resourceGroup, sEntityId);	// RH, 20181116, n	// RH, 20190322, o	// 20210812, o
		// RH, 20210812, sn
		List <PublicKey> publicKeys = null;
		if (usageType == UsageType.ENCRYPTION) {
			publicKeys = metadataManager.getEncryptionKeyFromMetadata(resourceGroup, sEntityId);
		} else {	// like we used to do
			publicKeys = metadataManager.getSigningKeyFromMetadata(resourceGroup, sEntityId);
		}
		// RH, 20210812, en
//		return publicKey;	// RH, 20181116, o
		return publicKeys;	// RH, 20181116, n
	}

	// For the new opensaml20 library
	/**
	 * Check signature.
	 * 
	 * @param ssObject
	 *            the SAML object to be checked
	 * @param pKey
	 *            the public key
	 * @return true, if successful
	 * @throws ASelectException
	 */
//	public boolean checkSignature(SignableSAMLObject ssObject, PublicKey pKey)	// RH, 20161116, o
	public boolean checkSignature(SignableSAMLObject ssObject, List<PublicKey> pKeys)	// RH, 20161116, n
	throws ASelectException
	{
//		return SamlTools.checkSignature(ssObject, pKey);	// RH, 20161116, o
		return SamlTools.checkSignature(ssObject, pKeys);	// RH, 20161116, n
	}

	// For the new opensaml20 library
	/**
	 * Sign OpenSAML2 library objects (including both SAML versions 1 and 2).
	 * 
	 * @param obj
	 *            The object to be signed
	 * @return obj The signed object
	 * @throws ValidationException
	 *             Thrown if an error occurs while signing
	 * @throws ASelectException
	 *             the a select exception
	 */
	public SignableSAMLObject sign(SignableSAMLObject obj)
	throws ASelectException
	{
//		return SamlTools.signSamlObject(obj);	// RH, 20180918, o
		return SamlTools.signSamlObject(obj, null);	// RH, 20180918, n
	}

	// opensaml 1.0 version
	/**
	 * Check signature.
	 * 
	 * @param sResults
	 *            the s results
	 * @return true, if successful
	 * @throws ASelectException
	 *             the a select exception
	 */
	public boolean checkSignature(String sResults)
	throws ASelectException
	{
		ASelectConfigManager _oASelectConfigManager;
		String sMethod = "checkSignature";
		// The Assertion is the signed object, so get it first
		String sAssertion = Tools.extractFromXml(sResults, "saml:Assertion", false);
		if (sAssertion == null)
			sAssertion = Tools.extractFromXml(sResults, "Assertion", false);

		try {
			Element domElement = this.parseSamlMessage(sAssertion);

			// Tools.visitNode(null, domElement, _systemLogger);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Create Assertion");
			// MySAMLAssertion oAssert = new MySAMLAssertion(domElement, _systemLogger);
			// RM_32_02
			SAMLAssertion oAssert = new SAMLAssertion(domElement);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Created");

			if (oAssert.isSigned()) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed!");
				_oASelectConfigManager = ASelectConfigManager.getHandle();
				String _sKeystoreName = new StringBuffer(_oASelectConfigManager.getWorkingdir()).append(File.separator)
						.append("keystores").append(File.separator).append("providers.keystore").toString();

				// Extract the Issuer to retrieve associated public key
				String sIssuer = domElement.getAttribute("Issuer");
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Issuer=" + sIssuer);

				PublicKey pKey = loadPublicKeyFromKeystore(_sKeystoreName, sIssuer);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "pkey=" + pKey);
				oAssert.verify(pKey);
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Not Signed!");
				throw new SAMLException("Not Signed!");		// RH, 20150709, n
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Verified");
			return true;
		}
		catch (SAMLException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot check signature", e);
			throw new ASelectException(Errors.ERROR_ASELECT_PARSE_ERROR, e);
		}
	}

	
	/**
	 * Load public key from keystore.
	 * 
	 * @param sKeystoreName
	 *            the s keystore name
	 * @param sAlias
	 *            the s alias
	 * @return the public key
	 * @throws ASelectException
	 *             the a select exception
	 */
	PublicKey loadPublicKeyFromKeystore(String sKeystoreName, String sAlias)
	throws ASelectException
	{
		String sMethod = "loadPublicKeyFromKeystore";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Loading public key " + sAlias + " from " + sKeystoreName);
		try {
			sAlias = sAlias.toLowerCase();
			KeyStore ksJKS = KeyStore.getInstance("JKS");
			ksJKS.load(new FileInputStream(sKeystoreName), null);

			java.security.cert.X509Certificate x509Privileged = (java.security.cert.X509Certificate) ksJKS
					.getCertificate(sAlias);
			return x509Privileged.getPublicKey();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot load public key for: " + sAlias);
			throw new ASelectException(Errors.ERROR_ASELECT_NOT_FOUND);
		}
	}

	/**
	 * Parses the saml message.
	 * 
	 * @param sMessage
	 *            the s message
	 * @return the element
	 * @throws ASelectCommunicationException
	 *             the a select communication exception
	 */
	public Element parseSamlMessage(String sMessage)
	throws ASelectCommunicationException
	{
		Element elBody = null;
//		String sMethod = "parse";
		String sMethod = "parseSamlMessage";
		if (!sMessage.equals("")) {
			try {
				// RH, 20210930, so
//				DOMParser parser = new DOMParser();
//				_systemLogger.log(Level.FINER, MODULE, sMethod, "PARSE message: " + sMessage);
//				StringReader sr = new StringReader(sMessage);
//				InputSource is = new InputSource(sr);
//				_systemLogger.log(Level.FINER, MODULE, sMethod, "parse: " + Tools.clipString(sMessage, 100, true));
//				parser.parse(is);
//				_systemLogger.log(Level.FINER, MODULE, sMethod, "parsed");
//
//				// Get root XML tag
//				Document doc = (Document) parser.getDocument();
				// RH, 20210930, eo

				// RH, 20210930, sn
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Parse message: " + Auxiliary.obfuscate(sMessage));
				DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(_systemLogger);
				dbFactory.setNamespaceAware(true);
				dbFactory.setIgnoringComments(true);

				DocumentBuilder builder = dbFactory.newDocumentBuilder();
				StringReader stringReader = new StringReader(sMessage);
				InputSource inputSource = new InputSource(stringReader);
				Document doc = builder.parse(inputSource);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "parsed");
				// Get root XML tag
				// RH, 20210930, en
				
				Element elem = doc.getDocumentElement();
				return elem;
			}
			catch (org.xml.sax.SAXException eSaxE) {
				StringBuffer sbBuffer = new StringBuffer("Error during parsing: ");
				sbBuffer.append(eSaxE.getMessage());
				sbBuffer.append(" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_PARSE_ERROR);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eSaxE);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_PARSE_ERROR, eSaxE);
			}
			catch (java.io.IOException eIO) {
				StringBuffer sbBuffer = new StringBuffer("Error reading message from inputstream: ");
				sbBuffer.append(eIO.getMessage());
				sbBuffer.append(" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_IO);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eIO);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
				// RH, 20210930, sn
			} catch (ParserConfigurationException e) {
				StringBuffer sbBuffer = new StringBuffer("ParserConfigurationException: ");
				sbBuffer.append(e.getMessage());
				sbBuffer.append(" errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_IO);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), e);
				throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
			}
			// RH, 20210930, en
		}
		return elBody;
	}

	// Make timestamp readable
	/**
	 * Gets the readable date.
	 * 
	 * @param timestamp
	 *            the timestamp
	 * @return the readable date
	 */
	public String getReadableDate(long timestamp)
	{
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date(timestamp));
		StringBuffer tmp = new StringBuffer();

		tmp.append(calendar.get(Calendar.DAY_OF_MONTH));
		tmp.append('.').append(calendar.get(Calendar.MONTH) + 1);
		tmp.append('.').append(calendar.get(Calendar.YEAR));

		tmp.append(' ').append(calendar.get(Calendar.HOUR_OF_DAY));
		tmp.append(':').append(calendar.get(Calendar.MINUTE));
		tmp.append(':').append(calendar.get(Calendar.SECOND));

		return tmp.toString();
	}

	/**
	 * Read http post data.
	 * 
	 * @param request
	 *            the request
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public String readHttpPostData(HttpServletRequest request)
	throws ASelectException
	{
		String _sMethod = "readHttpPostData";
		try {
			return Tools.stream2string(request.getInputStream());
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Read POST data failed", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Returns w3 xmldsig representation of the signature algorithm
	 * @param sAlg
	 *            simple string representation sha1, sha256, sha384, sha512, defaults to sha1
	 * @return String w3 xmldsig representation of the signature algorithm
	 */
	protected String getXMLSignatureAlg(String sAlg) {
		String _sMethod = "getXMLSignatureAlg";
		String signatureAlg;
		
		if ( "sha1".equalsIgnoreCase(sAlg) ) {
			signatureAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
		}	else if ( "sha256".equalsIgnoreCase(sAlg) ) {
			signatureAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
		}	else if ( "sha384".equalsIgnoreCase(sAlg) ) {
			signatureAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384;
		}	else if ( "sha512".equalsIgnoreCase(sAlg) ) {
			signatureAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
		}	else{	//	defaults to sha1
			signatureAlg = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			_systemLogger.log(Level.WARNING, MODULE, _sMethod, "Unknown signature algoritm requested: " + sAlg + ", defaulting to sha1");
		}
		return signatureAlg;
	}
	
	
	
	/**
	 * Gets the _s a select server id.
	 * 
	 * @return the _s a select server id
	 */
	public synchronized String get_sASelectServerID()
	{
		return _sASelectServerID;
	}

	/**
	 * Sets the _s a select server id.
	 * 
	 * @param selectServerID
	 *            the new _s a select server id
	 */
	public synchronized void set_sASelectServerID(String selectServerID)
	{
		_sASelectServerID = selectServerID;
	}

	/**
	 * Gets the _s a select organization.
	 * 
	 * @return the _s a select organization
	 */
	public synchronized String get_sASelectOrganization()
	{
		return _sASelectOrganization;
	}

	/**
	 * Sets the _s a select organization.
	 * 
	 * @param selectOrganization
	 *            the new _s a select organization
	 */
	public synchronized void set_sASelectOrganization(String selectOrganization)
	{
		_sASelectOrganization = selectOrganization;
	}

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.IRequestHandler#destroy()
	 */
	public void destroy()
	{
	}
}
