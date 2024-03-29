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
 */

/* 
 * $Id: ASelectConfigManager.java,v 1.65 2006/04/26 12:17:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: ASelectConfigManager.java,v $
 * Revision 1.65  2006/04/26 12:17:06  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.64  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.61.4.11  2006/04/03 09:14:26  erwin
 * Moved redirect_url configuration (fixed bug #166)
 *
 * Revision 1.61.4.10  2006/03/28 08:07:26  leon
 * DirectLogin Form Added
 *
 * Revision 1.61.4.9  2006/03/21 12:46:01  martijn
 * changed log level of optional config item logging
 *
 * Revision 1.61.4.8  2006/03/20 11:06:12  martijn
 * added updateTemplate method
 *
 * Revision 1.61.4.7  2006/03/16 12:56:56  martijn
 * required templates are checked on existance during initialization
 *
 * Revision 1.61.4.6  2006/03/16 08:28:12  leon
 * extra config option added for cross_fallback when user is not found in local UDB
 *
 * Revision 1.61.4.5  2006/03/14 11:26:35  martijn
 * external_url renamed to redirect_url
 *
 * Revision 1.61.4.4  2006/03/13 13:59:20  martijn
 * added optional config item external_url instead of redirect_url
 *
 * Revision 1.61.4.3  2006/02/28 08:48:11  jeroen
 * Adaptations to support RedirectUrl
 *
 * Revision 1.61.4.2  2006/02/06 11:22:43  martijn
 * added signing_cert in _htServerCrypto
 *
 * Revision 1.61.4.1  2005/12/30 12:05:23  martijn
 * initial version
 *
 * Revision 1.61  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.60  2005/09/07 13:30:24  erwin
 * - Improved cleanup of the attribute gatherer (bug #93)
 * - Removed unnesserary HashMap in attribute gatherer (bug #94)
 *
 * Revision 1.59  2005/05/10 08:51:46  martijn
 * fixed bug in the optionality of single_sign-on
 *
 * Revision 1.58  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.57  2005/04/01 14:24:08  peter
 * cross aselect redesign
 *
 * Revision 1.56  2005/04/01 08:39:19  erwin
 * Removed redundant "A-Select Server" startup logging.
 *
 * Revision 1.55  2005/03/23 12:40:33  erwin
 * Changed log level INFO -> WARNING.
 *
 * Revision 1.54  2005/03/23 10:33:38  peter
 * code style fix
 *
 * Revision 1.53  2005/03/23 10:29:51  peter
 * Solved bug in loadHTMLTemplate: FileInputStream was never closed and locked the file.
 *
 * Revision 1.52  2005/03/21 14:42:49  martijn
 * fixed bug in loadPrivilegedSettings(): wrong root section was used to retrieve the applications section
 *
 * Revision 1.51  2005/03/18 08:11:03  remco
 * made AttributeGatherer singleton
 *
 * Revision 1.50  2005/03/18 08:01:49  tom
 * Fixed javadoc
 *
 * Revision 1.49  2005/03/16 13:29:18  martijn
 * loadPrivilegedSettings(): better error handling
 *
 * Revision 1.48  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 * Revision 1.47  2005/03/16 09:28:03  martijn
 * The config item 'cookie_domain' will now only be retrieved from the config at startup and not every time the ticket is issued.
 *
 * Revision 1.46  2005/03/15 15:29:04  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.45  2005/03/15 15:00:50  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.44  2005/03/14 15:23:32  martijn
 * checkUDBSettings() has been changed, because of configuration change
 *
 * Revision 1.43  2005/03/14 14:23:56  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section
 *
 * Revision 1.42  2005/03/11 21:24:08  martijn
 * config section: storagemanager id='ticket' is renamed to storagemanager id='tgt'
 *
 * Revision 1.41  2005/03/11 16:49:35  martijn
 * moved verifying if max sessions and tickets are reached to the storagemanager
 *
 * Revision 1.40  2005/03/11 13:52:37  martijn
 * moved config item resourcegroup from udb config section to connector config section
 *
 * Revision 1.39  2005/03/11 13:15:13  martijn
 * Renamed single-sign-on config item that now will be read once at startup of the config manager.
 *
 * Revision 1.38  2005/03/11 11:19:33  martijn
 * fixed bug: loadAuthSPSettings() required an authsps config section and an authsp config section in it. This has been made optional.
 *
 * Revision 1.37  2005/03/11 08:41:45  martijn
 * fixed bug: keystore aliasses are always stored in lower case, so when retrieved they must be lowercased.
 *
 * Revision 1.36  2005/03/10 17:02:43  martijn
 * moved reading of the system logger configuration to the right classes, so changed init() methods
 *
 * Revision 1.35  2005/03/10 14:17:45  erwin
 * Improved Javadoc.
 *
 * Revision 1.34  2005/03/10 12:54:27  erwin
 * Fixed problem with loading HTML templates.
 *
 * Revision 1.33  2005/03/10 11:11:54  martijn
 * moved the config retrieving from the ASelect component to the AuthenticationLogger
 *
 * Revision 1.32  2005/03/10 10:37:50  erwin
 * Improved error handling.
 *
 * Revision 1.31  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 *
 * Revision 1.30  2005/03/09 15:39:54  remco
 * removed <special_authsp> section from config
 *
 * Revision 1.29  2005/03/09 12:10:53  remco
 * added application signing (untested)
 *
 * Revision 1.28  2005/03/09 11:00:05  tom
 * Javadoc: added return value description to getHandle
 *
 * Revision 1.27  2005/03/09 09:24:50  erwin
 * Renamed and moved errors.
 *
 * Revision 1.26  2005/03/08 08:38:17  peter
 * javadoc typos
 *
 * Revision 1.25  2005/03/07 14:32:11  martijn
 * fixed typo in logging
 *
 * Revision 1.24  2005/03/07 13:40:11  remco
 * - moved random generator to crypto engine
 * - made used crypto algorithms configurable
 *
 * Revision 1.23  2005/03/04 16:27:48  martijn
 * ASelectAuthenticationLogger init call has been changed
 *
 * Revision 1.22  2005/03/03 12:40:40  remco
 * - Crypto Provider, RandomGenerator & Cipher algorithms are now configurable
 *
 * Revision 1.21  2005/03/03 09:30:10  martijn
 * minor fix in INFO logging
 *
 * Revision 1.20  2005/03/02 15:38:54  martijn
 * added INFO logging
 *
 * Revision 1.19  2005/03/01 13:10:57  martijn
 * added directory config for initialization of system logger and authentication logger
 *
 * Revision 1.18  2005/02/28 10:12:16  martijn
 * changed a log meesage from WARNING to SEVERE
 *
 * Revision 1.17  2005/02/28 08:53:59  martijn
 * renamed UDBConnector to IUDBConnector
 *
 * Revision 1.16  2005/02/25 16:07:52  martijn
 * changed some log levels from INFO to CONFIG
 *
 * Revision 1.15  2005/02/25 16:00:36  martijn
 * fixed typo in logging
 *
 * Revision 1.14  2005/02/25 12:32:00  martijn
 * some log messages changed
 *
 * Revision 1.13  2005/02/25 12:13:08  martijn
 * changed initialize A-Select sequence, SAMAgent will be initialized earlier
 *
 * Revision 1.12  2005/02/25 11:04:50  martijn
 * removed getServletConfig() from config manager
 *
 * Revision 1.11  2005/02/24 15:55:17  martijn
 * changed startup messages
 *
 * Revision 1.10  2005/02/24 15:19:10  martijn
 * changed startup messages
 *
 * Revision 1.9  2005/02/22 12:01:51  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.8  2005/02/10 16:28:49  martijn
 * Tested the init() method, and bugfixed it.
 *
 * Revision 1.7  2005/02/10 15:46:47  martijn
 * fixed small bugs that were implemented when variables were renemed
 *
 * Revision 1.6  2005/02/10 14:14:33  martijn
 * fixed typo in javadoc
 *
 * Revision 1.5  2005/02/09 11:33:24  martijn
 * changed all variable names to naming convention and added javadoc
 *
 * Revision 1.4  2005/02/08 15:35:24  martijn
 * changed all variable names to naming convention and renamed and changed implementation of loadUUDBSettings() to checkUDBSettings() and removed old SIP2 checkers.
 *
 */
package org.aselect.server.config;

import java.io.File;
import java.io.FileInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Properties;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.HttpServletRequest;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.cross.CrossASelectManager;
import org.aselect.server.log.ASelectAuthProofLogger;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectEntrustmentLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.utils.FileCache;
import org.aselect.system.utils.Utils;

/**
 * The configuration manager for the A-Select Server. <br>
 * <br>
 * <b>Description:</b><br>
 * A singleton configuration manager, containing the A-Select Server configuration. It loads several settings in memory
 * during initialization. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class ASelectConfigManager extends ConfigManager
{
	/**
	 * The name of this module, that is used in the system logging.
	 */
	public final static String MODULE = "ASelectConfigManager";

	/**
	 * Needed to make this class a singleton.
	 */
	private static ASelectConfigManager _oASelectConfigManager;

	/**
	 * optional template tag
	 */
	public final static String TAG_FRIENLDY_NAME = "[requestor_friendly_name]";

	/**
	 * optional template tag
	 */
	public final static String TAG_MAINTAINER_EMAIL = "[requestor_maintainer_email]";

	/**
	 * optional template tag
	 */
	public final static String TAG_SHOW_URL = "[requestor_url]";

	/**
	 * optional template tag
	 */
	public final static String TAG_RID = "[requestor_rid]";

	/**
	 * The main config section in XML: the root tag containing all A-Select configuration items
	 */
	private Object _oASelectConfigSection;

	/**
	 * Boolean that indicates if single sign on is enabled
	 */
	private boolean _bSingleSignOn;

	/**
	 * Boolean that indicates if a local UDB is enabled
	 */
	private boolean _bUDBEnabled;

	/**
	 * The working dir of the A-Select Server
	 */
	private String _sWorkingDir;

	/**
	 * The redirect URL is the external URL of the A-Select Server, which must be used in redirects
	 */
	private String _sRedirectURL;

	/**
	 * The federation URL is the external URL of the A-Select Server, which must be used in auth requests
	 */
	private String _sFederationUrl;

	/**
	 * Contains the AuthSP keys that can be found in the local_authsp.keystore and remote_authsp.keystore
	 */
	private HashMap _htAuthspKeys = new HashMap();

	/**
	 * Contains the error messages identified by error codes, that are configured in the A-Select Server errors.conf
	 * file
	 */
	//private Properties _propErrorMessages = new Properties();

	/**
	 * Contains the Server private key (default siging key) and it's certificate id.
	 */
	private HashMap _htServerCrypto = new HashMap();

	/**
	 * Containing siging keys for privileged application
	 */
	private HashMap _htPrivilegedPublicKeys = new HashMap();

	/**
	 * The logger used for system logging
	 */
	private ASelectSystemLogger _systemLogger;

	/**
	 * The logger used for authentication logging
	 */
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;

	/**
	 * The logger used for entrustment logging like on-behalf-of
	 */
	private ASelectEntrustmentLogger _oASelectEntrustmentLogger;

	/**
	 * The logger used for entrustment logging like on-behalf-of
	 */
	private ASelectAuthProofLogger _oASelectAuthProofLogger;

	/**
	 * The domain name which is used to set A-Select cookies
	 */
	private String _sCookieDomain = null;

	private String _sCookiePath = null;

	// Additional security precaution
	private String _sAddedSecurity = "";

	// Patching specials
	private String _sAddedPatching = "";

	// <user_info>consent,save_consent,session,logout</user_info>
	// use either "consent" or "save_consent"
	private String _sUserInfoSettings = "";
	
	private String _sSharedSecret = null;
	
	private String _sOrgFriendlyName = null;

	/**
	 * Gets the shared secret.
	 * 
	 * @return the string
	 */
	public String getSharedSecret() { return _sSharedSecret; }

	// Key is <template_name>_<lang> where _<lang> is optional (default entry)
	private ConcurrentHashMap<String, String> hmCachedTemplates = new ConcurrentHashMap<String, String>();

	// Key is errors_<lang> where _<lang> is optional (default entry)
	private ConcurrentHashMap<Properties, String> hmCachedErrorMessages = new ConcurrentHashMap<Properties, String>();

	/**
	 * Check if CrossFallback is enabled when user not is found in local A-Select UDB.
	 */
	private boolean _bCrossFallbackEnabled = false;
	
	// <String> will contain query parameters, <Vector<String>> will contain app_id's
	// If <Vector<String>> == null, urldecoding will take place for all applications
	private HashMap<String, Vector<String>> parameters2decode = null;
	////////////////////////////////////////
	private HashMap<String, HashMap<String, Pattern>> parameters2forward = null;
	private final String DEFAULT_REGEX = "[\\w]{0,80}";	// 80 or less word characters + underscore

	private String _sPreviousSessionCookieName = null;
	private String _sPreviousSessionAuthspID = null;
	private int _iPreviousSessionCookieAge = 0;

	/**
	 * Must be used to get an ASelectConfigManager instance. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Creates a new <code>ASelectConfigManager</code> instance if it's still <code>null</code>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * Always the same instance of the config manager is returned, because it's singleton. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return handle to the ASelectConfigManager
	 */
	public static ASelectConfigManager getHandle()
	{
		if (_oASelectConfigManager == null)
			_oASelectConfigManager = new ASelectConfigManager();
		return _oASelectConfigManager;
	}

	/**
	 * Initialization of the ASelectConfigManager singleton. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Must be successfully run once, before it can be used. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>If SSL is used, the truststore must be set at the startup of the servlet container.</li>
	 * <li><code>sWorkingDir != null</code>.</li>
	 * <li><code>sSQLDriver != null</code> if config is stored in a file instead of in a database.</li>
	 * <li><code>sSQLUser != null</code> if config is stored in a file instead of in a database.</li>
	 * <li><code>sSQLPassword != null</code> if config is stored in a file instead of in a database.</li>
	 * <li><code>sSQLURL != null</code> if config is stored in a file instead of in a database.</li>
	 * <li><code>sSQLTable != null</code> if config is stored in a file instead of in a database.</li>
	 * <li><code>sConfigIDName != null</code> if config is stored in a file instead of in a database.</li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The A-Select configuration is read and components are initialized. <br>
	 * 
	 * @param sWorkingDir
	 *            The workingdir containing the configuration and keystores of the A-Select Server.
	 * @param sSQLDriver
	 *            The JDBC driver name, used when configuration is stored in a database.
	 * @param sSQLUser
	 *            The JDBC user name, used when configuration is stored in a database.
	 * @param sSQLPassword
	 *            The JDBC password for the given user name, used when configuration is stored in a database.
	 * @param sSQLURL
	 *            The JDBC URL, used when configuration is stored in a database.
	 * @param sSQLTable
	 *            The JDBC table name in which the configuration is located; used when configuration is stored in a
	 *            database.
	 * @param sConfigIDName
	 *            The JDBC configuration id to locate the configuration in the config table, used when configuration is
	 *            stored in a database.
	 * @throws ASelectException
	 *             If initialisation fails.
	 */
	public void init(String sWorkingDir, String sSQLDriver, String sSQLUser, String sSQLPassword, String sSQLURL,
			String sSQLTable, String sConfigIDName)
	throws ASelectException
	{
		String sMethod = "init";
		StringBuffer sbInfo;
		
		// Load config from database or xml file
		loadConfiguration(sWorkingDir, sSQLDriver, sSQLUser, sSQLPassword, sSQLURL, sSQLTable, sConfigIDName);

		// initialize system logger
		Object oSysLogging = null;
		try {
			oSysLogging = getSection(_oASelectConfigSection, "logging", "id=system");
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"No valid 'logging' config section with id='system' found.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		_systemLogger.init(oSysLogging, sWorkingDir);

		sbInfo = new StringBuffer("Starting ").append(Version.getVersion());
		_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

		// initialize authentication logger
		Object oAuthLogging = null;
		try {
			oAuthLogging = getSection(_oASelectConfigSection, "logging", "id=authentication");
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod,
					"No valid 'logging' config section with id='authentication' found.", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		_oASelectAuthenticationLogger.init(oAuthLogging, sWorkingDir);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized ASelectAuthenticationLogger.");

		// read redirect URL
		try {
			_sRedirectURL = getParam(_oASelectConfigSection, "redirect_url");
			new URL(_sRedirectURL); // checks correctness
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No configuration item 'redirect_url' defined, using default");
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Configured configuration item 'redirect_url' isn't an URL: " + _sRedirectURL);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		// read federation URL (OLD mechanism)
		try {
			_sFederationUrl = getParam(_oASelectConfigSection, "federation_url");
			new URL(_sFederationUrl);
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No configuration item 'federation_url' defined");
		}
		catch (MalformedURLException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Configured configuration item 'federation_url' isn't an URL: " + _sFederationUrl);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		// checking essentional config
		checkEssentialConfig();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully parsed essential system configuration.");

		try {
			ASelectSAMAgent.getHandle().init();
		}
		catch (ASelectSAMException eSAM) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Can't initialize SAMAgent", eSAM);
			throw eSAM;
		}

		// load private key from aselect.keystore
		loadDefaultPrivateKey(sWorkingDir);

		// check if single sign-on is enabled
		String sSingleSignOn = null;
		try {
			sSingleSignOn = getParam(_oASelectConfigSection, "single_sign_on");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No 'single_sign_on' config item found, using default: single_sign_on = enabled", e);
		}
		_bSingleSignOn = (sSingleSignOn == null) || (sSingleSignOn.equalsIgnoreCase("true"));
		if (!_bSingleSignOn) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Single sign-on is disabled");
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Single sign-on is enabled");

		_sCookiePath = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "cookie_path", false);
		if (_sCookiePath == null)
			_sCookiePath = "/aselectserver/server";
		if (!_sCookiePath.startsWith("/"))
			_sCookiePath = "/" + _sCookiePath;
		_sAddedSecurity = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "added_security", false);
		if (_sAddedSecurity == null)
			_sAddedSecurity = "";
		_sAddedPatching = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "added_patching", false);
		if (_sAddedPatching == null)
			_sAddedPatching = "";
		_sUserInfoSettings = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "user_info", false);
		if (_sUserInfoSettings == null)
			_sUserInfoSettings = "";
		_sSharedSecret = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "shared_secret", false);
		
		_sOrgFriendlyName = getParam(_oASelectConfigSection, "organization_friendly_name");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Organization friendly name: "+_sOrgFriendlyName);
		
		String sKeep = ASelectConfigManager.getSimpleParam(_oASelectConfigSection, "file_cache_keep", false);
		if (sKeep != null) {
			try {
				long lKeep = Integer.parseInt(sKeep);
				if (lKeep >= 0)
					FileCache.setFileCacheKeep(lKeep);
			}
			catch (NumberFormatException e) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Bad value for file_cache_keep");
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		// In a redundant environment a domain cookie wil be set.
		// This way, all A-Select servers in, for example:
		// .aselect.domain.com, will receive the TGT cookie from the
		// user.
		try {
			_sCookieDomain = getParam(_oASelectConfigSection, "cookie_domain");
			if (_sCookieDomain.trim().length() == 0) {
				_sCookieDomain = null;
			}
			else { // Needs to use a dot as prefix, to make it an official domain name
				if (!_sCookieDomain.startsWith(".")) {
					_sCookieDomain = "." + _sCookieDomain;
				}
			}
		}
		catch (ASelectConfigException e) {
			_sCookieDomain = null;
		}

		if (_sCookieDomain != null) {
			sbInfo = new StringBuffer("The following cookie domain will be used for setting A-Select cookies: ");
			sbInfo.append(_sCookieDomain);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		else {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"No specific cookie domain configured, using the default domain");
		}
		
		// RH, 20141121, sn
		// get PreviousSession parameters
		Object oPreviousSession = null;
		try {
			oPreviousSession = getSection(_oASelectConfigSection, "store_cookie", "id=previous_session");
			_sPreviousSessionCookieName = getParam(oPreviousSession, "cookiename");
			String _sPreviousSessionCookieAge = getParam(oPreviousSession, "cookieage");
			try {
			_iPreviousSessionCookieAge = Integer.parseInt(_sPreviousSessionCookieAge);
			} catch ( NumberFormatException nfe) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Could not parse cookieage");
				throw new ASelectConfigException(nfe.getMessage());
			}
			_sPreviousSessionAuthspID = getParam(oPreviousSession, "authspid");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized PreviousSession");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod,
					"No valid 'store_cookie' config section with id='previous_session' found, previous_session not enabled.");
		}
		// RH, 20141121, en

		if (_htServerCrypto.size() > 0) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded default private key.");

			// load authsp settings
			loadAuthSPSettings(sWorkingDir);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded AuthSP settings.");

			// load user db settings
			try {
				checkUDBSettings();
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded UDB settings.");
				_bUDBEnabled = true;
			}
			catch (ASelectException eAS) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid UDB settings found, resume starting with UDB disabled.");
				_bUDBEnabled = false;
			}
		}
		
		// RH, 20140228, sn
		// initialize entrust (on-behalf-of) logger
		Object oEntrustLogging = null;
		try {
			oEntrustLogging = getSection(_oASelectConfigSection, "logging", "id=entrustment");
			_oASelectEntrustmentLogger.init(oEntrustLogging, sWorkingDir);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized ASelectEntrustmentLogger.");
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod,
					"No valid 'logging' config section with id='entrustment' found, entrustment logging not enabled.");
		}
		// RH, 20140228, sn

		// RH, 20140327, sn
		// initialize authentication proof logger
		Object oAuthProofLogging = null;
		try {
			oAuthProofLogging = getSection(_oASelectConfigSection, "logging", "id=authproof");
			_oASelectAuthProofLogger.init(oAuthProofLogging, sWorkingDir);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized ASelectAuthProofLogger.");
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod,
					"No valid 'logging' config section with id='authproof' found, authproof logging not enabled.");
		}
		// RH, 20140327, sn
		
		///////////////////////////////////////////////////////// querystringparameterurldecoding configuration
		try {
			Object oURLDecoding = getSection(_oASelectConfigSection, "transformation", "id=querystringparameterurldecoding");
			parameters2decode = new HashMap<String, Vector<String>>();
			Object oURLDecodingParameter = getSection(oURLDecoding, "parameter");
			while (oURLDecodingParameter != null) {
				Vector<String> apps = null;
				String queryparametername = getParam(oURLDecodingParameter, "name");
				String application = null;
				try {
					application = getParam(oURLDecodingParameter, "application");
					apps = parameters2decode.get(queryparametername); // Get applications so far
					if (apps == null) {
						apps = new Vector<String>();
					}
					apps.add(application);
				} catch (ASelectConfigException e) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, 
							"No attribute 'application' found, decoding all GET requestparameters with name: " + queryparametername);
				}
				parameters2decode.put(queryparametername, apps);	// apps can be null

				_systemLogger.log(Level.INFO, MODULE, sMethod, "Setting URLDecode for parameter: " + queryparametername + " in application: " + application);
				oURLDecodingParameter = getNextSection(oURLDecodingParameter);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded querystringparameterurldecoding configuration: " + parameters2decode);

		} catch (ASelectConfigException e) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, 
					"No valid 'transformation' section with id='querystringparameterurldecoding' found or no 'parameter' section found or no 'name' section found, urldecoding on GET not enabled.");
		}
		
		//////////////////////////////////////////////////////////////////////////////
		
		//	RH, 20160621, sn
		//	place allowed query string parameters here
		// with regex for validation/sanitization
		///////////////////////////////////////////////////////// querystringparameterforward configuration
		try {
			Object oURLForwarding = getSection(_oASelectConfigSection, "transformation", "id=querystringparameterforwarding");
			Object oURLForwardParameter = getSection(oURLForwarding, "parameter");
			parameters2forward = new HashMap<String, HashMap<String, Pattern>>();
			while (oURLForwardParameter != null) {
				Vector<String> apps = null;
				String queryparametername = getParam(oURLForwardParameter, "name");
				String queryparameterregex = DEFAULT_REGEX;
				HashMap<String, Pattern> app_regex = null;
				app_regex = parameters2forward.get(queryparametername);
				if (app_regex == null) {
					app_regex = new HashMap<String, Pattern>();
				}
				try {
					queryparameterregex = getParam(oURLForwardParameter, "regex");
				} catch (ASelectConfigException ace) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, 
							"No attribute 'regex' found, using default regex");
				}
				try {
					Pattern pattern = Pattern.compile(queryparameterregex);
					String application = null;
					try {
						application = getParam(oURLForwardParameter, "application");
					} catch (ASelectConfigException e) {
						_systemLogger.log(Level.FINEST, MODULE, sMethod, 
								"No attribute 'application' found, setting regex for default applications and requestparameters with name: " + queryparametername);
					}
					app_regex.put(application, pattern);	// application can be null

					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Setting URL parameter forward for parameter: " + queryparametername + " in application: " + application + " with pattern:" + pattern);
					
					parameters2forward.put(queryparametername, app_regex);

				} catch (PatternSyntaxException pse) {
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, 
							"Error compiling regex:"  + queryparameterregex + " for requestparameters with name: " + queryparametername);
					throw new ASelectConfigException("Error compiling regex", pse);
				}

				oURLForwardParameter = getNextSection(oURLForwardParameter);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded querystringparameterforwarding configuration: " + parameters2forward);

		} catch (ASelectConfigException e) {
			_systemLogger.log(Level.FINER, MODULE, sMethod, 
					"No valid 'transformation' section with id='querystringparameterforwarding' found or no 'parameter' section found or no 'name' section found, urlparameterforwarding on GET not enabled.");
		}
		
		//	RH, 20160621, en
		//////////////////////////////////////////////////////////////////////////////
		
		
		// loading html templates
		loadAllHTMLTemplates(sWorkingDir);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded HTML templates");

		// loading privileged application settings
		loadPrivilegedSettings(sWorkingDir);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded privileged settings");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully initialized A-Select Server Config Manager");
	}

	/**
	 * Load configuration.
	 * 
	 * @param sWorkingDir
	 *            the s working dir
	 * @param sSQLDriver
	 *            the s sql driver
	 * @param sSQLUser
	 *            the s sql user
	 * @param sSQLPassword
	 *            the s sql password
	 * @param sSQLURL
	 *            the s sqlurl
	 * @param sSQLTable
	 *            the s sql table
	 * @param sConfigIDName
	 *            the s config id name
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public void loadConfiguration(String sWorkingDir, String sSQLDriver, String sSQLUser, String sSQLPassword,
								String sSQLURL, String sSQLTable, String sConfigIDName)
	throws ASelectConfigException
	{
		String sMethod = "loadConfiguration";
		StringBuffer sbInfo = null;

		_sWorkingDir = sWorkingDir;
		_systemLogger = ASelectSystemLogger.getHandle();
		_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();
		_oASelectEntrustmentLogger = ASelectEntrustmentLogger.getHandle();
		_oASelectAuthProofLogger = ASelectAuthProofLogger.getHandle();
		// read config
		if (sSQLDriver != null || sSQLPassword != null || sSQLURL != null || sSQLTable != null) {
			sbInfo = new StringBuffer("Reading config from database: ");
			sbInfo.append(sSQLURL);
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString());
			super.init(sSQLDriver, sSQLUser, sSQLPassword, sSQLURL, sSQLTable, sConfigIDName, _systemLogger);
		}
		else {
			StringBuffer sbConfigFile = new StringBuffer(sWorkingDir);

			if (!sWorkingDir.endsWith(File.separator)) {
				sbConfigFile.append(File.separator);
			}
			sbConfigFile.append("conf").append(File.separator).append("aselect.xml");

			sbInfo = new StringBuffer("Reading config from file: ");
			sbInfo.append(sbConfigFile.toString());
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbInfo.toString());
			super.init(sbConfigFile.toString(), _systemLogger);
		}
		try {
			_oASelectConfigSection = this.getSection(null, "aselect");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not find aselect config section in config file", e);
			throw e;
		}
		
		// Save presence of the <lbsensor> setting in the ConfigManager
		Object oLbSensorSection = Utils.getSimpleSection(this, _systemLogger, _oASelectConfigSection, "lbsensor", false);
		setLbSensorConfigured(oLbSensorSection!=null);
	}

	/**
	 * Returns TRUE if single sign-on for this A-Select Server is enabled. <br>
	 * <br>
	 * 
	 * @return FALSE if single sign-on is disabled in the configuration
	 */
	public boolean isSingleSignOn()
	{
		return _bSingleSignOn;
	}

	/**
	 * Returns TRUE if a UDB for this A-Select Server is enabled. <br>
	 * <br>
	 * 
	 * @return FALSE if only cross A-Select is supported
	 */
	public boolean isUDBEnabled()
	{
		return _bUDBEnabled;
	}

	/**
	 * Returns the cookie domain, if specificaly set in the configuration. <br>
	 * <br>
	 * 
	 * @return containing the cookie domain that is configured including the '.'
	 *         as prefix.
	 */
	public String getCookieDomain()
	{
		return _sCookieDomain;
	}

	/**
	 * Returns the A-Select Server working dir. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the A-Select Server working_dir init parameter in the web.xml. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <br>
	 * 
	 * @return containing the A-Select Server working dir.
	 */
	public String getWorkingdir()
	{
		return _sWorkingDir;
	}

	/**
	 * Returns the A-Select Server redirect URL. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the external URL of the A-Select Server which is used in
	 * redirects.<br/>
	 * The optional 'redirect_url' config item is configured in the A-Select
	 * configuration (aselect.xml). <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <br>
	 * 
	 * @return containing the A-Select Server redirect URL dir.
	 */
	public String getRedirectURL()
	{
		return _sRedirectURL;
	}

	/**
	 * Gets the federation url.
	 * 
	 * @return the federation url
	 */
	public String getFederationUrl()
	{
		return _sFederationUrl;
	}

	/**
	 * Get all AuthSP settings. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns all AuthSP settings that are loaded during startup. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return A containing all AuthSP settings.
	 */
	public HashMap getAuthspSettings()
	{
		return _htAuthspKeys;
	}

	/**
	 * Returns the public signing key of the privileged application with the given alias. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the <code>PublicKey</code> of the privileged application that has the supplied alias name. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - Returns <code>null</code> if no public key was found for that alias. <br>
	 * 
	 * @param sAlias
	 *            The id of the public key.
	 * @return The public key of a privieleged application indicated by it's alias.
	 */
	public PublicKey getPrivilegedPublicKey(String sAlias)
	{
		return (PublicKey) _htPrivilegedPublicKeys.get(sAlias);
	}

	/**
	 * Returns the default private key of this A-Select Server. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the PrivateKey that is stored in the aselect.keystore keystore. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return The private key of this A-Select Server.
	 */
	public PrivateKey getDefaultPrivateKey()
	{
		return (PrivateKey) _htServerCrypto.get("private_key");
	}

	/**
	 * Returns the certificate of this A-Select Server. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the X509 certificate that is stored in the aselect.keystore keystore. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return The certificate of this A-Select Server.
	 */
	public java.security.cert.X509Certificate getDefaultCertificate()
	{
		return (java.security.cert.X509Certificate) _htServerCrypto.get("signing_cert");
	}

	/**
	 * Returns the default certificate ID. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the certificate ID of the A-Select Server private key. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return a representation of the certificate ID
	 */
	public String getDefaultCertId()
	{
		return (String) _htServerCrypto.get("cert_id");
	}

	/**
	 * Get the error message that matches the error code that is supplied. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the error message that is configured in the errors.conf file in
	 * the A-Select Server configuration. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sErrorCode != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sErrorCode
	 *            An error code as configured in the errors.conf file
	 * @param sLanguage
	 *            the s language
	 * @param sCountry
	 *            the s country
	 * @return A representation of the error message
	 */
	// 20141201, Bauke: now using loadPropertiesFromFile
	public String getErrorMessage(String sModule, String sErrorCode, String sLanguage, String sCountry)
	{
		String sMethod = "getErrorMessage";
		String sMessage = null;

		// aselectserver/conf/errors/errors.conf
		try {
			Properties propErrorMessages = Utils.loadPropertiesFromFile(_systemLogger, _sWorkingDir, null/*subdir*/, "errors.conf", sLanguage);
			sMessage = propErrorMessages.getProperty(sErrorCode);
			if (!Utils.hasValue(sMessage))
				sMessage = "[" + sErrorCode + "]";
		}
		catch (ASelectException e) { // could not translate the error code
			sMessage = "[" + sErrorCode + "]";
		}
		_systemLogger.log(Level.INFO, sModule/*callers module*/, sMethod, "MSG["+sErrorCode+"]->" + sMessage);
		return sMessage;
	}

	/**
	 * Get a template of an A-Select Server form. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns a A-Select Server form that is located in the A-Select Server
	 * configuration (aselectserver/conf/html/*) and can be used as a template. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sForm != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sForm
	 *            The id of the form that must be returned.
	 * @param sLanguage
	 *            the language
	 * @param sCountry
	 *            the country
	 * @return A representation of the requested form.
	 * @throws ASelectException
	 */
	public String getHTMLForm(String sForm, String sLanguage, String sCountry)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, "ASelectConfigManager", "getForm", "Get FORM '" + sForm + "' _" + sLanguage + "_"
				+ sCountry);

		if (sForm.equals("login"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("directlogin"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("userinfo"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

//		if (sForm.equals("select"))	// RH, 20121119, o
		if (sForm.startsWith("select")) // Allow for application specific select form, RH, 20121119, n
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("popup"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("serverinfo"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("logout_info"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("session_info"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("error"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		if (sForm.equals("loggedout"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());

		// Start sequential authsp's
		if (sForm.equals("nextauthsp"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());
		// End sequential authsp's

		// RH, 20180712, sn
		// Start authsp's subselect
		if (sForm.startsWith("subselect"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());
		// End  authsp's subselect
		// RH, 20180712, en

		// RH, 20181127, sn
		// Start wsfed logout cleanup form
		if (sForm.startsWith("wsfed"))
			return Utils.loadTemplateFromFile(_systemLogger, getWorkingdir(), null, sForm, sLanguage, _sOrgFriendlyName, Version.getVersion());
		// End wsfed logout cleanup
		// RH, 20181127, en

		return "Form '" + sForm + "' not found, not a standard form";
	}
	
	/**
	 * Updates the supplied template with optional requestor information. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Updates the supplied template with the tags:<br/>
	 * [requestor_url]<br/>
	 * [requestor_friendly_name]<br/>
	 * [requestor_maintainer_email]<br/>
	 * <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - sTemplate != null <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sTemplate
	 *            the template that must be updated
	 * @param htSessionContext
	 *            containing the session information
	 * @param servletRequest
	 *            the servlet request
	 * @return String containing the updated template
	 * @throws ASelectException
	 *             if template could not be updated
	 */
	public String updateTemplate(String sTemplate, HashMap htSessionContext, HttpServletRequest servletRequest)
	throws ASelectException
	{
		String sMethod = "updateTemplate";
		String sReturn = null;
		String sFriendlyName = "";
		String sMaintainerEmail = "";
		String sUrl = "";
		String sRid = "";	// RH, 20180302, n

		try {
			sReturn = sTemplate;

			// Get tag info from the session
			if (htSessionContext != null) {
				String sLocalOrganization = (String) htSessionContext.get("local_organization");
				_systemLogger.log(Level.FINE, MODULE, sMethod, "org="+sLocalOrganization);
				if (sLocalOrganization != null) {
					HashMap htOrgInfo = CrossASelectManager.getHandle().getLocalServerInfo(sLocalOrganization);
					if (htOrgInfo != null) {
						sFriendlyName = (String) htOrgInfo.get(TAG_FRIENLDY_NAME);
						_systemLogger.log(Level.FINE, MODULE, sMethod, "From Org="+sFriendlyName);
						sMaintainerEmail = (String) htOrgInfo.get(TAG_MAINTAINER_EMAIL);
						Boolean boolShowUrl = (Boolean) htOrgInfo.get(TAG_SHOW_URL);
						if (boolShowUrl != null && boolShowUrl.booleanValue())
							sUrl = (String) htSessionContext.get("local_as_url");
					}
				}
				else {
					String sAppId = (String) htSessionContext.get("app_id");
					_systemLogger.log(Level.FINE, MODULE, sMethod, "app_id="+sAppId);
					if (sAppId != null) {
						sFriendlyName = ApplicationManager.getHandle().getFriendlyName(sAppId);
						_systemLogger.log(Level.FINE, MODULE, sMethod, "From Session="+sFriendlyName);
						sMaintainerEmail = ApplicationManager.getHandle().getMaintainerEmail(sAppId);
						if (ApplicationManager.getHandle().isShowUrl(sAppId))
							sUrl = (String) htSessionContext.get("app_url");
					}
				}
				// RH, 20180302, sn
				sRid = (String) htSessionContext.get("rid");
				// RH, 20180302, en
			}

			// 20130821, Bauke: Get tag info from the cookie
			_systemLogger.log(Level.FINE, MODULE, sMethod, "FriendlyName="+sFriendlyName+" servletRequest="+servletRequest);
			if (!Utils.hasValue(sFriendlyName)) {
				sFriendlyName = HandlerTools.getEncryptedCookie(servletRequest, "requestor_friendly_name", _systemLogger);
				_systemLogger.log(Level.FINE, MODULE, sMethod, "From Cookie="+sFriendlyName);
			}
			if (sFriendlyName == null) {
				sFriendlyName = "";
			}
			sReturn = Utils.replaceString(sReturn, TAG_FRIENLDY_NAME, sFriendlyName);

			if (sMaintainerEmail == null)
				sMaintainerEmail = "";
			sReturn = Utils.replaceString(sReturn, TAG_MAINTAINER_EMAIL, sMaintainerEmail);

			if (sUrl == null)
				sUrl = "";
			sReturn = Utils.replaceString(sReturn, TAG_SHOW_URL, sUrl);

			// RH, 20180302, sn
			if (Utils.hasValue(sRid)) {
				sReturn = Utils.replaceString(sReturn, TAG_RID, sRid);
			}
			// RH, 20180302, en
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not update template with optional parameters", e);
			// 20130502, Bauke: don't throw an exception during error handling
			//throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return sReturn;
	}

	/**
	 * Private constructor. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This constructor is private comform the Singleton design pattern. Use {@link #getHandle()} to retrieve an static
	 * instance. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 */
	private ASelectConfigManager() {
	}

	/**
	 * Load the default private siging key for the A-Select Server. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the private signing key that is stored in the aselect.keystore in the A-Select Server configuration. The
	 * key must be stored in the keystore with the same ID as the A-Select Server id. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li>The keystore_password config item must be available in the A-Select configuration and may not be empty.</li>
	 * <li><code>sWorkingDir != null </code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @throws ASelectException
	 *             if loading fails.
	 */
	private void loadDefaultPrivateKey(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadDefaultPrivateKey";
		String sKeyStoreName = "aselect.keystore";
		String sPassword = null;
		StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);
		String sAlias = getParam(_oASelectConfigSection, "server_id");

		try {
			try {
				sPassword = getParam(_oASelectConfigSection, "keystore_password");
			}
			catch (ASelectConfigException e) {
				StringBuffer sbError = new StringBuffer("Missing keystore_password in config.xml\n");
				sbError.append("\tAuthentication of users is disabled.\n");
				sbError.append("\tOnly cross authentication is possible through ");
				sbError.append("cross A-Select servers running on other organizations.");
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString());
				return;
			}

			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("keystores");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append(sKeyStoreName);
			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			// convert String to char[]
			char[] caPassword = sPassword.toCharArray();
			PrivateKey oPrivateKey = (PrivateKey) ksASelect.getKey(sAlias, caPassword);

			java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
					.getCertificate(sAlias);

			byte[] baCert = x509Cert.getEncoded();
			MessageDigest mdDigest = MessageDigest.getInstance("SHA1");
			mdDigest.update(baCert);
			String sCertFingerPrint = Utils.byteArrayToHexString(mdDigest.digest());

			_htServerCrypto.put("signing_cert", x509Cert);
			_htServerCrypto.put("private_key", oPrivateKey);
			_htServerCrypto.put("cert_id", sCertFingerPrint);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load private key from "+sbKeystoreLocation+" alias="+sAlias, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Loads settings of all configured AuthSP's. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if all minimum AuthSP settings for all configured AuthSPs are available and loads their public keys. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The Authsp settings are loaded. <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @throws ASelectException
	 *             id loading fails.
	 */
	private void loadAuthSPSettings(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadAuthSPSettings";
		Object oAuthSP = null;
		Object oAuthSPsSection = null;

		try {
			try {
				oAuthSPsSection = this.getSection(null, "authsps");
			}
			catch (ASelectConfigException e) {
				// may happen if A-Select is only configured for Cross A-Select
				// will be logged, because _htAuthspKeys.size() == 0
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'authsps' config section found", e);
			}

			if (oAuthSPsSection != null) {
				// get first AuthSP
				try {
					oAuthSP = this.getSection(oAuthSPsSection, "authsp");
				}
				catch (ASelectConfigException e) {
					// may happen if A-Select is only configured for Cross A-Select
					// will be logged, because _htAuthspKeys.size() == 0
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'authsp' config section found", e);
				}
			}

			while (oAuthSP != null) {
				if (checkAuthSPConfig(oAuthSP)) {
					// load it's public key
					loadAuthSPPublicKey(sWorkingDir, oAuthSP);
				}
				oAuthSP = this.getNextSection(oAuthSP);
			}
			if (_htAuthspKeys.size() == 0) {

				StringBuffer sbError = new StringBuffer("No authsp definitions found. AuthSP's disabled. ");
				sbError.append("Can be valid if A-Select Server is configured in Cross A-Select modus.");
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString());
			}
		}
		catch (ASelectException eAC) {
			throw eAC;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load AuthSP settings.");
			sbError.append("AuthSP's disabled.");
			sbError.append("Can be valid if A-Select Server is configured in Cross A-Select modus");
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbError.toString(), e);
		}
	}

	/**
	 * Loads the configured AuthSP Public key of the supplied authsp config section. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the public key of the configured AuthSP from the remote_authsp.keystore or local_authsp.keystore and tries
	 * to load the speicif private key if configured. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sWorkingDir != null</code></li>
	 * <li><code>oAuthSPSection != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <code>_htAuthspKeys</code> comtains the loaded Auhsp key. <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @param oAuthSPSection
	 *            The configuration section of the AuthSP that must be loaded.
	 * @throws ASelectException
	 *             If loading fails.
	 */
	private void loadAuthSPPublicKey(String sWorkingDir, Object oAuthSPSection)
	throws ASelectException
	{
		String sMethod = "loadAuthSPPublicKey";

		PublicKey pkAuthSP = null;
		StringBuffer sbKeystoreFile = null;
		File fKeystore = null;
		KeyStore ksKeyStore = null;
		java.security.cert.X509Certificate x509Cert = null;

		try {
			String sAlias = this.getParam(oAuthSPSection, "id");
			sAlias = sAlias.trim().toLowerCase();

			String sAuthSPType = this.getParam(oAuthSPSection, "type");
			sAuthSPType = sAuthSPType.toLowerCase();

			if (!sAuthSPType.equals("remote") && !sAuthSPType.equals("local")) {
				StringBuffer sbError = new StringBuffer(sAlias);
				sbError.append(" type=").append(sAuthSPType);
				sbError.append(" is illegal. Use 'local' or 'remote'.");
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			sbKeystoreFile = new StringBuffer(sWorkingDir).append(File.separator).append("keystores");
			sbKeystoreFile.append(File.separator).append(sAuthSPType);
			sbKeystoreFile.append(File.separator).append(sAuthSPType).append("_authsp.keystore");

			_systemLogger.log(Level.INFO, MODULE, sMethod, "Keystore=" + sbKeystoreFile + " Alias=" + sAlias);
			fKeystore = new File(sbKeystoreFile.toString());
			if (!fKeystore.exists()) {
				StringBuffer sbError = new StringBuffer("Keystore doesn't exist: ");
				sbError.append(sbKeystoreFile.toString());
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			// load keystore
			ksKeyStore = KeyStore.getInstance("JKS");
			ksKeyStore.load(new FileInputStream(sbKeystoreFile.toString()), null);

			// retrieve first certificate
			x509Cert = (java.security.cert.X509Certificate) ksKeyStore.getCertificate(sAlias);
			if (x509Cert == null) {
				StringBuffer sbError = new StringBuffer("No public key found for alias: '");
				sbError.append(sAlias).append("'");
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			// retrieve first public key
			pkAuthSP = x509Cert.getPublicKey();
			_htAuthspKeys.put(sAlias + ".public_key", pkAuthSP);

			// check if there are more keys for the same alias (for example
			// <alias>.1 or <alias>.2)
			int iSequence = 1;
			x509Cert = (java.security.cert.X509Certificate) ksKeyStore.getCertificate(sAlias + iSequence);
			while (x509Cert != null) {
				pkAuthSP = x509Cert.getPublicKey();

				StringBuffer sbKey = new StringBuffer(sAlias).append(iSequence).append(".public_key");
				_htAuthspKeys.put(sbKey.toString(), pkAuthSP);
				iSequence++;
				x509Cert = (java.security.cert.X509Certificate) ksKeyStore.getCertificate(sAlias + iSequence);
			}
			loadAuthSPSpecificPrivateKey(sWorkingDir, oAuthSPSection);
		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not load AuthSP public key", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Loads the optional specific private key for an AuthSP identified by it's config section. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Put's a specific private signing key in the class variable <i>_htAuthspKeys</i>. The key must be stored in a
	 * keystore with name: [alias]_specific.keystore. The keystore location is: [working_dir]\keystores\[keystore] <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sWorkingDir != null</code></li>
	 * <li><code>oAuthSPConfig != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <code>_htAuthspKeys</code> contains the loaded private key and certificate fingerprint. <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @param oAuthSPConfig
	 *            The config section of the AuthSP that is checked for private message.
	 * @throws ASelectException
	 *             If loading fails.
	 */
	private void loadAuthSPSpecificPrivateKey(String sWorkingDir, Object oAuthSPConfig)
	throws ASelectException
	{
		String sMethod = "loadAuthSPSpecificPrivateKey";
		String sAlias = null;
		String sPassword = null;

		try {
			sAlias = this.getParam(oAuthSPConfig, "id");
			sAlias = sAlias.trim();
			sAlias = sAlias.toLowerCase();

			try {
				sPassword = this.getParam(oAuthSPConfig, "specific_key_password");
			}
			catch (ASelectConfigException eAC) {
				return; // not mandatory
			}

			StringBuffer sbKeystoreFile = new StringBuffer(sWorkingDir);
			sbKeystoreFile.append(File.separator);
			sbKeystoreFile.append("keystores");
			sbKeystoreFile.append(File.separator);

			sbKeystoreFile.append(sAlias);
			sbKeystoreFile.append("_specific.keystore");

			File fKeystore = new File(sbKeystoreFile.toString());
			if (!fKeystore.exists()) {
				StringBuffer sbError = new StringBuffer("Keystore doesn't exist: ");
				sbError.append(sbKeystoreFile.toString());
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			// load keystore
			KeyStore ksKeyStore = KeyStore.getInstance("JKS");
			ksKeyStore.load(new FileInputStream(sbKeystoreFile.toString()), null);

			char[] caPassword = sPassword.toCharArray();

			PrivateKey pkPrivateKey = (PrivateKey) ksKeyStore.getKey(sAlias, caPassword);

			java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksKeyStore
					.getCertificate(sAlias);

			byte[] baCert = x509Cert.getEncoded();
			MessageDigest mdDigest = MessageDigest.getInstance("SHA1");
			mdDigest.update(baCert);
			String sCertFingerPrint = Utils.byteArrayToHexString(mdDigest.digest());

			_htAuthspKeys.put(sAlias + ".specific_private_key", pkPrivateKey);
			_htAuthspKeys.put(sAlias + ".specific_private_key.cert_id", sCertFingerPrint);
		}
		catch (ASelectConfigException e) {
			// no private key found for sAlias
			return;
		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("could not load specific private key for alias '");
			sbError.append(sAlias);
			sbError.append("'");
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Loads the HTML templates from the A-Select Server configuration directory. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the following HTML templates from the directory: [working_dir]\conf\html\*
	 * <ul>
	 * <li>login.html</li>
	 * <li>serverinfo.html</li>
	 * <li>userinfo.html</li>
	 * <li>loggedout.html</li>
	 * <li>error.html</li>
	 * <li>select.html</li>
	 * <li>popup.html</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sWorkingDir != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The HTML templates are loaded into instance strings (e.g. <code>_sLoginForm</code>). <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @throws ASelectException
	 *             If loading templates fails.
	 */
	public void loadAllHTMLTemplates(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadAllHTMLTemplates";

		try {
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "serverinfo.html", ""/*language*/, _sOrgFriendlyName, Version.getVersion());
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "userinfo.html", "", _sOrgFriendlyName, Version.getVersion());
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "loggedout.html", "", _sOrgFriendlyName, Version.getVersion());
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "error.html", "", _sOrgFriendlyName, Version.getVersion());
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "session_info.html", "", _sOrgFriendlyName, Version.getVersion());
			Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "logout_info.html", "", _sOrgFriendlyName, Version.getVersion());

			if (_htServerCrypto.size() > 0) {
				Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "login.html", "", _sOrgFriendlyName, Version.getVersion());
				Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "select.html", "", _sOrgFriendlyName, Version.getVersion());
				Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "popup.html", "", _sOrgFriendlyName, Version.getVersion());
				Utils.loadTemplateFromFile(_systemLogger, sWorkingDir, null, "directlogin.html", "", _sOrgFriendlyName, Version.getVersion());
			}
		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error loading HTML templates", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Loads the configured privileged application settings. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the public signing key for every privileged application that is configured in the A-Select Server
	 * configuration. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sWorkingDir != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The privileged application setting are loaded. <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @throws ASelectException
	 *             if loading fails.
	 */
	private void loadPrivilegedSettings(String sWorkingDir)
	throws ASelectException
	{
		String sMethod = "loadPrivilegedSettings";

		_htPrivilegedPublicKeys = new HashMap();

		try {
			Object oApplicationsSection = getSection(null, "applications");
			// Enumerate applications and load their public key
			Object oApplication = null;
			try {
				oApplication = getSection(oApplicationsSection, "application");
			}
			catch (ASelectConfigException e) {
			}
			while (oApplication != null) {
				String sAppID = getParam(oApplication, "id");
				String sCreateTGT = null;
				try {
					sCreateTGT = getParam(oApplication, "privileged");
				}
				catch (ASelectConfigException e) {
				}
				if (sCreateTGT != null && sCreateTGT.equalsIgnoreCase("true")) {
					loadPrivilegedPublicKey(sWorkingDir, sAppID);
				}
				oApplication = getNextSection(oApplication);
			}
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No privileged applications configured", e);
		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Error loading privileged settings", e);

			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Loads the privileged application public key. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Loads the privileged application public key located in the keystore:<br>
	 * <i>sWorkingDir</i>\keystores\applications\privileged_applications.keystore<br>
	 * and puts it, including it's certificate, in the class variable <i> _htPrivilegedPublicKeys</i>. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b>
	 * <ul>
	 * <li><code>sWorkingDir != null</code></li>
	 * <li><code>sAlias != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <code>_htPrivilegedPublicKeys</code> contains the loaded key with the gevin alias. <br>
	 * 
	 * @param sWorkingDir
	 *            contains the A-Select Server working dir specified in the web.xml.
	 * @param sAlias
	 *            The alias among the privileged application key is stored in the keystore.
	 * @throws ASelectException
	 *             If loading fails.
	 */
	private void loadPrivilegedPublicKey(String sWorkingDir, String sAlias)
	throws ASelectException
	{
		String sMethod = "loadPrivilegedPublicKey";
		try {
			sAlias = sAlias.toLowerCase();

			StringBuffer sbKeystoreName = new StringBuffer(sWorkingDir);
			sbKeystoreName.append(File.separator);
			sbKeystoreName.append("keystores");
			sbKeystoreName.append(File.separator);
			sbKeystoreName.append("applications");
			sbKeystoreName.append(File.separator);
			sbKeystoreName.append("privileged_applications.keystore");

			KeyStore ksJKS = KeyStore.getInstance("JKS");
			ksJKS.load(new FileInputStream(sbKeystoreName.toString()), null);

			java.security.cert.X509Certificate x509Privileged = (java.security.cert.X509Certificate) ksJKS
					.getCertificate(sAlias);

			PublicKey pkPrivileged = x509Privileged.getPublicKey();
			_htPrivilegedPublicKeys.put(sAlias, pkPrivileged);
		}
		catch (Exception e) {
			StringBuffer sbError = new StringBuffer("Could not load public key of privileged application '");
			sbError.append(sAlias);
			sbError.append("'");
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Checks for essential config of the given authsp. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if the minimum config parameters are available in the given AuthSP section. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>oAuthSPSection != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param oAuthSPSection
	 *            The configuration section containing AuthSP configuration.
	 * @return TRUE if the minimum AuthSP configuration is available in the supplied config section.
	 */
	private boolean checkAuthSPConfig(Object oAuthSPSection)
	{
		String sID = null;
		String sMethod = "checkAuthSPConfig";

		try {
			sID = this.getParam(oAuthSPSection, "id");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Missing 'id' parameter in authSP section", eAC);
			return false;
		}
		try {
			this.getParam(oAuthSPSection, "handler");
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbError = new StringBuffer("Missing 'handler' parameter in ");
			sbError.append(sID);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			return false;
		}

		try {
			this.getParam(oAuthSPSection, "level");
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbError = new StringBuffer("Missing 'level' parameter in ");
			sbError.append(sID);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			return false;
		}

		try {
			this.getParam(oAuthSPSection, "friendly_name");
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbError = new StringBuffer("Missing 'friendly_name' parameter in ");
			sbError.append(sID);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			return false;
		}

		try {
			this.getParam(oAuthSPSection, "type");
		}
		catch (ASelectConfigException eAC) {
			StringBuffer sbError = new StringBuffer("Missing 'type' parameter in ");
			sbError.append(sID);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			return false;
		}
		return true;
	}

	/**
	 * Checks if the UDB is correctly configured. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if there is a UDB configured in the A-Select Serve config. It Checks if the 'connector' config item is
	 * available in the udb section and if their is a connector config section with 'id' config item with a
	 * corresponding value. The connector section must also contain a 'class' config item that contains a valid
	 * UDBConnector Class. The configuration located in the resource tag for the udb is checked by calling the init()
	 * method of the UDBConnector Class. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @throws ASelectException
	 *             if check fails.
	 */
	private void checkUDBSettings()
	throws ASelectException
	{
		Object oUdbCfgSection = null;
		String sConnectorID = null;
		Object oUdbConnectorCfgSection = null;
		String sConnectorClass = null;
		IUDBConnector oUDBConnector = null;

		String sMethod = "checkUDBSettings";

		try {
			oUdbCfgSection = this.getSection(null, "udb");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve 'udb' config section", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			String sCrossFallbackEnabled = this.getParam(oUdbCfgSection, "cross_fallback");
			_bCrossFallbackEnabled = sCrossFallbackEnabled.trim().equalsIgnoreCase("true");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.CONFIG, MODULE, sMethod,
					"Could not find 'cross_fallback' param in udb config section, so 'cross_fallback' disabled.", eAC);
		}

		try {
			sConnectorID = this.getParam(oUdbCfgSection, "connector");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'connector' config parameter in udb config section", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			oUdbConnectorCfgSection = this.getSection(oUdbCfgSection, "connector", "id=" + sConnectorID);
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve connector config parameter in udb config section", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			sConnectorClass = this.getParam(oUdbConnectorCfgSection, "class");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not retrieve 'class' config parameter in udb connector config section", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			Class classConnector = Class.forName(sConnectorClass);
			oUDBConnector = (IUDBConnector) classConnector.newInstance();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"The configured udb connector class is not a valid UDBConnector class", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			oUDBConnector.init(oUdbConnectorCfgSection);
		}
		catch (ASelectUDBException eAUDB) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not initialize UDB as configured in the udb resource", eAUDB);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAUDB);
		}
	}

	/**
	 * Checks if the minimum A-Select Server configuration is available in the A-Select Config. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Checks if the following main config items are available:
	 * <ul>
	 * <li>'organization'</li>
	 * <li>'organization_friendly_name'</li>
	 * <li>'server_id'</li>
	 * <li>'max_sessions'</li>
	 * <li>'max_tgt'</li>
	 * </ul>
	 * Checks if their is a StorageManager configured with id='session' and id='ticket' containing the 'expire' config
	 * item. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @throws ASelectException
	 *             if check fails.
	 */
	private void checkEssentialConfig()
	throws ASelectException
	{
		String sMethod = "checkEssentialConfig";

		// check aselect config
		try {
			getParam(_oASelectConfigSection, "organization");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "missing 'organization' parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}
		try {
			getParam(_oASelectConfigSection, "organization_friendly_name");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"missing 'organization_friendly_name' parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			getParam(_oASelectConfigSection, "server_id");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "missing 'server_id' parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		// check session config
		Object oTemp = null;
		try {
			oTemp = getSection(null, "storagemanager", "id=session");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"missing 'storagemanager' section with id=session in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			getParam(oTemp, "max");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "missing 'max' parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			getParam(oTemp, "expire");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"missing 'expire' (in session section) parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}

		// check ticket config
		try {
			oTemp = getSection(null, "storagemanager", "id=tgt");
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"missing 'storagemanager' section with id=tgt in configuration", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		try {
			getParam(oTemp, "max");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "missing 'max' parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

		try {
			getParam(oTemp, "expire");
		}
		catch (ASelectConfigException eAC) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"missing 'expire' (in tgt section) parameter in configuration", eAC);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
		}

	}

	/**
	 * Returns if cross fallback is enabled or not. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns true if cross fallback is enabled and false if not. If a user not exists in the local UDB and cross
	 * fallback is enabled A-Select will try to do an cross authentication <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * cross_aselect must be enabled with remote servers. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @return true if cross fallback is enabled and false if not.
	 */
	public boolean isCrossFallBackEnabled()
	{
		return _bCrossFallbackEnabled;
	}

	/**
	 * Gets the cookie path.
	 * 
	 * @return the cookie path
	 */
	public String getCookiePath()
	{
		return _sCookiePath;
	}

	/**
	 * Gets the added security.
	 * 
	 * @return the added security
	 */
	public String getAddedSecurity()
	{
		return _sAddedSecurity;
	}

	/**
	 * Gets special patching.
	 * 
	 * @return the parameter value
	 */
	public String getAddedPatching()
	{
		return _sAddedPatching;
	}

	/**
	 * Gets the user info settings.
	 * 
	 * @return the user info settings
	 */
	public String getUserInfoSettings()
	{
		return _sUserInfoSettings;
	}

	public String getOrgFriendlyName() { return _sOrgFriendlyName; }
	public void set_sOrgFriendlyName(String sOrgFriendlyName) { _sOrgFriendlyName = sOrgFriendlyName; }

	// Convenience function
	/**
	 * Gets the param from section.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sSection
	 *            the s section
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the param from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getParamFromSection(getHandle(), ASelectSystemLogger.getHandle(), oConfig, sSection, sParam,
				bMandatory);
	}

	// Convenience function
	/**
	 * Gets the simple param.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple param
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleParam(getHandle(), ASelectSystemLogger.getHandle(), oConfig, sParam, bMandatory);
	}

	// Convenience function
	/**
	 * Gets the simple section.
	 * 
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the simple section
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static Object getSimpleSection(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleSection(getHandle(), ASelectSystemLogger.getHandle(), oConfig, sParam, bMandatory);
	}
	
	/**
	 * Gets the table from config.
	 * Read an xml config structure like:
	 * <authentication_method>
	 *  <security level=5 urn="urn:oasis:names:tc:SAML:1.0:cm:unspecified">
	 *  <security level=10 urn="urn:oasis:names:tc:SAML:1.0:cm:password">
	 *  <security level=20 urn="urn:oasis:names:tc:SAML:1.0:cm:sms">
	 *  <security level=30 urn="urn:oasis:names:tc:SAML:1.0:cm:smartcard">
	 * </authentication_method>
	 * 
	 * @param oConfig
	 *            the o config
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
	 * @return the table from config or null if sMainSection not found in config and mandatory == false
	 * @throws ASelectException
	 *             the a select exception
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static HashMap<String, String> getTableFromConfig(Object oConfig, HashMap<String, String> htAllKeys_Values, String sMainSection,
			String sSubSection, String sKeyName, String sValueName, boolean mandatory, boolean uniqueValues)
	throws ASelectException, ASelectConfigException
	{
		String sMethod = "getTableFromConfig";

		Object oProviders = null;
		try {
			oProviders = getHandle().getSection(oConfig, sMainSection);
		}
		catch (ASelectConfigException e) {
			if (!mandatory)
				return null;
			ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "No config section '" + sMainSection + "' found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}

		Object oProvider = null;
		try {
			oProvider = getHandle().getSection(oProviders, sSubSection);
		}
		catch (ASelectConfigException e) {
			ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "Not even one config section '" + sSubSection
					+ "' found in the '" + sMainSection + "' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		while (oProvider != null) {
			String sKey = null;
			try {
				sKey = getHandle().getParam(oProvider, sKeyName);
			}
			catch (ASelectConfigException e) {
				ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "No config item '" + sKeyName + "' found in '"
						+ sSubSection + "' section", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			// Key must be unique
			if (htAllKeys_Values.containsKey(sKey)) {
				ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "Provider '" + sKeyName + "' is not unique: " + sKey);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			String sValue = "";
			boolean bSetNull = Boolean.parseBoolean(getSimpleParam(oProvider, "setnull", false));	// RH, 20130115, n
			if (Utils.hasValue(sValueName)) {
				try {
					sValue = getHandle().getParam(oProvider, sValueName);
				}
				catch (ASelectConfigException e) {
					ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "No config item '" + sValueName + "' found in '"
							+ sSubSection + "' section", e);
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}
	
				if (uniqueValues) {
					// Also check for unique values
					if (htAllKeys_Values.containsValue(sValue)) {
						ASelectSystemLogger.getHandle().log(Level.WARNING, MODULE, sMethod, "Provider '" + sValueName + "' isn't unique: "
								+ sValue);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
					}
				}
			}
			htAllKeys_Values.put(sKey, bSetNull ? null : sValue);	// RH, 20130115, en
//			htAllKeys_Values.put(sKey, sValue);	// RH, 20130115, o

			oProvider = getHandle().getNextSection(oProvider);
		}
		return htAllKeys_Values;
	}

	public HashMap<String, Vector<String>> getParameters2decode() {
		return parameters2decode;
	}
	
	
	public String getPreviousSessionCookieName()
	{
		return _sPreviousSessionCookieName;
	}

	public String getPreviousSessionAuthspID()
	{
		return _sPreviousSessionAuthspID;
	}

	public int getPreviousSessionCookieAge()
	{
		return _iPreviousSessionCookieAge;
	}

	public synchronized HashMap<String, HashMap<String, Pattern>> getParameters2forward()
	{
		return parameters2forward;
	}



}