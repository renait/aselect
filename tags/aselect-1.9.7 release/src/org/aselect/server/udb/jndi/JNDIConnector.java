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
 * $Id: JNDIConnector.java,v 1.16 2006/05/03 10:11:56 tom Exp $ 
 * 
 * Changelog:
 * $Log: JNDIConnector.java,v $
 * Revision 1.16  2006/05/03 10:11:56  tom
 * Removed Javadoc version
 *
 * Revision 1.15  2006/03/16 14:49:35  martijn
 * optional full_uid config item is now supported
 *
 * Revision 1.14  2005/09/08 13:08:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.13  2005/04/29 11:37:53  erwin
 * Added isUserEnabled() and getUserAttributes() functionality
 *
 * Revision 1.12  2005/04/15 12:06:14  tom
 * Removed old logging statements
 *
 * Revision 1.11  2005/04/13 11:31:58  tom
 * Fixed javadoc
 *
 * Revision 1.10  2005/03/29 13:01:18  martijn
 * now logging the same authentication information as all other udb connectors
 *
 * Revision 1.9  2005/03/14 14:25:24  martijn
 * The UDBConnector init method expects the connector config section instead of a resource config section. The resource config will now be resolved when the connection with the resource must be opened.
 *
 * Revision 1.8  2005/03/11 10:44:06  remco
 * Renamed variable
 *
 * Revision 1.7  2005/03/09 10:24:17  erwin
 * Renamed and moved errors.
 *
 * Revision 1.6  2005/03/07 15:01:00  martijn
 * updated authentication log information
 *
 * Revision 1.4  2005/03/02 14:17:51  remco
 * Fixed a few bugs
 *
 * Revision 1.3  2005/02/28 15:46:38  martijn
 * changed all variable names to naming convention and added java documentation
 *
 */

package org.aselect.server.udb.jndi;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Set;
import java.util.logging.Level;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.server.udb.IUDBConnector;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.exception.ASelectUDBException;
import org.aselect.system.sam.agent.SAMResource;

// TODO: Auto-generated Javadoc
/**
 * JNDI database connector. <br>
 * <br>
 * <b>Description:</b><br>
 * Class for fetching the user's profile using JNDI (LDAP, Active Directory etc.) <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public class JNDIConnector implements IUDBConnector
{
	/**
	 * The name of the class, used for logging.
	 */
	private final static String MODULE = "JNDIConnector";
	/**
	 * Logger for logging system logging
	 */
	private ASelectSystemLogger _oASelectSystemLogger;
	/**
	 * Logger for logging authentication logging
	 */
	private ASelectAuthenticationLogger _oASelectAuthenticationLogger;
	/**
	 * Contains all AuthSPs configured in the A-Select Server configuration
	 */
	private HashMap _htConfiguredAuthSPs;

	/**
	 * Config item for base dn
	 */
	private String _sBaseDN;
	/**
	 * Config item for user dn
	 */
	private String _sUserDN;
	/**
	 * Config item for full uid
	 */
	private boolean _bFullUid;
	/**
	 * The configured resourcegroup
	 */
	private String _sUDBResourceGroup;

	/**
	 * The ASelect SAMAgent for retrieving an available resource
	 */
	private ASelectSAMAgent _oASelectSAMAgent;

	/**
	 * The ASelect Config Manager
	 */
	private ASelectConfigManager _oASelectConfigManager;

	/**
	 * Initializes managers and opens a JNDI connection to the A-Select user db. <br>
	 * <br>
	 * 
	 * @param oConfigSection
	 *            the o config section
	 * @throws ASelectUDBException
	 *             the a select udb exception
	 * @see org.aselect.server.udb.IUDBConnector#init(java.lang.Object)
	 */
	public void init(Object oConfigSection)
		throws ASelectUDBException
	{
		String sMethod = "init()";
		_htConfiguredAuthSPs = new HashMap();
		Object oAuthSPs = null;
		Object oAuthSP = null;
		String sAuthSPID = null;

		try {
			// get system logger
			_oASelectSystemLogger = ASelectSystemLogger.getHandle();

			// get authentication logger
			_oASelectAuthenticationLogger = ASelectAuthenticationLogger.getHandle();

			// get xml config manager
			_oASelectConfigManager = ASelectConfigManager.getHandle();

			// the A-Select SAM Agent
			_oASelectSAMAgent = ASelectSAMAgent.getHandle();

			// reads the connector configuration
			readConfig(oConfigSection);

			// check if there is at least one active resource available
			getConnection();

			// Get all enabled AuthSPs from config
			try {
				oAuthSPs = _oASelectConfigManager.getSection(null, "authsps");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config section 'authsps' found in main A-Select config", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				oAuthSP = _oASelectConfigManager.getSection(oAuthSPs, "authsp");
			}
			catch (Exception e) {
				_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
						"No config section 'authsps' found in main A-Select config", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			while (oAuthSP != null) {
				try {
					sAuthSPID = _oASelectConfigManager.getParam(oAuthSP, "id");
				}
				catch (Exception e) {
					_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
							"No config item 'id' found in 'authsp' section", e);

					throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				_htConfiguredAuthSPs.put(sAuthSPID.toUpperCase(), sAuthSPID);
				oAuthSP = _oASelectConfigManager.getNextSection(oAuthSP);
			}
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize JNDI Connector", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Resolves all user attributes from the JNDI back-end. <br>
	 * <br>
	 * Returns a hashtable with the user's record:<br>
	 * <table>
	 * <tr>
	 * <td><b>Item</b></td>
	 * <td><b>Value</b></td>
	 * </tr>
	 * <tr>
	 * <td><code>result_code</code></td>
	 * <td>Specifies an <code>Errors.NO_ERROR</code> for success or an relevant A-Select Error.</td>
	 * </tr>
	 * <tr>
	 * <td><code>user_authsps</code></td>
	 * <td>HashMap containing the AuthSP's that the user is registered for.<br>
	 * Within this hashtable each AuthSP has an entry with the value of the user attributes that specific AuthSP.</td>
	 * </tr>
	 * </table>
	 * <br>
	 * <br>
	 * <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return the user profile
	 * @see org.aselect.server.udb.IUDBConnector#getUserProfile(java.lang.String)
	 */
	public HashMap getUserProfile(String sUserId)
	{
		String sMethod = "getUserProfile()";

		DirContext oDirContext = null;
		HashMap htResponse = new HashMap();
		NamingEnumeration oSearchResults = null;
		String sAttribute = null;
		String sAttributeValue = null;
		StringBuffer sbQuery = null;

		Attribute oAttribute = null;
		Attributes oAttributes = null;
		HashMap htUserAttributes = new HashMap();
		HashMap htUserRecord = new HashMap();

		htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);

		try {
			if (sUserId.indexOf("*") >= 0 || sUserId.indexOf("?") >= 0 || sUserId.indexOf("=") >= 0) {
				StringBuffer sbBuffer = new StringBuffer("User id contains illegal characters: ");
				sbBuffer.append(sUserId);
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "User unknown");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			if (!_bFullUid) {
				int iIndex = sUserId.indexOf('@');
				if (iIndex > 0)
					sUserId = sUserId.substring(0, iIndex);
			}

			sbQuery = new StringBuffer("(").append(_sUserDN).append("=").append(sUserId).append(")");
			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

			oDirContext = getConnection();
			try {
				_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "Query="+sbQuery.toString());
				oSearchResults = oDirContext.search(_sBaseDN, sbQuery.toString(), oScope);
			}
			catch (NamingException e) {
				StringBuffer sbBuffer = new StringBuffer("User unknown: ");
				sbBuffer.append(sUserId);
				sbBuffer.append(e.getMessage());
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString(), e);
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "User unknown");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			// Check if we got a result
			if (!oSearchResults.hasMore()) {
				StringBuffer sbBuffer = new StringBuffer("User '");
				sbBuffer.append(sUserId);
				sbBuffer.append("' not found during LDAP search. The filter was: ");
				sbBuffer.append(sbQuery.toString());
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "User unknown");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			// Put all data in a hastable.
			// We only handle the first returned record.
			SearchResult oSearchResult = (SearchResult) oSearchResults.next();
			oAttributes = oSearchResult.getAttributes();

			for (NamingEnumeration oAttrEnum = oAttributes.getAll(); oAttrEnum.hasMore();) {
				oAttribute = (Attribute) oAttrEnum.next();
				sAttribute = oAttribute.getID();
				try {
					sAttributeValue = (String) oAttribute.get();
				}
				catch (Exception e) {
					sAttributeValue = "";
				}

				if (sAttributeValue == null)
					sAttributeValue = "";

				htUserRecord.put(sAttribute.toUpperCase(), sAttributeValue);
			}

			sAttributeValue = (String) htUserRecord.get("ASELECTACCOUNTENABLED");

			// check if the AccountEnabled value is Set
			if (sAttributeValue == null) {
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED, "User account disabled");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED);
			}
			// check if the account is enabled
			if (sAttributeValue.equalsIgnoreCase("false")) {
				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED, "User account disabled");
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED);
			}

			// resolve all user attributes
			Set keys = htUserRecord.keySet();
			for (Object s : keys) {
				String sAttributeName = (String) s;
				sAttributeValue = (String) htUserRecord.get(sAttributeName);
				if (sAttributeName.startsWith("ASELECT") && sAttributeName.endsWith("REGISTERED")) {
					// Only store user attributes of authsps that are registered for the user
					if (sAttributeValue.equalsIgnoreCase("TRUE")) {
						// The authsp id is the substring between ASELECT(7 chars) and REGISTERED(10 chars)
						String sAuthSPID = sAttributeName.substring(7, sAttributeName.length() - 10);

						StringBuffer sbUserAttributes = new StringBuffer("ASELECT");
						sbUserAttributes.append(sAuthSPID);
						sbUserAttributes.append("USERATTRIBUTES");
						sAttributeValue = (String) htUserRecord.get(sbUserAttributes.toString());
						_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "Attr "+sbUserAttributes+"="+sAttributeValue);
						
						// The user attribute is used as a login name later on,
						// but apparently it can be empty too!
						if (sAttributeValue == null)
							sAttributeValue = "";

						String sCFGAuthSPID = (String) _htConfiguredAuthSPs.get(sAuthSPID);
						if (sCFGAuthSPID != null)
							htUserAttributes.put(sCFGAuthSPID, sAttributeValue);
						// Result looks like: Ldap=<value of AselectLdapUserAttributes>
						_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, "Tranlated "+sAuthSPID+" to "+sCFGAuthSPID+" value="+sAttributeValue);
					}
				}
			}

			if (htUserAttributes.size() == 0) {
				StringBuffer sbBuffer = new StringBuffer("No user attributes found for user: ");
				sbBuffer.append(sUserId);
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_COULD_NOT_AUTHENTICATE_USER);
			}

			htResponse.put("user_authsps", htUserAttributes);
			htResponse.put("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (ASelectUDBException e) {
			htResponse.put("result_code", e.getMessage());
		}
		catch (Exception e) {
			StringBuffer sbBuffer = new StringBuffer("Failed to fetch profile of user ");
			sbBuffer.append(sUserId);
			sbBuffer.append(": ");
			sbBuffer.append(e.getMessage());
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod, sbBuffer.toString(), e);
			htResponse.put("result_code", Errors.ERROR_ASELECT_UDB_INTERNAL);
		}
		finally {
			try {
				if (oSearchResults != null)
					oSearchResults.close();
				if (oDirContext != null)
					oDirContext.close();
			}
			catch (Exception e) {
			}
		}
		return htResponse;
	}

	/**
	 * Retrieve the A-Select user attributes. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @param sAuthSPId
	 *            the s auth sp id
	 * @return the user attributes
	 * @throws ASelectUDBException
	 *             the a select udb exception
	 * @see org.aselect.server.udb.IUDBConnector#getUserAttributes(java.lang.String, java.lang.String)
	 */
	public String getUserAttributes(String sUserId, String sAuthSPId)
		throws ASelectUDBException
	{
		String sMethod = "getUserAttributes()";

		DirContext oDirContext = null;
		NamingEnumeration oSearchResults = null;
		String sAttributeName = null;
		String sAttributeValue = null;
		StringBuffer sbQuery = null;

		Attribute oAttribute = null;
		Attributes oAttributes = null;

		try {
			if (sUserId.indexOf("*") >= 0 || sUserId.indexOf("?") >= 0 || sUserId.indexOf("=") >= 0) {
				StringBuffer sbBuffer = new StringBuffer("User id contains illegal characters: '");
				sbBuffer.append(sUserId).append("'");
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				return null;
			}

			if (!_bFullUid) {
				int iIndex = sUserId.indexOf('@');
				if (iIndex > 0)
					sUserId = sUserId.substring(0, iIndex);
			}

			sbQuery = new StringBuffer("(");
			sbQuery.append(_sUserDN);
			sbQuery.append("=");
			sbQuery.append(sUserId);
			sbQuery.append(")");

			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

			oDirContext = getConnection();

			_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "JndiATTR BASE=" + _sBaseDN + ", QRY=" + sbQuery);
			try {
				oSearchResults = oDirContext.search(_sBaseDN, sbQuery.toString(), oScope);
			}
			catch (NamingException e) {
				StringBuffer sbBuffer = new StringBuffer("User unknown: ");
				sbBuffer.append(sUserId);
				sbBuffer.append(e.getMessage());
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString(), e);

				logAuthentication(sUserId, Errors.ERROR_ASELECT_UDB_UNKNOWN_USER, "User unknown");

				throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_UNKNOWN_USER);
			}

			// Check if we got a result
			if (oSearchResults.hasMore()) {
				// We only handle the first returned record.
				SearchResult oSearchResult = (SearchResult) oSearchResults.next();
				oAttributes = oSearchResult.getAttributes();
				boolean bFound = false; // attribute found

				_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "JndiATTR Attr=" + oAttributes);
				for (NamingEnumeration oAttrEnum = oAttributes.getAll(); oAttrEnum.hasMore() && !bFound;) {
					oAttribute = (Attribute) oAttrEnum.next();
					sAttributeName = oAttribute.getID();

					StringBuffer sbUserAttributes = new StringBuffer("ASELECT");
					sbUserAttributes.append(sAuthSPId);
					sbUserAttributes.append("USERATTRIBUTES");
					if (sAttributeName.equalsIgnoreCase(sbUserAttributes.toString())) {
						try {
							sAttributeValue = (String) oAttribute.get();
						}
						catch (Exception e) {
							StringBuffer sb = new StringBuffer(
									"Error retrieving A-Select attributes value for authsp: '");
							sb.append(sAuthSPId).append("', user: '");
							sb.append(sUserId).append("'");
							_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
						}
						bFound = true;
					}
				}
				if (sAttributeValue == null) {
					StringBuffer sb = new StringBuffer("User attributes for AuthSP: '");
					sb.append(sAuthSPId).append("' not found for user: '");
					sb.append(sUserId).append("'");
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
				}
			}
			else {
				StringBuffer sbBuffer = new StringBuffer("User '");
				sbBuffer.append(sUserId);
				sbBuffer.append("' not found during LDAP search. The filter was: ");
				sbBuffer.append(sbQuery.toString());
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
			}
		}
		catch (NamingException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not execute JNDI query", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL, e);
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (ASelectSAMException e) {
			throw new ASelectUDBException(e.getMessage(), e);
		}
		finally {
			try {
				if (oSearchResults != null)
					oSearchResults.close();
				if (oDirContext != null)
					oDirContext.close();
			}
			catch (Exception e) {
			}
		}
		return sAttributeValue;
	}

	/**
	 * Check if user is A-Select enabled. <br>
	 * <br>
	 * 
	 * @param sUserId
	 *            the s user id
	 * @return true, if checks if is user enabled
	 * @throws ASelectUDBException
	 *             the a select udb exception
	 * @see org.aselect.server.udb.IUDBConnector#isUserEnabled(java.lang.String)
	 */
	public boolean isUserEnabled(String sUserId)
		throws ASelectUDBException
	{
		String sMethod = "isUserEnabled()";

		DirContext oDirContext = null;
		boolean bIsEnabled = false;
		NamingEnumeration oSearchResults = null;
		String sAttribute = null;
		String sAttributeValue = null;
		StringBuffer sbQuery = null;

		Attribute oAttribute = null;
		Attributes oAttributes = null;

		try {
			if (sUserId.indexOf("*") >= 0 || sUserId.indexOf("?") >= 0 || sUserId.indexOf("=") >= 0) {
				StringBuffer sbBuffer = new StringBuffer("User id contains illegal characters: '");
				sbBuffer.append(sUserId).append("'");
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
				return false;
			}

			if (!_bFullUid) {
				int iIndex = sUserId.indexOf('@');
				if (iIndex > 0)
					sUserId = sUserId.substring(0, iIndex);
			}

			sbQuery = new StringBuffer("(");
			sbQuery.append(_sUserDN);
			sbQuery.append("=");
			sbQuery.append(sUserId);
			sbQuery.append(")");

			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

			oDirContext = getConnection();

			oSearchResults = oDirContext.search(_sBaseDN, sbQuery.toString(), oScope);

			// Check if we got a result
			if (oSearchResults.hasMore()) {
				// Put all data in a hash table.
				// We only handle the first returned record.
				SearchResult oSearchResult = (SearchResult) oSearchResults.next();
				oAttributes = oSearchResult.getAttributes();
				boolean bFound = false; // attribute found
				for (NamingEnumeration oAttrEnum = oAttributes.getAll(); oAttrEnum.hasMore() && !bFound;) {
					oAttribute = (Attribute) oAttrEnum.next();
					sAttribute = oAttribute.getID();
					if (sAttribute.equalsIgnoreCase("ASELECTACCOUNTENABLED")) {
						try {
							sAttributeValue = (String) oAttribute.get();
						}
						catch (Exception e) {
							StringBuffer sb = new StringBuffer("Error retrieving A-Select account enabled attribute value for user '");
							sb.append(sUserId).append("'");
							_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sb.toString(), e);
						}
						if (sAttributeValue != null && sAttributeValue.equalsIgnoreCase("true")) {
							// account enabled
							bIsEnabled = true;
							bFound = true; // stop searching
						}
						else // user not enabled
						{
							bFound = true; // stop searching
						}
					}
				}
				if (!bIsEnabled) {
					StringBuffer sb = new StringBuffer("User not A-Select enabled: '");
					sb.append(sUserId).append("' ").append(Errors.ERROR_ASELECT_UDB_USER_ACCOUNT_DISABLED);
					_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sb.toString());
				}
			}
			else {
				StringBuffer sbBuffer = new StringBuffer("User '");
				sbBuffer.append(sUserId);
				sbBuffer.append("' not found during LDAP search. The filter was: ");
				sbBuffer.append(sbQuery.toString());
				_oASelectSystemLogger.log(Level.FINE, MODULE, sMethod, sbBuffer.toString());
			}

		}
		catch (NamingException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not execute JNDI query", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_UDB_INTERNAL, e);
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (ASelectSAMException e) {
			throw new ASelectUDBException(e.getMessage(), e);
		}
		finally {
			try {
				if (oSearchResults != null)
					oSearchResults.close();
				if (oDirContext != null)
					oDirContext.close();
			}
			catch (Exception e) {
			}
		}
		return bIsEnabled;
	}

	/**
	 * Creates an <code>HashMap</code> containing the JNDI environment variables. <br>
	 * <br>
	 * 
	 * @param sDriver
	 *            The JNDI driver that must be used
	 * @param sPrincipal
	 *            The principal dn
	 * @param sPassword
	 *            The password to use while connecting
	 * @param sUseSSL
	 *            indicates if an ssl connection must be created
	 * @param sUrl
	 *            The connection url
	 * @return a <code>Hastable</code> containing the JNDI environment variables
	 */
	private Hashtable createJNDIEnvironment(String sDriver, String sPrincipal, String sPassword, String sUseSSL,
			String sUrl)
	{
		Hashtable htEnvironment = new Hashtable(11);

		htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, sDriver);
		htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
		htEnvironment.put(Context.SECURITY_PRINCIPAL, sPrincipal);
		htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

		if (sUseSSL.equalsIgnoreCase("true")) {
			htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
		}

		htEnvironment.put(Context.PROVIDER_URL, sUrl);

		return htEnvironment;
	}

	/**
	 * Only reads the configuration items for this component. <br>
	 * <br>
	 * 
	 * @param oConfigSection
	 *            The config section containing the config for this component
	 * @throws ASelectUDBException
	 *             if a mandatory config item doesn't exist or is invalid
	 */
	private void readConfig(Object oConfigSection)
		throws ASelectUDBException
	{
		String sMethod = "readConfig()";
		_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "JNDIConf oConfigSection=" + oConfigSection);
		try {
			try {
				_sBaseDN = _oASelectConfigManager.getParam(oConfigSection, "base_dn");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No valid config item 'base_dn' found in connector configuration", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sUserDN = _oASelectConfigManager.getParam(oConfigSection, "user_dn");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No valid config item 'user_dn' found in connector configuration", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			String sFullUid = null;
			try {
				sFullUid = _oASelectConfigManager.getParam(oConfigSection, "full_uid");
			}
			catch (ASelectConfigException e) {
				sFullUid = "false";

				_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
						"No config item 'full_uid' found in connector configuration, using default: full_uid = "
								+ sFullUid, e);
			}

			if (sFullUid.equalsIgnoreCase("true"))
				_bFullUid = true;
			else if (sFullUid.equalsIgnoreCase("false"))
				_bFullUid = false;
			else {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No valid config item 'full_uid' found in connector configuration: " + sFullUid);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			try {
				_sUDBResourceGroup = _oASelectConfigManager.getParam(oConfigSection, "resourcegroup");
			}
			catch (ASelectConfigException e) {
				_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
						"No 'resourcegroup' config item found in udb 'connector' config section.", e);

				throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "JNDIConf _sBaseDN=" + _sBaseDN + ", _sUserDN="
					+ _sUserDN + ", sFullUid=" + sFullUid + ", _sUDBResourceGroup=" + _sUDBResourceGroup);
		}
		catch (ASelectUDBException e) {
			throw e;
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.SEVERE, MODULE, sMethod,
					"Could not read the JNDI udb connector configuration", e);

			throw new ASelectUDBException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Opens a new JNDI connection to the resource that is retrieved from the SAMAgent. <br>
	 * <br>
	 * 
	 * @return <code>DirContext</code> that contains the JNDI connection
	 * @throws ASelectUDBException
	 *             if the connection could not be opened
	 * @throws ASelectSAMException
	 *             if no valid resource could be found
	 */
	private DirContext getConnection()
		throws ASelectUDBException, ASelectSAMException
	{
		String sMethod = "getConnection()";

		SAMResource oSAMResource = null;
		String sDriver = null;
		String sPrincipal = null;
		String sPassword = null;
		String sUseSSL = null;
		String sUrl = null;
		InitialDirContext oInitialDirContext = null;
		Object oResourceConfig = null;

		try {
			oSAMResource = _oASelectSAMAgent.getActiveResource(_sUDBResourceGroup);
		}
		catch (ASelectSAMException e) {
			StringBuffer sbFailed = new StringBuffer("No active resource found in udb resourcegroup: ");
			sbFailed.append(_sUDBResourceGroup);
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, sbFailed.toString(), e);
			throw e;
		}

		oResourceConfig = oSAMResource.getAttributes();
		try {
			sDriver = _oASelectConfigManager.getParam(oResourceConfig, "driver");
		}
		catch (ASelectConfigException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'driver' found in connector configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sPrincipal = _oASelectConfigManager.getParam(oResourceConfig, "security_principal_dn");
		}
		catch (ASelectConfigException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'security_principal_dn' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sPassword = _oASelectConfigManager.getParam(oResourceConfig, "security_principal_password");
		}
		catch (ASelectConfigException e) {
			_oASelectSystemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Invalid or empty config item 'security_principal_password' found in connector resource configuration, using empty password.",
							e);
		}

		try {
			sUseSSL = _oASelectConfigManager.getParam(oResourceConfig, "ssl");
		}
		catch (ASelectConfigException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'ssl' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			sUrl = _oASelectConfigManager.getParam(oResourceConfig, "url");
		}
		catch (ASelectConfigException e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod,
					"No valid config item 'url' found in connector resource configuration", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_CONFIG_ERROR, e);
		}

		try {
			_oASelectSystemLogger.log(Level.INFO, MODULE, sMethod, "JNDI " + sDriver + "_" + sPrincipal + "_"
					+ sPassword + "_" + sUseSSL + "_" + sUrl);
			oInitialDirContext = new InitialDirContext(createJNDIEnvironment(sDriver, sPrincipal, sPassword, sUseSSL, sUrl));
		}
		catch (Exception e) {
			_oASelectSystemLogger.log(Level.WARNING, MODULE, sMethod, "Could not create JNDI environment", e);
			throw new ASelectUDBException(Errors.ERROR_ASELECT_IO, e);
		}

		return oInitialDirContext;
	}

	/**
	 * Sorts authentication logging parameters and logs them. <br>
	 * <br>
	 * 
	 * @param sUserID
	 *            The A-Select user id
	 * @param sErrorCode
	 *            The error code of the error that occured
	 * @param sMessage
	 *            The authentication log message
	 */
	private void logAuthentication(String sUserID, String sErrorCode, String sMessage)
	{
		_oASelectAuthenticationLogger.log(new Object[] {
			MODULE, sUserID, null, null, null, sMessage, sErrorCode
		});
	}
}