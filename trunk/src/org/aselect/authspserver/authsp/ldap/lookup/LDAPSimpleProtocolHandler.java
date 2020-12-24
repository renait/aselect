/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */

package org.aselect.authspserver.authsp.ldap.lookup;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.logging.Level;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NoPermissionException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.aselect.authspserver.authsp.ldap.Errors;
import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.session.PersistentManager;
import org.aselect.authspserver.session.PersistentStorageManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * @author remy
 *
 */
public class LDAPSimpleProtocolHandler extends org.aselect.authspserver.authsp.ldap.LDAPSimpleProtocolHandler {

	protected static String _sModule = "lookup.LDAPSimpleProtocolHandler";

	protected static final String LOOKUP_PARAMETER_USERNAME = "lookup_username";
	protected static final String LOOKUP_PARAMETER_STORAGE_MANAGER = "lookup_storage";

	protected static final String LOOKUP_PARAMETER_DECRYPTION_KEYSTORE = "lookup_decryption_keystore";
	protected static final String LOOKUP_PARAMETER_DECRYPTION_ALIAS = "lookup_decryption_alias";
	protected static final String LOOKUP_PARAMETER_DECRYPTION_PASSWORD = "lookup_decryption_password";
	
	protected String lookup_field = null;
	protected String lookup_storage_manager = null;
	
	protected PrivateKey priv_key = null;

	/**
	 * 
	 */
	public LDAPSimpleProtocolHandler() {
		super();
	}

	/**
	 * Tries to bind to the LDAP server using the users credentials. <br>
	 * Basically the same as superclass but does a lookup on UserDN first and replaces with retrieved value <br>
 	 * from persistent storage 'lookup'. <br>
	 * <b>Description:</b> <br>
	 * If no principal DN is known a simple binding is done, otherwise a subtree search. In this case the following
	 * steps are executed:
	 * <ol>
	 * <li>Bind to LDAP using security principal its DN & PWD</li>
	 * <li>Search for user its DN relative to base DN</li>
	 * <li>Bind using user credentials</li>
	 * </ol>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sPassword != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sPassword
	 *            the password
	 * @throws ASelectException
	 *             the aselect exception
	 * @see org.aselect.authspserver.authsp.ldap.AbstractLDAPProtocolHandler#doBind(java.lang.String)
	 */
	@Override
	protected void doBind(String sPassword)
	throws ASelectException
	{
		String sMethod = "doBind";
		StringBuffer sbTemp = null;
		DirContext oDirContext = null, oPrincipalContext = null;
		String sQuery = null;
		String sRelUserDn = null;
		NamingEnumeration<SearchResult> enumSearchResults = null;
		Hashtable<String, String> htEnvironment = new Hashtable<String, String>();
		
		// trade in opaque uid for real uid
		String lookedUp = null;
		try {
			PersistentStorageManager persist = PersistentManager.getHandle(lookup_storage_manager);
			HashMap<String, Object> retrieved = (HashMap<String, Object>)persist.get(_sUid);
			if (retrieved == null) {
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, new ASelectException("Nothing retrieved from persistent storage"));
			}
			lookedUp = (String)retrieved.get(lookup_field);
			if (lookedUp == null) {
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, new ASelectException("Retrieved 'username' == null"));
			}
			if (priv_key != null) {
				lookedUp = decryptString(lookedUp, priv_key, null);	// for now assume UTF-8 encoding
				
			}
		}catch (ASelectStorageException e) {
			throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, e);
		}
		
//		String sEscapedUid = Utils.ldapEscape(_sUid, _sLdapEscapes, _systemLogger);
		String sEscapedUid = Utils.ldapEscape(lookedUp, _sLdapEscapes, _systemLogger);

		if (_sPrincipalDn.equals("")) {
			// If no principal DN is known, we do a simple user binding
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

			sbTemp = new StringBuffer(_sUserDn).append("=").append(sEscapedUid);  //append(_sUid);
			sbTemp.append(", ").append(_sBaseDn);
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);
			additionalSettings(htEnvironment);

			_systemLogger.log(Level.FINEST, _sModule, sMethod, "USR_BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple1");
			try {
				oDirContext = new InitialDirContext(htEnvironment);
				// NOTE: the user may not have permissions to upd/del his own account
				// So, just forget it: checkAllowedLogins(sbTemp.toString(), oDirContext);
			}
			catch (AuthenticationException e) {
				/*
				 * This exception is thrown when an authentication error occurs while accessing the naming or directory
				 * service. An authentication error can happen, for example, when the credentials supplied by the user
				 * program is invalid or otherwise fails to authenticate the user to the naming/directory service.
				 */
				StringBuffer sbFine = new StringBuffer("Could not authenticate user (invalid password): ");
				sbFine.append(Auxiliary.obfuscate(_sUid));
				_systemLogger.log(Level.FINEST, _sModule, sMethod, sbFine.toString());
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
			}
			catch (CommunicationException eC) {
				/*
				 * This exception is thrown when the client is unable to communicate with the directory or naming
				 * service. The inability to communicate with the service might be a result of many factors, such as
				 * network partitioning, hardware or interface problems, failures on either the client or server side.
				 * This exception is meant to be used to capture such communication problems.
				 * The root cause can contain additional SSL error information.
				 */
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: \"");
					sbTemp.append(tRoot.getMessage()).append("\"");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				// The initial directory context could not be created.
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occurred", eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}
			finally {
				try {
					if (oDirContext != null)
						oDirContext.close();
				}
				catch (Exception e) {
					sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
				}
			}
			return;
		}

		oDirContext = null;  // just to make sure
		try {
			// Otherwise we do a subtree search using the principal dn
			// Step 1: bind to LDAP using security principal's DN & PWD
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver); // USED TO BE: _sLDAPUrl);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, _sPrincipalDn);
			htEnvironment.put(Context.SECURITY_CREDENTIALS, _sPrincipalPwd);
			additionalSettings(htEnvironment);
	
//			_systemLogger.log(Level.FINEST, _sModule, sMethod, "PRINCP_BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple2"
//					+ "_" + _sPrincipalDn + "_" + _sPrincipalPwd);
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "PRINCP_BIND " + _sLDAPUrl + "_" + _sDriver + "_" + "simple2");
			try {
				oPrincipalContext = new InitialDirContext(htEnvironment);
				_systemLogger.log(Level.INFO, _sModule, sMethod, "Principal login OK");
			}
			catch (AuthenticationException eA) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not bind to LDAP server", eA);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER, eA);
			}
			catch (CommunicationException eC) {
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: \"");
					sbTemp.append(tRoot.getMessage()).append("\"");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "An naming error has occurred", eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}
	
			// DirContext creation using the principal DN succeeded
			// Step 2: search for user's DN relative to base DN
			sbTemp = new StringBuffer("(").append(_sUserDn).append("=").append(sEscapedUid/*_sUid*/).append(")");
			sQuery = sbTemp.toString();
	
			SearchControls oScope = new SearchControls();
			oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
	
//			_systemLogger.log(Level.FINEST, _sModule, sMethod, "SRCH " + _sBaseDn + "_" + sQuery + "_sub");
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "SRCH " + _sBaseDn + "_sub");
			try {
				enumSearchResults = oPrincipalContext.search(_sBaseDn, sQuery, oScope);
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("User '").append(Auxiliary.obfuscate(_sUid)).append("' is unknown");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}
	
			try {  // Check if we got a result
				if (!enumSearchResults.hasMore()) {
					sbTemp = new StringBuffer("User '").append(Auxiliary.obfuscate(_sUid));
//					sbTemp.append("' not found during LDAP search. The filter was: '").append(sQuery).append("'.");
					sbTemp.append("' not found during LDAP search.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}
	
				SearchResult oSearchResult = (SearchResult) enumSearchResults.next();
				sRelUserDn = oSearchResult.getName();
				// prevent memory leaks in shaky LDAP implementations(154)
				enumSearchResults.close();
				if (sRelUserDn == null) {
					sbTemp = new StringBuffer("No user DN was returned for '").append(Auxiliary.obfuscate(_sUid)).append("'.");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString());
					throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
				}
			}
			catch (NamingException eN) {
				sbTemp = new StringBuffer("failed to fetch profile of user '").append(Auxiliary.obfuscate(_sUid)).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_AUTHENTICATE_USER);
			}
	
			// Step 3: Bind using the user's credentials
			sbTemp = new StringBuffer(sRelUserDn).append(",").append(_sBaseDn);
			htEnvironment = new Hashtable<String, String>();
			htEnvironment.put(Context.PROVIDER_URL, _sLDAPUrl);
			htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
			htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
			htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
			htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);
			additionalSettings(htEnvironment);
	
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "USR_BIND " + _sLDAPUrl + "_" + _sDriver +
					"_" + "simple3");
			try {
				oDirContext = new InitialDirContext(htEnvironment);
				// User login succeeded
				_systemLogger.log(Level.INFO, _sModule, sMethod, "User login OK");
				// The user may not have permissions to upd/del account, therefore use the Principal account
				int rc = checkAllowedLogins(sbTemp.toString(), oPrincipalContext);
				if (rc != 0) {
					_systemLogger.log(Level.INFO, _sModule, sMethod, "Account not OK, either no logins left, or login no longer valid");
					throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
				}
			}
			catch (NoPermissionException eP) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "No permission: expl=" + eP.getExplanation(), eP);
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD, eP);
			}
			catch (AuthenticationException e) {
				StringBuffer sbFine = new StringBuffer("Could not authenticate user (invalid password): ").append(Auxiliary.obfuscate(_sUid))
									.append(" expl="+e.getExplanation()).append(" cause="+e.getCause());
				_systemLogger.log(Level.INFO, _sModule, sMethod, sbFine.toString());
				throw new ASelectException(Errors.ERROR_LDAP_INVALID_PASSWORD);
			}
			catch (CommunicationException eC) {
				Throwable tRoot = eC.getRootCause();
				if (tRoot == null) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "A communication error has occurred", eC);
				}
				else {
					sbTemp = new StringBuffer("A communication error has occurred, root cause: '");
					sbTemp.append(tRoot.getMessage()).append("'");
					_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), eC);
				}
				throw new ASelectException(Errors.ERROR_LDAP_COULD_NOT_REACH_LDAP_SERVER, eC);
			}
			catch (NamingException eN) {
				_systemLogger.log(Level.WARNING, _sModule, sMethod, "A naming error has occurred: expl=" + eN.getExplanation(), eN);
				throw new ASelectException(Errors.ERROR_LDAP_INTERNAL_ERROR, eN);
			}
		}
		finally {
			try {
				if (oDirContext != null) oDirContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
			try {
				if (oPrincipalContext != null) oPrincipalContext.close();
			}
			catch (Exception e) {
				sbTemp = new StringBuffer("Could not close connection to '").append(_sLDAPUrl).append("'");
				_systemLogger.log(Level.WARNING, _sModule, sMethod, sbTemp.toString(), e);
			}
		}			
	}
	
	// RH, 20191003, sn
	public boolean postInit(Object oConfig, String sUid, SystemLogger oSystemLogger) {
		String sMethod = "postInit";
		
		boolean returnValue = false;

		_sModule = "lookup.LDAPSimpleProtocolHandler";
		AuthSPConfigManager _configManager = AuthSPConfigManager.getHandle();
		_systemLogger.log(Level.FINEST, _sModule, sMethod, "_configManager="+_configManager);

		try {
			lookup_field = _configManager.getParam(oConfig, LOOKUP_PARAMETER_USERNAME);
			lookup_storage_manager = _configManager.getParam(oConfig, LOOKUP_PARAMETER_STORAGE_MANAGER);
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "lookup_field="+lookup_field);
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "lookup_storage_manager="+lookup_storage_manager);
			returnValue = true;
			String lookup_keystore = null;
			try {
				lookup_keystore = _configManager.getParam(oConfig, LOOKUP_PARAMETER_DECRYPTION_KEYSTORE);
			} catch (ASelectConfigException e) {
				_systemLogger.log(Level.FINER, _sModule, sMethod, "Could not retrieve : " + LOOKUP_PARAMETER_DECRYPTION_KEYSTORE 
						+ " from authsp section. Continuing without decryption");
			}
			_systemLogger.log(Level.FINEST, _sModule, sMethod, "lookup_keystore="+lookup_keystore);
	
			if (lookup_keystore != null) {
				returnValue = false;	// if we have a keystore, other values must be present
				String lookup_alias = null;
				try {
					lookup_alias = _configManager.getParam(oConfig, LOOKUP_PARAMETER_DECRYPTION_ALIAS);
					_systemLogger.log(Level.FINEST, _sModule, sMethod, "lookup_alias="+lookup_alias);

					String pw = null;
					try {
						pw = _configManager.getParam(oConfig, LOOKUP_PARAMETER_DECRYPTION_PASSWORD);
						priv_key = Auxiliary.getPrivateKeyFromLocation(lookup_keystore, pw, lookup_alias, _systemLogger);
						if (priv_key != null) {	// all well
							returnValue = true;;
						} else {
							_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not retrieve private key from keystore.");
						}
					} catch (ASelectConfigException e) {
						_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not retrieve : " + LOOKUP_PARAMETER_DECRYPTION_PASSWORD 
								+ " from authsp section.");
					}
				} catch (ASelectConfigException e) {
					_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not retrieve : " + LOOKUP_PARAMETER_DECRYPTION_ALIAS 
							+ " from authsp section.");
				}
			}
		} catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "Could not retrieve one of: " + LOOKUP_PARAMETER_USERNAME 
					+ "or:" + LOOKUP_PARAMETER_STORAGE_MANAGER + " from authsp section.");
		}
		return returnValue;
	}
	// RH, 20191003, en

	protected String decryptString(String cipher, PrivateKey priv_key, String encoding) {
		String sMethod = "encryptString";

		String plain = null;
		if (priv_key != null) {
			plain = Auxiliary.decryptRSAString(cipher, priv_key, _systemLogger);	// for now assume UTF-8 encoding
		} else {
			_systemLogger.log(Level.WARNING, _sModule, sMethod, "No private key provided for decryption, no decryption done!");
			plain = cipher;
		}
		return plain;
	}

}
