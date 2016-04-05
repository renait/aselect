/*
 * Created on 28-aug-2007
 */
package org.aselect.server.request.handler.xsaml20;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map.Entry;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.RequestedAuthnContext;

public class SecurityLevel
{
	final static String MODULE = "SecurityLevel";
	
	// Level of Assurance (loa)
	// Used by: Elektronische Toegangsdiensten (ETD), no levels 2 and 7
	final private static String LOA1 = "urn:etoegang:core:assurance-class:loa1";  // 5
	final private static String LOA2 = "urn:etoegang:core:assurance-class:loa2";  // 10
	final private static String LOA2PLUS= "urn:etoegang:core:assurance-class:loa2plus";  // 15
	final private static String LOA3 = "urn:etoegang:core:assurance-class:loa3";  // 20
	final private static String LOA4 = "urn:etoegang:core:assurance-class:loa4";  // 30

	// Standard SAML levels, 2 and 7 private additions?
	final private static String PREVIOUSSESSION_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";  // 2	// RH, 20141113, n
	final private static String UNSPECIFIED_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";  // 5
	final private static String PASSWORD_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";  // 7
	final private static String PASSWORDPROTECTEDTRANSPORT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";  // 10
	final private static String MOBILETWOFACTORUNREGISTERED_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered";  // 15
	//final private static String MOBILETWOFACTORCONTRACT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";  // Novell
	final private static String MOBILETWOFACTORCONTRACT_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";  // 20
	final private static String SMARTCARDPKI_URI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";  // 30

	// We might want to refer to these levels from other Classes so make them public
	final private static int LEVEL_NOT_FOUND = -1;
	final private static int LEVEL_MIN = 0;  // used for searching
	final private static int LEVEL_MAX = 999; // used for searching
	final public static int LEVEL_PREVIOUS = 2;	// RH, 20141113, n, used for previous_session
	final private static String LEVEL_LOWEST_SERIOUS = "5";  // The lowest serious level we have
	
//	final public static int LEVEL_NULL = 5;
//	final public static int LEVEL_POOR = 7;	// RH, 20120124, n
//	final public static int LEVEL_LOW = 10;
//	final public static int LEVEL_BETTER = 15;  // 20100714 was 5?!?
//	final public static int LEVEL_MEDIUM = 20;
//	final public static int LEVEL_HIGH = 30;
	
	// String versions of the same levels

/*	final private static String BN_PREVIOUS = "2";	// RH, 20141113, n, used for previous_session
	final private static String BN_POOR = "7";	// RH, 20120124, n
	final private static String BN_LOW = "10";
	final private static String BN_BETTER = "15";
	final private static String BN_MEDIUM = "20";
	final private static String BN_HOOG = "30";
	
	private static String[] aAlllowedLevels = {BN_PREVIOUS, BN_NUL, BN_POOR, BN_LOW, BN_BETTER, BN_MEDIUM,  BN_HOOG} ;	//  RH, 20141113, n
	public static Set<String> ALLOWEDLEVELS = new HashSet<String>(Arrays.asList(aAlllowedLevels));
	*/

	private static class SecurityLevelEntry
	{
		int sleLevel;
		String sleLevelString;
		String sleSamlUri;
		String sleLoaUri;
		
		SecurityLevelEntry(int level, String sLevel, String sSaml, String sLoa)
		{
			this.sleLevel = level;
			this.sleLevelString = sLevel;
			this.sleSamlUri = sSaml;
			this.sleLoaUri = sLoa;
		}		
	}
	
	private static SecurityLevelEntry[] allLevels =
	{
		new SecurityLevelEntry(2, "2", PREVIOUSSESSION_URI, null),
		new SecurityLevelEntry(5, "5", UNSPECIFIED_URI, LOA1),
		new SecurityLevelEntry(7, "7", PASSWORD_URI, null),
		new SecurityLevelEntry(10, "10", PASSWORDPROTECTEDTRANSPORT_URI, LOA2),
		new SecurityLevelEntry(15, "15", MOBILETWOFACTORUNREGISTERED_URI, LOA2PLUS),
		new SecurityLevelEntry(20, "20", MOBILETWOFACTORCONTRACT_URI, LOA3),
		new SecurityLevelEntry(30, "30", SMARTCARDPKI_URI, LOA4)
	};
	
	/**
	 * Checks if 'iLvel' is low, but not previous session.
	 * 
	 * @param iLevel
	 *            the i level
	 * @return true, if successful
	 */
	public static boolean isLowLevelButNotPreviousSession(int iLevel)
	{
		return (iLevel != LEVEL_PREVIOUS && iLevel <= 10);
	}

	/**
	 * Check all levels in 'secLevels' for validity.
	 * NOTE: no check whether the URI in our table has a value.
	 * 
	 * @param secLevels
	 *            the security levels to be checked
	 * @return true, if successful
	 */
	public static boolean checkAllValidLevels(HashMap<String, String> secLevels)
	{
		Iterator<?> secIter = secLevels.entrySet().iterator();
		while (secIter.hasNext()) {
			Entry<?, ?> secEntry = (Entry<?, ?>)secIter.next();
			String sKey = (String)secEntry.getKey();
			
			// Check the level against our table
			int i = 0;
			for (i = 0; i<allLevels.length; i++) {
				if (allLevels[i].sleLevelString.equals(sKey))  // level is OK
					break;
			}
			if (i >= allLevels.length)  // level was not found
				return false;
		}
		return true;
	}

	/**
	 * Convert level to authn context class ref uri.
	 * 
	 * @param sLevel
	 *            the required level
	 * @param useLoa
	 *            use Level of Assurance strings instead of standard Saml20
	 * @param systemLogger
	 *            the systemlogger
	 * @return the uri string
	 * @throws ASelectException
	 *             when the given level is invalid or cannot found
	 */
	public static String convertLevelToAuthnContextClassRefURI(String sLevel, boolean useLoa, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "convertLevelToAuthnContextClassRefURI";
		
		for (int i=0; i<allLevels.length; i++) {
			String useUri = (useLoa)? allLevels[i].sleLoaUri: allLevels[i].sleSamlUri;
			if (useUri != null && allLevels[i].sleLevelString.equals(sLevel))
				return useUri;
		}
		/* switch (iLevel) {
		// RH, 20141113, sn
		case LEVEL_PREVIOUS:
			return PREVIOUSSESSION_URI;
			// RH, 20141113, en
		case LEVEL_NULL:
			return UNSPECIFIED_URI;
		case LEVEL_POOR:	// RH, 20120124, sn
			return PASSWORD_URI;	// RH, 20120124, en
		case LEVEL_LOW:
			return PASSWORDPROTECTEDTRANSPORT_URI;
		case LEVEL_BETTER:
			return MOBILETWOFACTORUNREGISTERED_URI;
		case LEVEL_MEDIUM:
			return MOBILETWOFACTORCONTRACT_URI;
		case LEVEL_HIGH:
			return SMARTCARDPKI_URI;
		} */
		
		// Not found
		if (systemLogger != null)
			systemLogger.log(Level.SEVERE, MODULE, sMethod, "Level value: " + sLevel + " is not valid.");
		throw new ASelectException(Errors.ERROR_ASELECT_CONFIG_ERROR);
	}

	/**
	 * Convert authn context class ref uri to a level string.
	 * 
	 * @param sAuthnContextClassRefURI
	 *            the authn context class ref uri
	 * @param useLoa
	 *            use Level of Assurance instead of SAML20
	 * @param systemLogger
	 *            the systemlogger
	 * @return the uri string
	 * @throws ASelectException
	 *             when the uri string was not found
	 */
	public static String convertAuthnContextClassRefURIToLevel(String sAuthnContextClassRefURI, boolean useLoa, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "convertAuthnContextClassRefURIToLevel";

		for (int i=0; i<allLevels.length; i++) {
			String useUri = (useLoa)? allLevels[i].sleLoaUri: allLevels[i].sleSamlUri;
			if (useUri != null && useUri.equals(sAuthnContextClassRefURI))
				return allLevels[i].sleLevelString;
		}

		// Requested class uri not found
		if (systemLogger != null)
			systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnContextClassRefURI value: "+sAuthnContextClassRefURI+" is not valid.");
		throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);

		/*
		try {
			// RH, 20141113, sn
			if (sAuthnContextClassRefURI.equals(PREVIOUSSESSION_URI))
				return String.valueOf(LEVEL_PREVIOUS);
			// RH, 20141113, en
//			if (sAuthnContextClassRefURI.equals(UNSPECIFIED_URI))// RH, 20141113, o
			else if (sAuthnContextClassRefURI.equals(UNSPECIFIED_URI))// RH, 20141113, n
				return String.valueOf(LEVEL_NULL);
			else if (sAuthnContextClassRefURI.equals(PASSWORD_URI))		// RH, 20120124, sn
				return String.valueOf(LEVEL_POOR);	// RH, 20120124, en
			else if (sAuthnContextClassRefURI.equals(PASSWORDPROTECTEDTRANSPORT_URI))
				return String.valueOf(LEVEL_LOW);
			else if (sAuthnContextClassRefURI.equals(MOBILETWOFACTORUNREGISTERED_URI))
				return String.valueOf(LEVEL_BETTER);
			else if (sAuthnContextClassRefURI.equals(MOBILETWOFACTORCONTRACT_URI))
				return String.valueOf(LEVEL_MEDIUM);
			else if (sAuthnContextClassRefURI.equals(SMARTCARDPKI_URI))
				return String.valueOf(LEVEL_HIGH);

			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "AuthnContextClassRefURI value: "
						+ sAuthnContextClassRefURI + " is not valid.");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		catch (Exception e) {
			if (systemLogger != null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);

		}*/
	}

	/**
	 * Gets the Security Level as a String
	 */
/*
	private static String NOLONGERUSEDgetSecurityLevelFromContext(String sAuthnContextClassRef, boolean useLoa)
	{
		for (int i=0; i<allLevels.length; i++) {
			if (((useLoa)? allLevels[i].sleLoaUri: allLevels[i].sleSamlUri).equals(sAuthnContextClassRef))
				return allLevels[i].sleLevelString;
		}
//		if (sAuthnContextClassRef.equals(PREVIOUSSESSION_URI))			// RH, 20141113, sn
//			return BN_PREVIOUS;			// RH, 20141113, en
//		else if (sAuthnContextClassRef.equals(UNSPECIFIED_URI))			// RH, 20141113, n
//			return BN_NUL;
//		else if (sAuthnContextClassRef.equals(PASSWORD_URI))				// RH, 20120124, sn
//			return BN_POOR;						// RH, 20120124, en
//		else if (sAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
//			return BN_LOW;
//		else if (sAuthnContextClassRef.equals(MOBILETWOFACTORUNREGISTERED_URI))
//			return BN_BETTER;
//		else if (sAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
//			return BN_MEDIUM;
//		else if (sAuthnContextClassRef.equals(SMARTCARDPKI_URI))
//			return BN_HOOG;
		return null;
	}
*/

	/**
	 * Convert contextRef to Level (as String) from supplied HashMap with key=level, value=ContextRef
	 * 
	 * @param sAuthnContextClassRef
	 *           the reference to look for
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 * @return the Security Level or null if not found
	 */
	private static String getSecurityLevelFromContextUsingExternal(String sAuthnContextClassRef, HashMap<String, String> secLevels, boolean useLoa)
	{
		if (secLevels == null) {	// backward compatibility
			int iLevel = getIntSecurityLevel(sAuthnContextClassRef, useLoa);
			return convertSecurityLevelToString(iLevel);
			//return getSecurityLevelFromContext(sAuthnContextClassRef, useLoa);
		}
		
		// Consult the supplied 'secLevels' argument
		Iterator<?> secIter = secLevels.entrySet().iterator();
		while (secIter.hasNext()) {
			Entry<?, ?> secEntry = (Entry<?, ?>)secIter.next();
			if (sAuthnContextClassRef.equals(secEntry.getValue()) ) {
				return (String)secEntry.getKey();
			}
		}
		return null;
	}
	
	/**
	 * Translate the Security Level from int to String.
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @return the Security Level or null if not found
	 */
	private static String convertSecurityLevelToString(int iSecurityLevel)
	{
		for (int i=0; i<allLevels.length; i++) {
			if (allLevels[i].sleLevel == iSecurityLevel)
				return allLevels[i].sleLevelString;
		}
		/*
		if (iSecurityLevel == LEVEL_PREVIOUS)				// RH, 20141113, sn
			return BN_PREVIOUS;			// RH, 20141113, en
		else if (iSecurityLevel == LEVEL_NULL)
			return BN_NUL;
		else if (iSecurityLevel == LEVEL_POOR)				// RH, 20120124, sn
			return BN_POOR;							// RH, 20120124, en
		else if (iSecurityLevel == LEVEL_LOW)
			return BN_LOW;
		else if (iSecurityLevel == LEVEL_BETTER)
			return BN_BETTER;
		else if (iSecurityLevel == LEVEL_MEDIUM)
			return BN_MEDIUM;
		else if (iSecurityLevel == LEVEL_HIGH)
			return BN_HOOG;
		*/
		return null;
	}

	/**
	 * Convert URI Security Level to an integer.
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @return the Security Level
	 */
	private static int getIntSecurityLevel(String sCurrentAuthnContextClassRef, boolean useLoa)
	{
		for (int i=0; i<allLevels.length; i++) {
			String useUri = (useLoa)? allLevels[i].sleLoaUri: allLevels[i].sleSamlUri;
			if (useUri != null && useUri.equals(sCurrentAuthnContextClassRef))
				return allLevels[i].sleLevel;
		}
		/*
		if (sCurrentAuthnContextClassRef.equals(PREVIOUSSESSION_URI))					// RH, 20141113, sn
			return LEVEL_PREVIOUS;					// RH, 20141113, en
//		if (sCurrentAuthnContextClassRef.equals(UNSPECIFIED_URI))					// RH, 20141113, o
		else if (sCurrentAuthnContextClassRef.equals(UNSPECIFIED_URI))					// RH, 20141113, n
			return LEVEL_NULL;
		else if (sCurrentAuthnContextClassRef.equals(PASSWORD_URI))						// RH, 20120124, sn
			return LEVEL_POOR;									// RH, 20120124, en
		else if (sCurrentAuthnContextClassRef.equals(PASSWORDPROTECTEDTRANSPORT_URI))
			return LEVEL_LOW;
		else if (sCurrentAuthnContextClassRef.equals(MOBILETWOFACTORUNREGISTERED_URI))
			return LEVEL_BETTER;
		else if (sCurrentAuthnContextClassRef.equals(MOBILETWOFACTORCONTRACT_URI))
			return LEVEL_MEDIUM;
		else if (sCurrentAuthnContextClassRef.equals(SMARTCARDPKI_URI))
			return LEVEL_HIGH;
		*/
		return LEVEL_NOT_FOUND;
	}

	/**
	 * Convert AuthnContextClassRef to integer Level from supplied HashMap with key=level, value=ContextRef
	 * 
	 * @param sCurrentAuthnContextClassRef
	 *            AuthnContext class ref
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 * @return the integer Security Level
	 */
	private static int getIntSecurityLevelUsingExternal(String sCurrentAuthnContextClassRef, HashMap<String, String> secLevels, boolean useLoa)
	{
		if (secLevels == null) {	// backward compatibility
			return getIntSecurityLevel(sCurrentAuthnContextClassRef, useLoa);
		}
		
		// levels given as argument
		String sLevel = getSecurityLevelFromContextUsingExternal(sCurrentAuthnContextClassRef, secLevels, useLoa);
		if (sLevel == null) {
			return LEVEL_NOT_FOUND;
		}
		else {
			return Integer.parseInt(sLevel);	// levels (=keys) from secLevels should be checked for integer at startup
		}
	}
	
	/**
	 * Gets the Security Level, use AuthnContext to make comparisons.
	 * Use supplied HashMap with key=level, value=ContextRef if set
	 * 
	 * @param requestedAuthnContext
	 *            the requested authn context
	 * @param secLevels
	 *            HashMap with mapping from key=level to value=AuthnContextClassRef
	 *            Example entry: "10" -> "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	 * @param useLoa
	 *            use Level of Assurance
	 * @param systemLogger
	 *            the systemlogger
	 * @return the Security Level
	 */
	public static String getComparedSecurityLevelUsingExternal(RequestedAuthnContext requestedAuthnContext,
					HashMap<String, String> secLevels, boolean useLoa, ASelectSystemLogger systemLogger)
	{
		String sMethod = "getSecurityLevel";
		final int EXACT = 0;
		final int MINIMUM = 1;
		final int MAXIMUM = 2;
		final int BETTER = 3;

		if (requestedAuthnContext != null) {
			int iComparison = EXACT;
			AuthnContextComparisonTypeEnumeration authnContextComparisonTypeEnumeration = requestedAuthnContext.getComparison();
			if (authnContextComparisonTypeEnumeration != null) {
				if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.MINIMUM)) {
					iComparison = MINIMUM;
				}
				else if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.MAXIMUM)) {
					iComparison = MAXIMUM;
				}
				else if (authnContextComparisonTypeEnumeration.equals(AuthnContextComparisonTypeEnumeration.BETTER)) {
					iComparison = BETTER;
				}
			}

			List<AuthnContextClassRef> authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();
			ListIterator<AuthnContextClassRef> itr = authnContextClassRefs.listIterator();

			String sCurrentAuthnContextClassRef = null;
			String sMatchedBetrouwheidsNiveau = null;
			int iCurrentBetrouwheidsNiveau = LEVEL_NOT_FOUND;

			switch (iComparison) {
			case EXACT:
				while (itr.hasNext() && sMatchedBetrouwheidsNiveau == null) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					sMatchedBetrouwheidsNiveau = getSecurityLevelFromContextUsingExternal(sCurrentAuthnContextClassRef, secLevels, useLoa);
				}
				break;

			case MINIMUM:
				int iCurrentMinBetrouwheidsNiveau = LEVEL_MAX;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntSecurityLevelUsingExternal(sCurrentAuthnContextClassRef, secLevels, useLoa);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau < iCurrentMinBetrouwheidsNiveau)
						iCurrentMinBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = convertSecurityLevelToString(iCurrentMinBetrouwheidsNiveau);
				break;

			case BETTER:
				int iCurrentBestBetrouwheidsNiveau = LEVEL_MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntSecurityLevelUsingExternal(sCurrentAuthnContextClassRef, secLevels, useLoa);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentBestBetrouwheidsNiveau)
						iCurrentBestBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				// we now have the highest level mentioned in the AuthnContextClassRef that is also known by us

				// now return one level higher than that, if we are already at the highest level return LEVEL_MAX
				int idxFoundLevel = -1;
				int iBetterLevel = LEVEL_MIN;
				for (int i=0; i<allLevels.length; i++) {
					String useUri = (useLoa)? allLevels[i].sleLoaUri: allLevels[i].sleSamlUri;
					if (useUri != null && idxFoundLevel < 0 && allLevels[i].sleLevel == iCurrentBestBetrouwheidsNiveau) {
						idxFoundLevel = i;  // found the entry corresponding to iCurrentBestBetrouwheidsNiveau
						continue;  // we want an entry following this one
					}
					if (useUri != null && idxFoundLevel >= 0) {  // a better one has been found
						iBetterLevel = i;
						break;
					}
				}
				if (iBetterLevel == LEVEL_MIN)  // nothing found
					iBetterLevel = LEVEL_MAX;

				/*if (iCurrentBestBetrouwheidsNiveau == LEVEL_NULL)
					iCurrentBestBetrouwheidsNiveau = LEVEL_LOW;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_PREVIOUS)			// RH, 2014113, sn
					iCurrentBestBetrouwheidsNiveau = LEVEL_LOW;			// RH, 2014113, en
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_POOR)			// RH, 20120124, sn
					iCurrentBestBetrouwheidsNiveau = LEVEL_LOW;			// RH, 20120124, en
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_LOW)
					iCurrentBestBetrouwheidsNiveau = LEVEL_BETTER;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_BETTER)
					iCurrentBestBetrouwheidsNiveau = LEVEL_MEDIUM;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_MEDIUM)
					iCurrentBestBetrouwheidsNiveau = LEVEL_HIGH;
				else if (iCurrentBestBetrouwheidsNiveau == LEVEL_HIGH)
					iCurrentBestBetrouwheidsNiveau = LEVEL_MAX;*/

				sMatchedBetrouwheidsNiveau = convertSecurityLevelToString(iBetterLevel);
				break;

			case MAXIMUM:
				int iCurrentMaxBetrouwheidsNiveau = LEVEL_MIN;
				while (itr.hasNext()) {
					sCurrentAuthnContextClassRef = itr.next().getAuthnContextClassRef();
					iCurrentBetrouwheidsNiveau = getIntSecurityLevelUsingExternal(sCurrentAuthnContextClassRef, secLevels, useLoa);
					if (iCurrentBetrouwheidsNiveau != LEVEL_NOT_FOUND
							&& iCurrentBetrouwheidsNiveau > iCurrentMaxBetrouwheidsNiveau)
						iCurrentMaxBetrouwheidsNiveau = iCurrentBetrouwheidsNiveau;
				}
				sMatchedBetrouwheidsNiveau = convertSecurityLevelToString(iCurrentMaxBetrouwheidsNiveau);
			}
			
			systemLogger.log(Level.INFO, MODULE, sMethod, "Level=" + sMatchedBetrouwheidsNiveau);
			return sMatchedBetrouwheidsNiveau;  // can still be null

		}
		// 20090501, Bauke: Since the <RequestedAuthnContext> element is optional,
		// we return the lowest known level here. (no restriction on the level is required)
		return LEVEL_LOWEST_SERIOUS; // BN_EMPTY;
	}
	
	static public Integer loa2stork(String loaLevel) {
		Integer storkLevel = null;
		String[] levels = { LOA1, LOA2, LOA3, LOA4 };	// no stork mapping for loa2plus
		for (int  i=0; i < levels.length; i++) {
			if ( levels[i].equalsIgnoreCase(loaLevel)) return i+1;
		}
		return storkLevel;
	}

	static public String stork2loa(Integer storkLevel) {
		String loaLevel = null;
		String[] levels = { LOA1, LOA2, LOA3, LOA4 };	// no stork mapping for loa2plus
		if ( storkLevel > 0 && storkLevel <= levels.length ) {
			return levels[storkLevel - 1];
		}
		return loaLevel;
	}

}
