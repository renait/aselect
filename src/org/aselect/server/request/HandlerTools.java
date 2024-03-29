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
package org.aselect.server.request;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aselect.server.application.ApplicationManager;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/*
 * Generic Tools for all Handler routines
 * 
 * 20100228, Bauke: moved all copies of (de)serializeAttributes to HandlerTools
 */
public class HandlerTools
{
	final static String MODULE = "HandlerTools";

	// This code can be used to set HttpOnly (not supported by Java Cookies)
	/**
	 * Put cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the cookie name
	 * @param sCookieValue
	 *            the cookie value
	 * @param sCookieDomain
	 *            the cookie domain
	 * @param sCookiePath
	 *            the cookie path
	 * @param iAge
	 *            the age
	 * @param httpOnly
	 *            the http only flag
	 * @param logger
	 *            the logger
	 */
	public static void putCookieValue(HttpServletResponse response, String sCookieName, String sCookieValue,
			String sCookieDomain, String sCookiePath, int iAge, int httpOnly, ASelectSystemLogger logger)
	{
		String sMethod = "putCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		if (response == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie "+sCookieName);
			return;
		}

		String addedSecurity = _configManager.getAddedSecurity();
		if (sCookiePath == null)
			sCookiePath = _configManager.getCookiePath();

		String sValue = sCookieName + "=" + sCookieValue;
		if (sCookieDomain != null)
			sValue += "; Domain=" + sCookieDomain;
		// RH, 20200203, sn
		if (addedSecurity != null && addedSecurity.contains("cookie_versionobsolete")) {
			sValue += "; Path=" + sCookiePath; // was: "/aselectserver/server";
		} else {
		// RH, 20200203, en
			sValue += "; Version=1; Path=" + sCookiePath; // was: "/aselectserver/server";
		}	// RH, 20200203, n
		// if (iAge != -1) sValue += "; expires=<date>"
		// format: Wdy, DD-Mon-YYYY HH:MM:SS GMT, e.g.: Fri, 31-Dec-2010, 23:59:59 GMT

		if (iAge >= 0)
			sValue += "; Max-Age=" + iAge;

		// RH, 20200203, sn
		if (addedSecurity != null && addedSecurity.contains("cookie_samesitestrict")) {
			sValue += "; SameSite=Strict";
		} else if (addedSecurity != null && addedSecurity.contains("cookie_samesitelax")) {
			sValue += "; SameSite=Lax";
		} else {	// will be the new default
			sValue += "; SameSite=None";
		}
		// RH, 20200203, en
		

		if (addedSecurity != null && addedSecurity.contains("cookies") && httpOnly == 1) {
				sValue += "; Secure; HttpOnly";
		}
		logger.log(Level.FINER, MODULE, sMethod, "Add Cookie, Header: " + sValue);
		
		//response.setHeader("Set-Cookie", sValue);
		// 20121029, Bauke: It must be possible to have multiple "Set-Cookie" headers! Therefore use addHeader().
		response.addHeader("Set-Cookie", sValue);
	}

	/**
	 * Del cookie value.
	 * 
	 * @param response
	 *            the response
	 * @param sCookieName
	 *            the s cookie name
	 * @param sCookieDomain
	 *            the s cookie domain
	 * @param logger
	 *            the logger
	 */
	public static void delCookieValue(HttpServletResponse response, String sCookieName,
				String sCookieDomain, String sCookiePath, ASelectSystemLogger logger)
	{
		String sMethod = "delCookieValue";
		ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
		if (response == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie "+sCookieName);
			return;
		}

		Cookie cookie = new Cookie(sCookieName, "_deleted_");
		if (sCookieDomain != null)
			cookie.setDomain(sCookieDomain);
		if (!Utils.hasValue(sCookiePath))
			sCookiePath = _configManager.getCookiePath();
		cookie.setPath(sCookiePath); // was: "/aselectserver/server");
		cookie.setMaxAge(0);
		logger.log(Level.FINE, MODULE, sMethod, "Delete Cookie="+sCookieName+" Domain="+sCookieDomain+" Path="+sCookiePath);
		response.addCookie(cookie);
	}

	// Bauke: added
	/**
	 * Gets the cookie value.
	 * 
	 * @param request
	 *            the request
	 * @param sName
	 *            the s name
	 * @param logger
	 *            the logger
	 * @return the cookie value
	 */
	public static String getCookieValue(HttpServletRequest request, String sName, ASelectSystemLogger logger)
	{
		String sMethod = "getCookieValue";
		String sReturnValue = null;
		
		if (request == null) {
			logger.log(Level.WARNING, MODULE, sMethod, "No servletRequest to retrieve cookie "+sName);
			return null;
		}
		Cookie oCookie[] = request.getCookies();
		if (oCookie == null)
			return null;
		for (int i = 0; i < oCookie.length; i++) {
			String sCookieName = oCookie[i].getName();
			if (logger != null) { // allow for null logger
				logger.log(Level.FINEST, MODULE, sMethod, "Get "+sName+" try="+sCookieName);
			}
			if (sCookieName.equals(sName)) {
				String sCookieValue = oCookie[i].getValue();
				// remove '"' surrounding the cookie if applicable
				int iLength = sCookieName.length();
				if (sCookieName.charAt(0) == '"' && sCookieName.charAt(iLength - 1) == '"') {
					sCookieName = sCookieName.substring(1, iLength - 1);
				}
				if (logger != null) {// allow for null logger
					logger.log(Level.FINE, MODULE, sMethod, sCookieName + "=" + sCookieValue);
				}
				sReturnValue = sCookieValue;
				break;
			}
		}
		return sReturnValue;
	}

	/**
	 * @throws ASelectException
	 */
	public static void setRequestorFriendlyCookie(HttpServletResponse servletResponse, HashMap sessionContext, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		ASelectConfigManager configManager = ASelectConfigManager.getHandle();
		if (sessionContext == null)
			return;
	
		String sStatus = (String)sessionContext.get("status");
		String sAppId = (String)sessionContext.get("app_id");
		if (/*"del".equals(sStatus) &&*/ Utils.hasValue(sAppId)) {
			String sUF = ApplicationManager.getHandle().getFriendlyName(sAppId);
			HandlerTools.setEncryptedCookie(servletResponse, "requestor_friendly_name", sUF, configManager.getCookieDomain(), -1/*age*/, systemLogger);
		}
	}
	
	/**
	 * Sets an encrypted cookie.
	 * 
	 * @param servletResponse
	 *            the servlet response
	 * @param sCookieName
	 *            the cookie name
	 * @param sCookieValue
	 *            the cookie value
	 * @param sCookieDomain
	 *            the cookie domain
	 * @param systemLogger
	 *            the systemlogger
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static void setEncryptedCookie(HttpServletResponse servletResponse,
			String sCookieName, String sCookieValue, String sCookieDomain, int iAge, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "setEncryptedCookie";
		CryptoEngine _cryptoEngine = CryptoEngine.getHandle();

		systemLogger.log(Level.FINER, MODULE, sMethod, "Encrypt cookie="+sCookieName+", value="+sCookieValue);
		if (servletResponse == null) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No servletResponse to set cookie");
			return;
		}
		if (!Utils.hasValue(sCookieValue)) {
			systemLogger.log(Level.FINER, MODULE, sMethod, "No cookie value given for "+sCookieName);
			return;
		}
		sCookieValue = _cryptoEngine.encryptData(sCookieValue.getBytes());

		HandlerTools.putCookieValue(servletResponse, sCookieName, sCookieValue,
				sCookieDomain, null/*default path*/, iAge/*5 years*/, 1/*httpOnly*/, systemLogger);
	}

	/**
	 * Gets the encrypted cookie.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param sCookieName
	 *            the cookie name
	 * @param systemLogger
	 *            the system logger
	 * @return the string
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static String getEncryptedCookie(HttpServletRequest servletRequest, String sCookieName, ASelectSystemLogger systemLogger)
	throws ASelectException
	{
		String sMethod = "getEncryptedCookie";
		if (servletRequest == null) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "No servletRequest to retrieve cookie");
			return null;
		}
		CryptoEngine _cryptoEngine = CryptoEngine.getHandle();
		String sCookieValue = HandlerTools.getCookieValue(servletRequest, sCookieName, systemLogger);
		if (!Utils.hasValue(sCookieValue))
			return null;
		
		byte[] baBytes = _cryptoEngine.decryptData(sCookieValue);
		sCookieValue = new String(baBytes);
		systemLogger.log(Level.FINER, MODULE, sMethod, "Decrypt="+sCookieValue);
		return sCookieValue;
	}

	/**
	 * Log cookies.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param logger
	 *            the logger
	 */
	public static void logCookies(HttpServletRequest servletRequest, ASelectSystemLogger logger)
	{
		String sMethod = "logCookies";
		Cookie[] aCookies = servletRequest.getCookies();
		if (aCookies == null) {
			logger.log(Level.FINER, MODULE, sMethod, "No Cookies");
			return;
		}

		for (int i = 0; i < aCookies.length; i++) {
			logger.log(Level.FINER, MODULE, sMethod, "Cookie " + aCookies[i].getName() + "=" + aCookies[i].getValue()
					+ ", Path=" + aCookies[i].getPath() + ", Domain=" + aCookies[i].getDomain() + ", Age="
					+ aCookies[i].getMaxAge());
		}
	}

	
	
	/**
	 * Creates the attribute statement assertion.
	 * 
	 * @param parms
	 *            the parms
	 * @param sIssuer
	 *            the issuer
	 * @param sSubject
	 *            the subject
	 * @param sign
	 *            sign the assertion?
	 * @return the assertion
	 * @throws ASelectException
	 */
	public static Assertion createAttributeStatementAssertion(Map parms, String sIssuer, String sSubject, boolean sign )
	throws ASelectException
	{
		return createAttributeStatementAssertion(parms, sIssuer, sSubject, sign , true ); 	// defaults to using saml attribute type declarations
	}	

	
	/**
	 * Creates the attribute statement assertion.
	 * 
	 * @param parms
	 *            the parms
	 * @param sIssuer
	 *            the issuer
	 * @param sSubject
	 *            the subject
	 * @param sign
	 *            sign the assertion?
	 * @return the assertion
	 * @throws ASelectException
	 */
	@SuppressWarnings( {
		"unchecked"
	})
	public static Assertion createAttributeStatementAssertion(Map parms, String sIssuer, String sSubject, boolean sign ,boolean useSamlAttrTypeDecl )
	throws ASelectException
	{
		String sMethod = "createAttributeStatementAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		XMLObjectBuilderFactory _oBuilderFactory;
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

		systemLogger.log(Level.FINEST, MODULE, sMethod, "Issuer="+sIssuer+" Subject="+sSubject);


		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) _oBuilderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		Assertion assertion = assertionBuilder.buildObject();
		assertion.setVersion(SAMLVersion.VERSION_20);

		SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) _oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = nameIDBuilder.buildObject();
		nameID.setFormat(NameIDType.TRANSIENT); // was PERSISTENT
		nameID.setNameQualifier(sIssuer);
		nameID.setValue(sSubject);
		
		systemLogger.log(Level.FINEST, MODULE, sMethod, nameID.getValue());
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) _oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameID);

		SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
		assertionIssuer.setFormat(NameIDType.ENTITY);
		assertionIssuer.setValue(sIssuer);

		assertion.setIssuer(assertionIssuer);
		assertion.setSubject(subject);
		DateTime tStamp = new DateTime();
		assertion.setIssueInstant(tStamp);
		try {
			assertion.setID(SamlTools.generateIdentifier(systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to generate Identifier for the Assertion", ase);
		}

		
		if ( parms != null ) {

			// RH, 20151006, sn
			AttributeStatement attributeStatement = null;
			if (!useSamlAttrTypeDecl) {	// workaround option
				 attributeStatement = createAttributeStatementWithoutDataType(parms, systemLogger, _oBuilderFactory);
			} else {	// default way
				 attributeStatement = createAttributeStatement(parms, systemLogger, _oBuilderFactory);
			}
			
//			AttributeStatement attributeStatement = createAttributeStatement(parms, systemLogger, _oBuilderFactory); // RH, 20151006, o
			if (attributeStatement != null)
				assertion.getAttributeStatements().add(attributeStatement);

		}
		
		systemLogger.log(Level.FINER, MODULE, sMethod, "Finalizing the assertion building, sign="+sign);
		assertion = marshallAssertion(assertion, false);
		if (sign) {
			systemLogger.log(Level.FINER, MODULE, sMethod, "Sign the final Assertion >======");
//			assertion = (Assertion)SamlTools.signSamlObject(assertion);	// RH, 20180918, o
			assertion = (Assertion)SamlTools.signSamlObject(assertion, null);	// RH, 20180918, n
			systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the Assertion ======<");
		}

		// // Only for testing
		// if (!SamlTools.checkSignature(assertion, _configManager.getDefaultCertificate().getPublicKey()) ) {
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "Signing verification says signature NOT valid ?!?" );
		// } else {
		// _systemLogger.log(Level.INFO, MODULE, sMethod, "Signing verification says signature is valid!" );
		// }
		return assertion;
	}

	
	
	
	/**
	 * Creates the authn + attribute statement assertion.
	 * 
	 * @param parms
	 *            the (optional) attribute name/value pairs
	 * @param sIssuer
	 *            the issuer
	 * @param sSubject
	 *            the subject
	 * @param sign
	 *            sign the assertion?
	 * @return the assertion
	 * @throws ASelectException
	 */
	@SuppressWarnings( {
		"unchecked"
	})
	public static Assertion createAuthnStatementAttributeStatementAssertion(Map parms, String sIssuer, String sSubject, boolean sign)
	throws ASelectException
	{
		String sMethod = "createAuthnStatmeentAttributeStatementAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		XMLObjectBuilderFactory _oBuilderFactory;
		_oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

		systemLogger.log(Level.FINEST, MODULE, sMethod, "Issuer="+sIssuer+" Subject="+sSubject);
		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) _oBuilderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);

		SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) _oBuilderFactory
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		Assertion assertion = assertionBuilder.buildObject();
		assertion.setVersion(SAMLVersion.VERSION_20);

		SAMLObjectBuilder<NameID> nameIDBuilder = (SAMLObjectBuilder<NameID>) _oBuilderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameID = nameIDBuilder.buildObject();
//		nameID.setFormat(NameIDType.TRANSIENT);
//		nameID.setNameQualifier(sIssuer);
		nameID.setValue(sSubject);
		
		SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) _oBuilderFactory
		.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_SENDER_VOUCHES);

		
		
		systemLogger.log(Level.FINEST, MODULE, sMethod, nameID.getValue());
		SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) _oBuilderFactory
				.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(subjectConfirmation);


		SAMLObjectBuilder<Issuer> assertionIssuerBuilder = (SAMLObjectBuilder<Issuer>) _oBuilderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer assertionIssuer = assertionIssuerBuilder.buildObject();
		assertionIssuer.setFormat(NameIDType.ENTITY);
		assertionIssuer.setValue(sIssuer);

		assertion.setIssuer(assertionIssuer);
		assertion.setSubject(subject);
		DateTime tStamp = new DateTime();
		assertion.setIssueInstant(tStamp);
		try {
			assertion.setID(SamlTools.generateIdentifier(systemLogger, MODULE));
		}
		catch (ASelectException ase) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to generate Identifier for the Assertion", ase);
		}

		// ---- AuthenticationContext
		SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) _oBuilderFactory
				.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
		
		// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
		String sAutnContextClassRefURI = "PasswordProtectedTransport";// Make this a parameter
		authnContextClassRef.setAuthnContextClassRef(sAutnContextClassRefURI);

		SAMLObjectBuilder<AuthenticatingAuthority> authenticatingAuthorityBuilder = (SAMLObjectBuilder<AuthenticatingAuthority>) _oBuilderFactory
				.getBuilder(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
		AuthenticatingAuthority authenticatingAuthority = authenticatingAuthorityBuilder.buildObject();
		String  sAuthenticatingAuthority = "DIGID-BURGER";// Make this a parameter
		authenticatingAuthority.setURI(sAuthenticatingAuthority);
		
		
		SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) _oBuilderFactory
				.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContext authnContext = authnContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);

		SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) _oBuilderFactory
				.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnStatement authnStatement = authnStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(tStamp);

		authnStatement.setAuthnContext(authnContext);

		
		assertion.getAuthnStatements().add(authnStatement);

		
		if ( parms != null && !parms.isEmpty() ) {	// only add attributeStatement if there are any attributes
			

			AttributeStatement attributeStatement = createAttributeStatement(parms, systemLogger, _oBuilderFactory);

			if (attributeStatement != null)
				assertion.getAttributeStatements().add(attributeStatement);
		}

		systemLogger.log(Level.FINER, MODULE, sMethod, "Finalizing the assertion building, sign="+sign);
		assertion = marshallAssertion(assertion, false);
		if (sign) {
			systemLogger.log(Level.FINER, MODULE, sMethod, "Sign the final Assertion >======");
//			assertion = (Assertion)SamlTools.signSamlObject(assertion);
//			assertion = (Assertion)SamlTools.signSamlObject(assertion, null, true, true); // sha1 default algorithm	// RH, 20180918, o
			assertion = (Assertion)SamlTools.signSamlObject(assertion, null, true, true, null); // sha1 default algorithm	// RH, 20180918, n
			

			systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the Assertion ======<");
		}

		return assertion;
	}


	/**
	 * @param parms
	 * @param systemLogger
	 * @param _oBuilderFactory
	 * @return
	 * 
	 * all parameters MUST not be null
	 * parameter parms MAY be empty, if if multivalued values are used the MUST contain object elements not simple types
	 */
	public static AttributeStatement createAttributeStatement(Map parms, ASelectSystemLogger systemLogger, 
			XMLObjectBuilderFactory _oBuilderFactory)
	{
		String sMethod = "createAttributeStatement";

		systemLogger.log(Level.FINEST, MODULE, sMethod, "Building statement with parmameters:" + parms);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) _oBuilderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);


		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) _oBuilderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);

		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

		
		Iterator itr = parms.keySet().iterator();
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Starting iterating through parameters with keys: " + parms.keySet());
		while (itr.hasNext()) {
			String parmName = (String) itr.next();

			Object oValue = parms.get(parmName);
			systemLogger.log(Level.FINEST, MODULE, sMethod, "Found value: " + oValue);
			Attribute attribute = attributeBuilder.buildObject();
			attribute.setName(parmName);

			XSString attributeValue = null;

			if ( oValue != null && oValue instanceof Iterable) {
				Iterator enumValues = ((Iterable) oValue).iterator();
				while (enumValues.hasNext()) {
					attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
							XSString.TYPE_NAME);
					attributeValue.setValue("" + enumValues.next());	// cast to String
					attribute.getAttributeValues().add(attributeValue);
				}
			}
			else {
				attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
						XSString.TYPE_NAME);
				attributeValue.setValue("" + oValue);	// cast to String
				attribute.getAttributeValues().add(attributeValue);
			}

			attributeStatement.getAttributes().add(attribute);
		}
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Finished iterating through parameters");
		return attributeStatement;
	}


	
	/**
	 * @param parms
	 * @param systemLogger
	 * @param _oBuilderFactory
	 * @return
	 * 
	 * all parameters MUST not be null
	 * parameter parms MAY be empty, if if multivalued values are used the MUST contain object elements not simple types
	 * (Workaround) solution for clients that cannot handle Attribute DataType declarations
	 */
	public static AttributeStatement createAttributeStatementWithoutDataType(Map parms, ASelectSystemLogger systemLogger, 
			XMLObjectBuilderFactory _oBuilderFactory)
	{
		String sMethod = "createAttributeStatementWithoutDataType";

		systemLogger.log(Level.FINEST, MODULE, sMethod, "Building statement with parmameters:" + parms);

		SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) _oBuilderFactory
				.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);


		SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) _oBuilderFactory
				.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

//		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSString.TYPE_NAME);
//		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(AttributeValue.DEFAULT_ELEMENT_NAME);
		XMLObjectBuilder stringBuilder = _oBuilderFactory.getBuilder(XSAny.TYPE_NAME);

		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

		
		Iterator itr = parms.keySet().iterator();
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Starting iterating through parameters with keys: " + parms.keySet());
		while (itr.hasNext()) {
			String parmName = (String) itr.next();

			Object oValue = parms.get(parmName);
			systemLogger.log(Level.FINEST, MODULE, sMethod, "Found value: " + oValue);
			Attribute attribute = attributeBuilder.buildObject();
			attribute.setName(parmName);

//			XSString attributeValue = null;
			XSAny attributeValue = null;


			if ( oValue != null && oValue instanceof Iterable) {
				Iterator enumValues = ((Iterable) oValue).iterator();
				while (enumValues.hasNext()) {
//					attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
//							XSString.TYPE_NAME);
					attributeValue = (XSAny) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
							null);
//					attributeValue.setValue("" + enumValues.next());	// cast to String
					attributeValue.setTextContent("" + enumValues.next());

					attribute.getAttributeValues().add(attributeValue);
				}
			}
			else {
//				attributeValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
//						XSString.TYPE_NAME);
				attributeValue = (XSAny) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
						null);
//				attributeValue.setValue("" + oValue);	// cast to String
				attributeValue.setTextContent("" + oValue);

				attribute.getAttributeValues().add(attributeValue);
			}

			attributeStatement.getAttributes().add(attribute);
		}
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Finished iterating through parameters");
		return attributeStatement;
	}

	
/**
 * @param ass
 *             the assertion
 * @return the updated assertion
 * @throws ASelectException
 */
	public static Assertion updateAssertionIssueInstant(Assertion ass, DateTime refInstant, Long maxNotBefore, Long maxNotOnOrAfter)
	throws ASelectException
	{
		String sMethod = "updateAssertionIssueInstant";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "Refreshing assertion");
		Assertion refreshedAss = null;
		
		String alg = null;
		boolean adkeyname = false;
		boolean addcert = false;
		boolean sign = false;
		Signature sig = ass.getSignature();
		if (sig != null) { // (re)sign the assertion
			systemLogger.log(Level.FINER, MODULE, sMethod, "Assertion was signed");
			sign = true;
			alg = sig.getSignatureAlgorithm();
			systemLogger.log(Level.FINER, MODULE, sMethod, "Found signature algortithm: "+alg);
			if ( sig.getKeyInfo() != null) {
				adkeyname = true;
				List <X509Data> x509data = sig.getKeyInfo().getX509Datas();
				// We might safely assume this is a certificate
				if (x509data != null) {
					for (X509Data data : x509data) {
						String localPart = data.getElementQName().getLocalPart();
						systemLogger.log(Level.FINER, MODULE, sMethod, "Found local part: "+ localPart);
						addcert = true;
						if (localPart.equals("")) {	// maybe verify localpart
							
						}
					}
				}
				List<KeyName> keynames = sig.getKeyInfo().getKeyNames();
				if (keynames != null) {
					for (KeyName k : keynames) {
						systemLogger.log(Level.FINER, MODULE, sMethod, "Found keyname: "+alg);
					}
					
				}
			} else {
				systemLogger.log(Level.FINER, MODULE, sMethod, "No KeyInfo found, skipping");
			}
			systemLogger.log(Level.FINER, MODULE, sMethod, "Removing old signature");
			List<XMLObject> childList = ass.getOrderedChildren();
			for (XMLObject child : childList) { // we assume there are children
				if (child instanceof Signature) {
					ass.getDOM().removeChild(child.getDOM());
				}
			}
		} else {
			systemLogger.log(Level.FINER, MODULE, sMethod, "Assertion was not signed");
		}
		refreshedAss = (Assertion) rebuildAssertion(ass);
//		refreshedAss.setIssueInstant(new DateTime());	// RH, 20160310, o
		if (refInstant == null) refInstant = new DateTime();	// RH, 20160310, sn
		refreshedAss.setIssueInstant(refInstant);
		refreshedAss = (Assertion)SamlTools.setValidityInterval(refreshedAss, refInstant, maxNotBefore, maxNotOnOrAfter);	// RH, 20160310, en

		refreshedAss = (Assertion) rebuildAssertion(refreshedAss);
		if (sign) {
			systemLogger.log(Level.FINER, MODULE, sMethod, "ReSigning the Assertion");
//			Assertion signedAss = (Assertion)SamlTools.signSamlObject(refreshedAss, alg.endsWith("sha256") ? "sha256" : null, adkeyname, addcert); // sha1 default algorithm	// RH, 20180918, o
			Assertion signedAss = (Assertion)SamlTools.signSamlObject(refreshedAss, alg.endsWith("sha256") ? "sha256" : null, adkeyname, addcert, null); // sha1 default algorithm	// RH, 20180918, n
			return signedAss;
		}
		return refreshedAss;
	}

	
	
	/**
	 * Marshall assertion.
	 *
	 * Attention, the returned Assertion is not actually marshalled, only logs the marshalled assertion if doLog is true
	 * For actual Marshalling use {@link SamlTools}
	 * @param assertion
	 *            the assertion
	 * @return the original assertion
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static Assertion marshallAssertion(Assertion assertion, boolean doLog)
	throws ASelectException
	{
		String sMethod = "marshallAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(assertion);
		try {
			Node node = marshaller.marshall(assertion);
			if (doLog) {
				String msg = XMLHelper.prettyPrintXML(node);
				systemLogger.log(Level.FINEST, MODULE, sMethod, Auxiliary.obfuscate(msg, Auxiliary.REGEX_PATTERNS));
			}
		}
		catch (MarshallingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return assertion;
	}

	
	/**
	 * Rebuild assertion.
	 *
	 * 
	 * @param assertion
	 *            the assertion
	 * @return the rebuilded assertion
	 * @throws ASelectException
	 *             the a select exception
	 */
//	public static Assertion rebuildAssertion(Assertion assertion)
	public static XMLObject rebuildAssertion(XMLObject assertion)
	throws ASelectException
	{
		String sMethod = "rebuildAssertion";
//		Assertion rebuildedAssertion = null;
		XMLObject rebuildedAssertion = null;
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		
			Element e;
			try {
				e = SamlTools.marshallMessage(assertion);
//				rebuildedAssertion = (Assertion) SamlTools.unmarshallElement(e);
				rebuildedAssertion = SamlTools.unmarshallElement(e);
			}
			catch (MessageEncodingException e1) {
				systemLogger.log(Level.WARNING, MODULE, sMethod, e1.getMessage(), e1);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
			}
			
		return rebuildedAssertion;
	}


	/**
	 * Create a signed and base64 encoded Saml Token
	 * containing the attributes present in htAttributes.
	 * 
	 * @param sIssuer
	 *            the issuer
	 * @param sTgt
	 *            the tgt
	 * @param htAttributes
	 *            the attributes
	 * @return the attribute token
	 * @throws ASelectException
	 */
	public static String createAttributeToken(String sIssuer, String sTgt, HashMap htAttributes)
	throws ASelectException
	{
		return createAttributeToken(sIssuer, sTgt, htAttributes, true); // defualts to using datatype decalrations in saml attributes
	}

	/**
	 * Create a signed and base64 encoded Saml Token
	 * containing the attributes present in htAttributes.
	 * 
	 * @param sIssuer
	 *            the issuer
	 * @param sTgt
	 *            the tgt
	 * @param htAttributes
	 *            the attributes
	 * @return the attribute token
	 * @throws ASelectException
	 */
	public static String createAttributeToken(String sIssuer, String sTgt, HashMap htAttributes, boolean useSamlAttrTypeDecl )
	throws ASelectException
	{
		String sMethod = "createAttributeToken";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		systemLogger.log(Level.FINER, MODULE, sMethod, "Creating AttributeToken");

		Assertion samlAssert = HandlerTools.createAttributeStatementAssertion(htAttributes, sIssuer/* Issuer */,
				sTgt/* Subject */, true/* sign */, useSamlAttrTypeDecl );
		String sSamlAssert = base64EncodeAssertion(samlAssert);
		return sSamlAssert;
	}

	/**
	 * @param sMethod
	 * @param samlAssert
	 * @return
	 * @throws ASelectException
	 */
//	public static String base64EncodeAssertion(Assertion samlAssert)
	public static String base64EncodeAssertion(XMLObject samlAssert)
		throws ASelectException
	{
		String sMethod = "base64EncodeAssertion";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		String sAssertion = XMLHelper.nodeToString(samlAssert.getDOM());
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Assertion=" + Auxiliary.obfuscate(sAssertion, Auxiliary.REGEX_PATTERNS));

		try {
			byte[] bBase64Assertion = sAssertion.getBytes("UTF-8");
			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(bBase64Assertion);
		}
		catch (UnsupportedEncodingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage(), e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
	
	
	/**
	 * @param sMethod
	 * @param sSamlAssert
	 * @return
	 * @throws ASelectException
	 */
//	public static Assertion base64DecodeAssertion(String sSamlAssert)
	public static XMLObject base64DecodeAssertion(String sSamlAssert)
		throws ASelectException
	{
		String sMethod = "base64DecodeAssertion";
		XMLObject xmlObject = null;
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.FINEST, MODULE, sMethod, "base64Decoding: " + Auxiliary.obfuscate(sSamlAssert, Auxiliary.REGEX_PATTERNS));
		BASE64Decoder b64dec = new BASE64Decoder();
		byte[] tokenArray = b64dec.decodeBuffer(sSamlAssert);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			baos.write(tokenArray);
			String token = baos.toString("UTF-8"); // We should have gotten UTF-8 formatted strings
	
//			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilderFactory dbFactory = Utils.createDocumentBuilderFactory(systemLogger);
			dbFactory.setNamespaceAware(true);
			// dbFactory.setExpandEntityReferences(false);
			// dbFactory.setIgnoringComments(true);
			dbFactory.setIgnoringComments(true);	// By default the value of this is set to false

			StringReader stringReader = new StringReader(token);
			InputSource inputSource = new InputSource(stringReader);
	
			DocumentBuilder builder = null;
			Document samlResponse = null;
			Element dom = null;
			builder = dbFactory.newDocumentBuilder();
			samlResponse = builder.parse(inputSource);
			dom = samlResponse.getDocumentElement();
			xmlObject = SamlTools.unmarshallElement(dom);
		}
		catch (MessageEncodingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while marshalling message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_PARSE_ERROR, e);
		}
		catch (IOException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while marshalling message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_IO, e);
		}
		catch (ParserConfigurationException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while getting parser");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_PARSE_ERROR, e);
		}
		catch (SAXException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while parsing message", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_PARSE_ERROR, e);
		}
		return  xmlObject;
	}
	
	
	
	/*
	 * 
	 */
		/**
		 * @param keyfile	full path to keyfile that contains client certificate
		 * @param keyfilePw	password for the keystore
		 * @return	sslsocketfactory or null if creation failed 
		 * @throws GeneralSecurityException
		 * @throws IOException
		 * 
		 * Override this method if you need a non-default sslsocketfactory
		 * or set  the security property "ssl.SocketFactory.provider"
		 */
		public static SSLSocketFactory createSSLSocketFactory(String keyfile, String keyfilePw) throws GeneralSecurityException, IOException {
		    /*
		     * Set up a key manager for client authentication
		     * if asked by the server.  Use the implementation's
		     * default TrustStore and secureRandom routines.
		     */
		    SSLSocketFactory factory = null;
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;
			
			if (keyfile == null || "".equals(keyfile.trim()) ) {
				return null;
			}
			char[] passphrase = keyfilePw.toCharArray();

//			ctx = SSLContext.getInstance("TLS");	// RH, 20210316, o
			ctx = SSLContext.getInstance("TLSv1.2");	// RH, 20210316, n, we'll force v1.2
			kmf = KeyManagerFactory.getInstance("SunX509");
			ks = KeyStore.getInstance("JKS");

			ks.load(new FileInputStream(keyfile), passphrase);

			kmf.init(ks, passphrase);
			ctx.init(kmf.getKeyManagers(), null, null);

			factory = ctx.getSocketFactory();

			return factory;
			
		}

	
}
