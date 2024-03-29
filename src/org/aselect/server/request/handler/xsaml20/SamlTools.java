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
package org.aselect.server.request.handler.xsaml20;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedElementType;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedData;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.LocalKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SamlTools
{
	private static final String MODULE = "SamlTools";

	// 20091203, generate our own id
	/**
	 * Generate identifier.
	 * 
	 * @param systemLogger
	 *            the system logger
	 * @param sModule
	 *            the module
	 * @return the string
	 * @throws ASelectException
	 */
	public static String generateIdentifier(ASelectSystemLogger systemLogger, String sModule)
	throws ASelectException
	{
		String sMethod = "generateIdentifier";
		byte[] baRandomBytes = new byte[20];

		CryptoEngine.nextRandomBytes(baRandomBytes);
		return "I" + Utils.byteArrayToHexString(baRandomBytes);
	}

	/**
	 * Helper method to detect if the HttpServletRequest is signed The HttpServletRequest is signed if:
	 * <ul>
	 * <li>There is a parameter 'SigAlg' witch contains the value 'http://www.w3.org/2000/09/xmldsig#'</li>
	 * <li><b>And</b> there is a parameter 'Signature'</li>
	 * </ul>
	 * 
	 * @param httpRequest
	 *            the http request
	 * @return boolean
	 */
	@SuppressWarnings("unchecked")
	public static boolean isSigned(HttpServletRequest httpRequest)
	{
		Enumeration<String> enumParameterNames = httpRequest.getParameterNames();

		boolean bSigAlg = false;
		boolean bSignature = false;

		while (enumParameterNames.hasMoreElements() && (!bSigAlg || !bSignature)) {
			String sParameterName = enumParameterNames.nextElement();
			if (!bSigAlg)
				bSigAlg = ( httpRequest.getParameter(sParameterName).contains(XMLConstants.XMLSIG_NS) )	// Backward compatibility, 
								//though should be equal to SignatureConstants.ALGO_ID_DIGEST_SHA1 
				// RH, 20140310, sn
							|| ( httpRequest.getParameter(sParameterName).contains(SignatureConstants.ALGO_ID_DIGEST_SHA1) )
							|| ( httpRequest.getParameter(sParameterName).contains(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256) );
				// RH, 20140310, en
			if (!bSignature)
				bSignature = sParameterName.equals(Signature.DEFAULT_ELEMENT_LOCAL_NAME);
		}
		return bSigAlg && bSignature;
	}

	/**
	 * Helper method to verify the Signature of a HTTP GET request.
	 * 
	 * @param key
	 *            PublicKey
	 * @param httpRequest
	 *            HttpServletRequest
	 * @return boolean
	 * @throws MessageDecodingException
	 *             the message decoding exception
	 */
	/*
	public static boolean verifySignature(PublicKey key, HttpServletRequest httpRequest)
	throws MessageDecodingException
	{
		String sMethod = "verifySignature";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "Public key=" + key + " hashcode=" + key.hashCode());

		String signingAlgo;
		if (key instanceof RSAPublicKey) {
			signingAlgo = "SHA1withRSA";
		}
		else {
			signingAlgo = "SHA1withDSA";
		}

		// The signature was set on the complete query string, except the Signature parameter
		// RH, 20140310, Now following SAML specs
		try {
			String sQuery = httpRequest.getQueryString();// use query string because original urlencoded values must be used
														// do not url re-encode because url-encoding is not canonical
														// (other party may have different, though equally valid, url-encoding algoritm
			StringTokenizer tokenizer = new StringTokenizer(sQuery, "&");
			String sData = "";
			String[] verifyData = new String[3];
			while (tokenizer.hasMoreTokens()) {
				String s = tokenizer.nextToken();
				systemLogger.log(Level.FINEST, MODULE, sMethod, "Token=[" + s + "]");
				String sDecoded = URLDecoder.decode(s, "UTF-8");
				// RH, 20140307, so
//				if (sDecoded.equals("RelayState=[RelayState]"))
//					///////////////// empty RelayState should not be have been send, so we'll ignore it
//					; // 20091118, Bauke: ignore "empty" RelayState (came from logout_info.html)
//				else if (!s.startsWith("Signature=") && !s.startsWith("consent=")) {
//					sData += s + "&";
//				}
				// RH, 20140307, eo
				// RH, 20140307, sn
				if (sDecoded.equals("RelayState=[RelayState]"))
					continue; // 20091118, Bauke: ignore "empty" RelayState (came from logout_info.html)
								// keep this for backward compatibility
				
				// SAMLRequest=value&RelayState=value&SigAlg=value
				// SAMLResponse=value&RelayState=value&SigAlg=value
				if (s.startsWith("SAMLRequest=")) {
					verifyData[0] = s;
				} else if (s.startsWith("SAMLResponse=")) {
					verifyData[0] = s;
				} else if (s.startsWith("RelayState=")) {
					verifyData[1] = s;
				} else if (s.startsWith("SigAlg=")) {
					verifyData[2] = s;
					String sigAlgDecoded = URLDecoder.decode(s, "UTF-8");
					if ( (key instanceof RSAPublicKey) 
							&& (sigAlgDecoded.contains(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256)) ) {
						signingAlgo = "SHA256withRSA";	// Allow for SHA256
					}
					
				}
				// RH, 20140307, en
			}
			
//			sData = sData.substring(0, sData.length() - 1); // Delete the last '&'
			sData = verifyData[0] + "&" + (verifyData[1] != null ? verifyData[1] + "&" : "") + verifyData[2];
			systemLogger.log(Level.FINE, MODULE, sMethod, "Check [" + sData + "]");

			java.security.Signature signature = java.security.Signature.getInstance(signingAlgo);
			// RM_50_01
			signature.initVerify(key);
//			byte[] bData = sData.getBytes();	// RH, 20140307, o
			byte[] bData = sData.getBytes("UTF-8");	// RH, 20140307, o
			signature.update(bData);

			String sSig = httpRequest.getParameter("Signature");
			if (sSig == null)
				systemLogger.log(Level.SEVERE, MODULE, sMethod, "Signature NOT PRESENT");
			byte[] bSig = Base64.decode(sSig);
			return signature.verify(bSig);
		}
		catch (Exception e) {
			throw new MessageDecodingException("Unable to verify  signature", e);
		}
	}
	*/

	/**
	 * Helper method to verify the Signature of a HTTP GET request.
	 * 
	 * @param key
	 *            List<PublicKey>
	 * @param httpRequest
	 *            HttpServletRequest
	 * @return boolean
	 * @throws MessageDecodingException
	 *             the message decoding exception
	*/
	
	public static boolean verifySignature(List<PublicKey> keys, HttpServletRequest httpRequest)
	throws MessageDecodingException
	{
		String sMethod = "verifySignature";
		
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		boolean signatureOK = false;
		for (PublicKey key : keys) {	// This loop must be tighter but then we have to move the "key instanceof RSA.... also"
			systemLogger.log(Level.INFO, MODULE, sMethod, "Public key=" + key + " hashcode=" + key.hashCode());
	
			String signingAlgo;
			if (key instanceof RSAPublicKey) {
				signingAlgo = "SHA1withRSA";
			}
			else {
				signingAlgo = "SHA1withDSA";
			}
	
			// The signature was set on the complete query string, except the Signature parameter
			// RH, 20140310, Now following SAML specs
			try {
				String sQuery = httpRequest.getQueryString();// use query string because original urlencoded values must be used
															// do not url re-encode because url-encoding is not canonical
															// (other party may have different, though equally valid, url-encoding algoritm
				StringTokenizer tokenizer = new StringTokenizer(sQuery, "&");
				String sData = "";
				String[] verifyData = new String[3];
				while (tokenizer.hasMoreTokens()) {
					String s = tokenizer.nextToken();
					systemLogger.log(Level.FINEST, MODULE, sMethod, "Token=[" + s + "]");
					String sDecoded = URLDecoder.decode(s, "UTF-8");
					// RH, 20140307, so
	//				if (sDecoded.equals("RelayState=[RelayState]"))
	//					///////////////// empty RelayState should not be have been send, so we'll ignore it
	//					; // 20091118, Bauke: ignore "empty" RelayState (came from logout_info.html)
	//				else if (!s.startsWith("Signature=") && !s.startsWith("consent=")) {
	//					sData += s + "&";
	//				}
					// RH, 20140307, eo
					// RH, 20140307, sn
					if (sDecoded.equals("RelayState=[RelayState]"))
						continue; // 20091118, Bauke: ignore "empty" RelayState (came from logout_info.html)
									// keep this for backward compatibility
					
					// SAMLRequest=value&RelayState=value&SigAlg=value
					// SAMLResponse=value&RelayState=value&SigAlg=value
					if (s.startsWith("SAMLRequest=")) {
						verifyData[0] = s;
					} else if (s.startsWith("SAMLResponse=")) {
						verifyData[0] = s;
					} else if (s.startsWith("RelayState=")) {
						verifyData[1] = s;
					} else if (s.startsWith("SigAlg=")) {
						verifyData[2] = s;
						String sigAlgDecoded = URLDecoder.decode(s, "UTF-8");
						if ( (key instanceof RSAPublicKey) 
								&& (sigAlgDecoded.contains(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256)) ) {
							signingAlgo = "SHA256withRSA";	// Allow for SHA256
						}
						
					}
					// RH, 20140307, en
				}
				
	//			sData = sData.substring(0, sData.length() - 1); // Delete the last '&'
				sData = verifyData[0] + "&" + (verifyData[1] != null ? verifyData[1] + "&" : "") + verifyData[2];
				systemLogger.log(Level.FINE, MODULE, sMethod, "Check [" + sData + "]");
	
				java.security.Signature signature = java.security.Signature.getInstance(signingAlgo);
				// RM_50_01
				signature.initVerify(key);
	//			byte[] bData = sData.getBytes();	// RH, 20140307, o
				byte[] bData = sData.getBytes("UTF-8");	// RH, 20140307, o
				signature.update(bData);
	
				String sSig = httpRequest.getParameter("Signature");
				if (sSig == null)
					systemLogger.log(Level.SEVERE, MODULE, sMethod, "Signature NOT PRESENT");
				byte[] bSig = Base64.decode(sSig);
				signatureOK = signature.verify(bSig);
				if (signatureOK) break;
			}
			catch (Exception e) {
				throw new MessageDecodingException("Unable to verify  signature", e);
			}
			
		}
		return signatureOK;
	}

	// For the new opensaml20 library
	/**
	 * Check signature.
	 * 
	 * @param ssObject
	 *            the SAML object to be checked
	 * @param List<publicKey>
	 *            list of public keys to verify against
	 * @return true, if successful
	 * @throws ASelectException
	 */
	public static boolean checkSignature(SignableSAMLObject ssObject, List <PublicKey> publicKeys)
	throws ASelectException
	{
		String sMethod = "checkSignature";
		
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		Signature sig = ssObject.getSignature();
	
		if (sig == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No signature found in SAML object");
			return false;
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Trying publicKey(s)=" + publicKeys);
	
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(sig);
		}
		catch (ValidationException e) {
			// Indicates signature did not conform to SAML Signature profile
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot validate signature, signature did not conform to SAML Signature profile: " + e.getMessage());
			return false;
		}
		boolean signature_valid = false;
		for (PublicKey publicKey : publicKeys) {

			BasicCredential credential = new BasicCredential();
			credential.setPublicKey(publicKey);
		
			SignatureValidator sigValidator = new SignatureValidator(credential);
			try {
				sigValidator.validate(sig);
			}
			catch (ValidationException e) {
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot verify signature, signature was not cryptographically valid");
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Cannot verify signature on this attempt, signature was not cryptographically valid, trying next");
//				return false;
				continue;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Valid signature found for pubKey=" + publicKey);
			signature_valid = true;
			break;
		}
//		return true;
		if (!signature_valid) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot verify signature, signature was not cryptographically valid");
		}
		return signature_valid;
	}

	/**
	 * Check OpenSAML2 library objects for subjectLocalityAddress validity.
	 * 
	 * @param obj
	 *            The object to be checked
	 * @param refAddress
	 *            Reference (ip)address to check against
	 * @return valid true = valid, false otherwise
	 * @throws ValidationException
	 *             Thrown if an error occurs
	 * @throws ASelectException
	 *             the ASelect exception
	 */
	public static boolean checkLocalityAddress(SAMLObject obj, String refAddress)
	throws ASelectException
	{
		// We may want to check the DNSName here
		boolean valid = false;
		String sMethod = "checkLocalityAddress";
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "obj->" + obj + "refAddress->" + refAddress);
		// This might be implemented more elegantly
		if ((obj instanceof AuthnStatement) && (refAddress != null)) {
			if (((AuthnStatement) obj).getSubjectLocality() != null
					&& refAddress.equals(((AuthnStatement) obj).getSubjectLocality().getAddress())) {
				valid = true;
			}
			// There might be more saml2 types to implement here
		}
		else {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot validate the object:" + obj + " with refAddress:"
					+ refAddress);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "checkLocalityAddress evaluates to: " + valid);
		return valid;
	}

	/**
	 * Check OpenSAML2 library objects for timeRestrictions NotBefore and NotOnOrAfter comparing with now.
	 * 
	 * @param obj
	 *            The object to be checked
	 * @return valid true = valid, false otherwise (invalid or undetermined)
	 * @throws ValidationException
	 *             Thrown if an error occurs
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static boolean checkValidityInterval(SAMLObject obj)
	throws ASelectException
	{
		return checkValidityInterval(obj, new DateTime());
	}

	/**
	 * Check OpenSAML2 library objects for timeRestrictions NotBefore and NotOnOrAfter.
	 * 
	 * @param obj
	 *            The object to be checked
	 * @param refInstant
	 *            Reference moment in time
	 * @return valid true = valid, false otherwise (invalid or undetermined)
	 * @throws ValidationException
	 *             Thrown if an error occurs
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static boolean checkValidityInterval(SAMLObject obj, DateTime refInstant)
	throws ASelectException
	{
		boolean valid = true;
		String sMethod = "checkValidityInterval";
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "refInstant=" + refInstant);
		
		// We could do it with some sort of command pattern, for now we do it the "hard" way
		// We would have been happy with some common ancestor that implements Conditions or so ;-)
		DateTime nbf = null;
		DateTime nooa = null;
		if (obj instanceof Assertion) {
			if (((Assertion) obj).getConditions() != null && ((Assertion) obj).getConditions().getNotBefore() != null)
				nbf = ((Assertion) obj).getConditions().getNotBefore();
			if (((Assertion) obj).getConditions() != null
					&& ((Assertion) obj).getConditions().getNotOnOrAfter() != null)
				nooa = ((Assertion) obj).getConditions().getNotOnOrAfter();
		}
		else if (obj instanceof AuthnRequest) {
			if (((AuthnRequest) obj).getConditions() != null
					&& ((AuthnRequest) obj).getConditions().getNotBefore() != null)
				nbf = ((AuthnRequest) obj).getConditions().getNotBefore();
			if (((AuthnRequest) obj).getConditions() != null
					&& ((AuthnRequest) obj).getConditions().getNotOnOrAfter() != null)
				nooa = ((AuthnRequest) obj).getConditions().getNotOnOrAfter();
		}
		else if (obj instanceof LogoutRequest) {
			nooa = ((LogoutRequest) obj).getNotOnOrAfter();
		}
		else if (obj instanceof SubjectConfirmationData) {
			nooa = ((SubjectConfirmationData) obj).getNotOnOrAfter();
			nbf = ((SubjectConfirmationData) obj).getNotBefore();
		}
		// Other saml2 types would go here

		// Refer to saml2-core (2.5.1.2 Attributes NotBefore and NotOnOrAfter)
		if (nbf != null && refInstant.isBefore(nbf)) {
			valid = false;
		}
		if (nooa != null && !refInstant.isBefore(nooa)) {
			valid = false;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "checkValidityInterval evaluates to: " + valid);
		return valid;
	}

	/**
	 * Set OpenSAML2 library Conditions object for timeRestrictions NotBefore and NotOnOrAfter.
	 * 
	 * @param obj
	 *            The object to which conditions are to be added
	 * @param refInstant
	 *            Reference moment in time
	 * @param maxNotBefore
	 *            the max not before
	 * @param maxNotOnOrAfter
	 *            the max not on or after
	 * @return valid Object with conditions (if not all timeRestrictions were null) otherwise return same object
	 *         unmodified
	 * @throws ValidationException
	 *             Thrown if an error occurs while placing conditions
	 * @throws ASelectException
	 */
	public static SAMLObject setValidityInterval(SAMLObject obj, DateTime refInstant,
			Long maxNotBefore, Long maxNotOnOrAfter)
	throws ASelectException
	{
		String sMethod = "setValidityInterval";
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "obj->" + obj + ", refInstant->" + refInstant
				+ ", maxNotBefore->" + maxNotBefore + ", maxNotOnOrAfter->" + maxNotOnOrAfter);
		
		// Still think this is a bit clumsy, maybe implement some sort of
		// (command) pattern here or use generics
		if (obj instanceof Assertion) {
			Conditions conditions = ((Assertion) obj).getConditions();
			if (maxNotBefore != null || maxNotOnOrAfter != null) {
				XMLObjectBuilderFactory oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
				SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) oBuilderFactory
						.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

				if (maxNotBefore != null) {
					conditions = (conditions == null) ? conditionsBuilder.buildObject() : conditions;
					conditions.setNotBefore(refInstant.minus(maxNotBefore.longValue()));
				}
				if (maxNotOnOrAfter != null) {
					conditions = (conditions == null) ? conditionsBuilder.buildObject() : conditions;
					conditions.setNotOnOrAfter(refInstant.plus(maxNotOnOrAfter.longValue()));
				}
			}
//			if (conditions != null) {	// RH, 20160108, o
			if (conditions != null && ((Assertion) obj).getConditions() == null) {		// RH, 20160108, n // add only if not yet present
				((Assertion) obj).setConditions(conditions);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Conditions added on Assertion->" + obj);
			}
		}
		else // not instanceof Assertion
		if (obj instanceof AuthnRequest) {
			Conditions conditions = ((AuthnRequest) obj).getConditions();
			if (maxNotBefore != null || maxNotOnOrAfter != null) {
				XMLObjectBuilderFactory oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
				SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) oBuilderFactory
						.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

				if (maxNotBefore != null) {
					conditions = (conditions == null) ? conditionsBuilder.buildObject() : conditions;
					conditions.setNotBefore(refInstant.minus(maxNotBefore.longValue()));
				}
				if (maxNotOnOrAfter != null) {
					conditions = (conditions == null) ? conditionsBuilder.buildObject() : conditions;
					conditions.setNotOnOrAfter(refInstant.plus(maxNotOnOrAfter.longValue()));
				}
			}
//			if (conditions != null) {		// RH, 20160108, o
//			if (conditions != null && ((Assertion) obj).getConditions() == null) {	// RH, 20160108, n	// add only if not yet present, RH, 20160310, o
			if (conditions != null && ((AuthnRequest) obj).getConditions() == null) {	// RH, 20160108, n	// add only if not yet present, RH, 20160310, n
				((AuthnRequest) obj).setConditions(conditions);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Conditions added on AuthnRequest->" + obj);
			}
		}
		else // not instanceof AuthnRequest
		if (obj instanceof SubjectConfirmationData) {
			// RH, 20160418, so,  saml specs say: do not set for method "bearer". We only support "bearer"
//			if (maxNotBefore != null) {
//				((SubjectConfirmationData) obj).setNotBefore(refInstant.minus(maxNotBefore.longValue()));
//			}
			// RH, 20160418, so
			if (maxNotOnOrAfter != null) {
				((SubjectConfirmationData) obj).setNotOnOrAfter(refInstant.plus(maxNotOnOrAfter.longValue()));
			}
		}
		else // not instanceof SubjectConfirmationData
		if (obj instanceof LogoutRequest) {
			if (maxNotOnOrAfter != null) {
				((LogoutRequest) obj).setNotOnOrAfter(refInstant.plus(maxNotOnOrAfter.longValue()));
			}
		}// not instanceof LogoutRequest

		return obj;
	}

	/**
	 * Set OpenSAML2 library Conditions object for timeRestrictions NotBefore and NotOnOrAfter.
	 * 
	 * @param obj
	 *            The object to which restriction are to be added
	 * @param restriction
	 *            AudienceRestriction to add to Condition of this object (create Condition if not exists
	 * @return valid Object with restrictions/conditions (if not restriction == null)
	 * @throws ValidationException
	 *             Thrown if an error occurs while placing conditions
	 * @throws ASelectException
	 *             the a select exception
	 */
	public static SAMLObject setAudienceRestrictions(SAMLObject obj, AudienceRestriction restriction)
	throws ASelectException
	{

		String sMethod = "setAudienceRestrictions";
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "obj->" + obj + ", restriction->" + restriction);
		// Still think this is a bit clumsy, maybe implement some sort of
		// (command) pattern here or use generics
		if (obj instanceof Assertion) {
			Conditions conditions = null;
			if (restriction != null) {
				if (((Assertion) obj).getConditions() == null) {
					XMLObjectBuilderFactory oBuilderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
					SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) oBuilderFactory
							.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
					((Assertion) obj).setConditions(conditions);
					_systemLogger.log(Level.INFO, MODULE, sMethod, "Conditions set on Assertion->" + obj);
					((Assertion) obj).setConditions(conditionsBuilder.buildObject());
				}
				((Assertion) obj).getConditions().getAudienceRestrictions().add(restriction);
			}
		}
		// Other SAMLObjects would go here
		return obj;
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
	
//	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj)
//	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, PrivateKey specificKey)
	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, PartnerData.Crypto specificCrypto)
	throws ASelectException
	{
//		return signSamlObject(obj, "sha1");  // default algorithm
//		return signSamlObject(obj, "sha1", specificKey);  // default algorithm
		return signSamlObject(obj, "sha1", specificCrypto);  // default algorithm
	}
	
	/*
	 * @param sAlgo
	 *            The algorithm to use [ "sha256" | "sha1" ] defaults to "sha1"
	 */
//	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, String sAlgo)
//	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, String sAlgo, PrivateKey specificKey)
	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, String sAlgo, PartnerData.Crypto specificCrypto)
	throws ASelectException
	{
//		return signSamlObject(obj, sAlgo, false, false);
//		return signSamlObject(obj, sAlgo, false, false, specificKey);
		return signSamlObject(obj, sAlgo, false, false, specificCrypto);
	}

	/*
	 * @param    addKeyName         
	 *            Add the (default) keyname in a KeyInfo element
	 * @param    addCertificate         
	 *            Add the (default) certificate in a KeyInfo element
	 */
//	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, String sAlgo,
//										boolean addKeyName, boolean addCertificate)
	public static SignableSAMLObject signSamlObject(SignableSAMLObject obj, String sAlgo,
//										boolean addKeyName, boolean addCertificate, PrivateKey specificKey)
										boolean addKeyName, boolean addCertificate, PartnerData.Crypto specificCrypto)
	
	throws ASelectException
	{
		String sMethod = "sign(SignableSAMLObject obj)";
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
		boolean useSha256 = "sha256".equals(sAlgo);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "obj->" + obj);
		if (!obj.isSigned()) {
			ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
//			PrivateKey privKey = _oASelectConfigManager.getDefaultPrivateKey();// RH, 20180917, o
			// RH, 20180917, sn
			PrivateKey privKey = null;
			if (specificCrypto != null) {
				privKey = specificCrypto.getPrivateKey();
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using specific private key");
			} else {
				privKey = _oASelectConfigManager.getDefaultPrivateKey();
			}
			// RH, 20180917, en
			Signature signature = new SignatureBuilder().buildObject();
			String signingAlgo;
			if ("RSA".equalsIgnoreCase(privKey.getAlgorithm())) {
				signingAlgo = (useSha256)? SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256:
											SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
			}
			else {
				signingAlgo = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "privKey algorithm="+privKey.getAlgorithm()+
					" use signing algorithm: " + signingAlgo);

			BasicCredential credential = new BasicCredential();
			credential.setPrivateKey(privKey);
			signature.setSigningCredential(credential);
			signature.setSignatureAlgorithm(signingAlgo);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			// add keyinfo
			if (addKeyName || addCertificate) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Adding keyinfo");
				
				// Tried KeyInfoGenerator but.generate(credential)  always returns null
				// so build keyinfo manually
				XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
				KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
				KeyInfo keyinfo = (KeyInfo)	keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
						// RH, 20180921, sn
				java.security.cert.X509Certificate x509Certificate = null;
				if (specificCrypto != null) {
					x509Certificate = specificCrypto.getX509Cert();
				} else {
					x509Certificate =  _oASelectConfigManager.getDefaultCertificate();
				}
				// RH, 20180921, en
//				java.security.cert.X509Certificate x509Certificate =  _oASelectConfigManager.getDefaultCertificate();	// RH, 20180921, o
				if ( addCertificate ) {
					try {
						KeyInfoHelper.addCertificate(keyinfo, x509Certificate);
					}
					catch (CertificateEncodingException e) {
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Problem adding certificate to keyinfo");
						throw new ASelectException(e.getMessage());
					}
				}
				if ( addKeyName ) {
					// RH, 20180921, sn
					if (specificCrypto != null) {
						KeyInfoHelper.addKeyName(keyinfo, specificCrypto.getCertFingerPrint());
					} else {
						KeyInfoHelper.addKeyName(keyinfo, _oASelectConfigManager.getDefaultCertId());
					}
					// RH, 20180921, en
//					KeyInfoHelper.addKeyName(keyinfo, _oASelectConfigManager.getDefaultCertId());	/ RH, 20180921, o
				}
				signature.setKeyInfo(keyinfo);
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Added keyinfo");
			}
			else {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "No keyinfo added");
			}
			
			obj.setSignature(signature);

			// 20100315, Bauke: Set Sha256, call after setSignature, remove all ContentReferences,
			// including the default and add a new one for Sha256 (eHerkenning)
			if (useSha256) {
	            SAMLObjectContentReference contentReference = new SAMLObjectContentReference(obj);
	            contentReference.setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
	            signature.getContentReferences().clear();  // must be done after setSignature() (it adds a default to the list)
	            signature.getContentReferences().add(contentReference);            
			}

            try {
				org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(obj).marshall(obj);
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot marshall object for signature", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			try {
				Signer.signObject(signature);
			}
			catch (SignatureException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Cannot sign the object", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		else
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Object already signed!");

		return obj;
	}
	
	// RH, 20201210, sn
	public static SAMLObject decryptSamlObject(EncryptedElementType obj)
	{
		return decryptSamlObject(obj, null);
	}
	// RH, 20201210, en

//	public static SAMLObject decryptSamlObject(EncryptedID obj)
//	public static SAMLObject decryptSamlObject(EncryptedElementType obj)	// RH, 20201210, o
	public static SAMLObject decryptSamlObject(EncryptedElementType obj, PartnerData.Crypto specificCrypto)	// RH, 20201210, n
	 
	{
		String sMethod = "decryptSamlObject";
		//
		// One-time init code here
		//
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

		ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
		
//		PrivateKey privKey = _oASelectConfigManager.getDefaultPrivateKey();	// RH, 20201210, o
		// RH, 20201210, sn
		PrivateKey privKey = null;
		if (specificCrypto != null) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Looking for specific private key");
			privKey =  specificCrypto.getPrivateKey();	// might not be present
		}
		if (privKey != null) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found specific private key");
		} else {	// like we used to
			privKey = _oASelectConfigManager.getDefaultPrivateKey();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using default private key");
		}
		// RH, 20201210, en
		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(privKey);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found private key with format:" + privKey.getFormat());

		// Collection of local credentials, where each contains
		// a private key that corresponds to a public key that may
		// have been used by other parties for encryption
//		List<Credential> localCredentials = getLocalCredentials();
		// if we're gono take the init code out of the method we'll have better use the synchronized version
//		List<Credential> localCredentials = new getLocalCredentials();
		List<Credential> localCredentials = Collections.synchronizedList(new ArrayList<Credential>());
		synchronized (localCredentials) {
			localCredentials.add(credential);
		}

		CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created CollectionCredentialResolver");
		         
		// Support EncryptedKey/KeyInfo containing decryption key hints via
		// KeyValue/RSAKeyValue and X509Data/X509Certificate
		List<KeyInfoProvider> kiProviders = new ArrayList<KeyInfoProvider>();
		kiProviders.add( new RSAKeyValueProvider() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added RSAKeyValueProvider to KeyInfoProvider List");
		kiProviders.add( new InlineX509DataProvider() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineX509DataProvider to KeyInfoProvider List");
		         
		// Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
		// local credential resolver.
		KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created KeyInfoCredentialResolver");
		         
		// Supports resolution of EncryptedKeys by 3 common placement mechanisms
		ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
		encryptedKeyResolver.getResolverChain().add( new InlineEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineEncryptedKeyResolver to ChainingEncryptedKeyResolver");
		encryptedKeyResolver.getResolverChain().add( new EncryptedElementTypeEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added EncryptedElementTypeEncryptedKeyResolver to ChainingEncryptedKeyResolver");
		encryptedKeyResolver.getResolverChain().add( new SimpleRetrievalMethodEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added SimpleRetrievalMethodEncryptedKeyResolver to ChainingEncryptedKeyResolver");
		 
		Decrypter samlDecrypter =
		    new Decrypter(null, kekResolver, encryptedKeyResolver);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Decrypter with providername: " + samlDecrypter.getJCAProviderName());
	
		// We'll store the decryptor later, for now we just use it
//		storeDecrypter(samlDecrypter);
		         
		// End init code
		         
		/* ........................... */
		    
		// Begin message processing code
		        
		// for now we use the decryptor just created;
//		Decrypter decrypter = getDecrypter();
		Decrypter decrypter = samlDecrypter;
//		EncryptedAssertion encryptedAssertion = getEncryptedAssertion();
//		try {
//		    Assertion assertion = decrypter.decrypt(encryptedAssertion);
//		} catch (DecryptionException e) {
//		    e.printStackTrace();
//		}
		
//		EncryptedID encryptedEntityID = obj;
//		SAMLObject samlObject = null;
		XMLObject samlObject = null;
		try {
//		     samlObject = decrypter.decrypt(encryptedEntityID);
		     samlObject = decrypter.decryptData(obj.getEncryptedData());
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "SamlObject decrypted");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "XMLObject decrypted");
			 if (! (samlObject instanceof SAMLObject)) {
				 samlObject = null;
				 throw new DecryptionException("Decrypted XMLObject was not an instance of SAMLObject");
		        }
			 } catch (DecryptionException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to decrypted SamlObject: " + e.getMessage());
		}
		return (SAMLObject) samlObject;
	}
	
// RH, 20210713, sn
	public static EncryptedElementType encryptSamlObject(SAMLObject obj, PublicKey pubkey)
//	public static EncryptedElementType encryptSamlObject(XMLObject obj, PublicKey pubkey)
	 
	{
		String sMethod = "encryptSamlObject";
		//
		// One-time init code here
		//
		ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

//		ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();

		BasicCredential credential = new BasicCredential();
		credential.setUsageType(UsageType.ENCRYPTION);
		credential.setPublicKey(pubkey);

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using public key with format:" + pubkey.getFormat());

/*
		// Collection of local credentials, where each contains
		// a private key that corresponds to a public key that may
		// have been used by other parties for encryption
//		List<Credential> localCredentials = getLocalCredentials();
		// if we're gono take the init code out of the method we'll have better use the synchronized version
//		List<Credential> localCredentials = new getLocalCredentials();
		List<Credential> localCredentials = Collections.synchronizedList(new ArrayList<Credential>());
		synchronized (localCredentials) {
			localCredentials.add(credential);
		}

		CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created CollectionCredentialResolver");
		         
		// Support EncryptedKey/KeyInfo containing decryption key hints via
		// KeyValue/RSAKeyValue and X509Data/X509Certificate
		List<KeyInfoProvider> kiProviders = new ArrayList<KeyInfoProvider>();
		kiProviders.add( new RSAKeyValueProvider() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added RSAKeyValueProvider to KeyInfoProvider List");
		kiProviders.add( new InlineX509DataProvider() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineX509DataProvider to KeyInfoProvider List");
		         
		// Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
		// local credential resolver.
		KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created KeyInfoCredentialResolver");
		         
		// Supports resolution of EncryptedKeys by 3 common placement mechanisms
		ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
		encryptedKeyResolver.getResolverChain().add( new InlineEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineEncryptedKeyResolver to ChainingEncryptedKeyResolver");
		encryptedKeyResolver.getResolverChain().add( new EncryptedElementTypeEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added EncryptedElementTypeEncryptedKeyResolver to ChainingEncryptedKeyResolver");
		encryptedKeyResolver.getResolverChain().add( new SimpleRetrievalMethodEncryptedKeyResolver() );
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added SimpleRetrievalMethodEncryptedKeyResolver to ChainingEncryptedKeyResolver");
*/
		
		EncryptionParameters encParams = new EncryptionParameters();
//		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "encParams.getAlgorithm():" + encParams.getAlgorithm());

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(credential);
		kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "kekParams.getAlgorithm:" + kekParams.getAlgorithm());
		KeyInfoGeneratorFactory kigf =
		    Configuration.getGlobalSecurityConfiguration()
		    .getKeyInfoGeneratorManager().getDefaultManager()
		    .getFactory(credential);

		kekParams.setKeyInfoGenerator(kigf.newInstance());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "kekParams.getKeyInfoGenerator():" + kekParams.getKeyInfoGenerator());
		         
		Encrypter samlEncrypter =
		    new Encrypter(encParams, kekParams);
//		org.opensaml.xml.encryption.Encrypter samlEncrypter =
//			    new org.opensaml.xml.encryption.Encrypter();
		
//		samlEncrypter.setKeyPlacement(KeyPlacement.PEER);	// default
//		samlEncrypter.setKeyPlacement(KeyPlacement.INLINE);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Encrypter with KeyPlacement: " + samlEncrypter.getKeyPlacement());
	
		/* ........................... */
		    
		// Begin message processing code
		        
		
//		EncryptedID encryptedEntityID = obj;
//		SAMLObject samlObject = null;
		XMLObject samlObject = null;
//		EncryptedID encrID =  null;
		try {
//		     samlObject = decrypter.decrypt(encryptedEntityID);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Trying to encrypt: " + obj);
		     samlObject = samlEncrypter.encrypt((Attribute)obj);	// works
//		     samlObject = samlEncrypter.encryptElement(obj, encParams, kekParams);	// Does NOT place key as PEER
//		     XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
//
//		     SAMLObjectBuilder<EncryptedID> encryptedIDBuilder = (SAMLObjectBuilder<EncryptedID>) builderFactory.getBuilder(EncryptedID.DEFAULT_ELEMENT_NAME);
//
//		     encrID = encryptedIDBuilder.buildObject();
//		     encrID.setEncryptedData((EncryptedData) samlObject);

		     
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "SamlObject decrypted");
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "XMLObject encrypted: " + XMLHelper.prettyPrintXML(samlObject.getDOM()));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "XMLObject encrypted: " + samlObject);
			 if (! (samlObject instanceof EncryptedElementType)) {
				 samlObject = null;
				 throw new EncryptionException("Encrypted XMLObject was not an instance of EncryptedElementType");
		        }
//			 if (! (encrID instanceof EncryptedElementType)) {
//				 encrID = null;
//				 throw new EncryptionException("Encrypted XMLObject was not an instance of EncryptedElementType");
//		        }
		} catch (EncryptionException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to encrypt SamlObject: " + e.getMessage());
		}
		return (EncryptedElementType) samlObject;
//		return (EncryptedElementType) encrID;
		
	}
// RH, 20210713, en	
	
	
	// RH, 20210713, sn
//		public static EncryptedElementType encryptSamlObject(SAMLObject obj, PublicKey pubkey)
		public static EncryptedElementType encryptSamlObjectValue(XMLObject obj, PublicKey pubkey)
		 
		{
			String sMethod = "encryptSamlObjectValue";
			//
			// One-time init code here
			//
			ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

//			ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();

			EncryptedID encrID = null;
			BasicCredential credential = new BasicCredential();
			credential.setUsageType(UsageType.ENCRYPTION);
			credential.setPublicKey(pubkey);

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using public key with format:" + pubkey.getFormat());

	/*
			// Collection of local credentials, where each contains
			// a private key that corresponds to a public key that may
			// have been used by other parties for encryption
//			List<Credential> localCredentials = getLocalCredentials();
			// if we're gono take the init code out of the method we'll have better use the synchronized version
//			List<Credential> localCredentials = new getLocalCredentials();
			List<Credential> localCredentials = Collections.synchronizedList(new ArrayList<Credential>());
			synchronized (localCredentials) {
				localCredentials.add(credential);
			}

			CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created CollectionCredentialResolver");
			         
			// Support EncryptedKey/KeyInfo containing decryption key hints via
			// KeyValue/RSAKeyValue and X509Data/X509Certificate
			List<KeyInfoProvider> kiProviders = new ArrayList<KeyInfoProvider>();
			kiProviders.add( new RSAKeyValueProvider() );
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added RSAKeyValueProvider to KeyInfoProvider List");
			kiProviders.add( new InlineX509DataProvider() );
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineX509DataProvider to KeyInfoProvider List");
			         
			// Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
			// local credential resolver.
			KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created KeyInfoCredentialResolver");
			         
			// Supports resolution of EncryptedKeys by 3 common placement mechanisms
			ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
			encryptedKeyResolver.getResolverChain().add( new InlineEncryptedKeyResolver() );
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added InlineEncryptedKeyResolver to ChainingEncryptedKeyResolver");
			encryptedKeyResolver.getResolverChain().add( new EncryptedElementTypeEncryptedKeyResolver() );
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added EncryptedElementTypeEncryptedKeyResolver to ChainingEncryptedKeyResolver");
			encryptedKeyResolver.getResolverChain().add( new SimpleRetrievalMethodEncryptedKeyResolver() );
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Added SimpleRetrievalMethodEncryptedKeyResolver to ChainingEncryptedKeyResolver");
	*/
			
			EncryptionParameters encParams = new EncryptionParameters();
//			encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
			encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "encParams.getAlgorithm():" + encParams.getAlgorithm());

			KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
			kekParams.setEncryptionCredential(credential);
			kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "kekParams.getAlgorithm:" + kekParams.getAlgorithm());
			KeyInfoGeneratorFactory kigf =
			    Configuration.getGlobalSecurityConfiguration()
			    .getKeyInfoGeneratorManager().getDefaultManager()
			    .getFactory(credential);

			kekParams.setKeyInfoGenerator(kigf.newInstance());
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "kekParams.getKeyInfoGenerator():" + kekParams.getKeyInfoGenerator());
			         
//			Encrypter samlEncrypter =
//			    new Encrypter(encParams, kekParams);
			org.opensaml.xml.encryption.Encrypter samlEncrypter =
				    new org.opensaml.xml.encryption.Encrypter();
			
//			samlEncrypter.setKeyPlacement(KeyPlacement.PEER);	// default
//			samlEncrypter.setKeyPlacement(KeyPlacement.INLINE);
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created Encrypter with KeyPlacement: " + samlEncrypter.getKeyPlacement());
		
			/* ........................... */
			    
			// Begin message processing code
			        
			
//			EncryptedID encryptedEntityID = obj;
//			SAMLObject samlObject = null;
			XMLObject samlObject = null;
//			EncryptedID encrID =  null;
			try {
//			     samlObject = decrypter.decrypt(encryptedEntityID);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Trying to encrypt: " + obj);
//			     samlObject = samlEncrypter.encrypt((Attribute)obj);	// works
			     samlObject = samlEncrypter.encryptElement(obj, encParams, kekParams);	// Does NOT place key as PEER

			     XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
			     SAMLObjectBuilder<EncryptedID> encryptedIDBuilder = (SAMLObjectBuilder<EncryptedID>) builderFactory.getBuilder(EncryptedID.DEFAULT_ELEMENT_NAME);
			     encrID = encryptedIDBuilder.buildObject();
			     encrID.setEncryptedData((EncryptedData) samlObject);

			     
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "SamlObject decrypted");
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "XMLObject encrypted: " + XMLHelper.prettyPrintXML(samlObject.getDOM()));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "XMLObject encrypted: " + samlObject);
//				 if (! (samlObject instanceof EncryptedElementType)) {
//					 samlObject = null;
//					 throw new EncryptionException("Encrypted XMLObject was not an instance of EncryptedElementType");
//			        }
				 if (! (encrID instanceof EncryptedElementType)) {
					 encrID = null;
					 throw new EncryptionException("Encrypted XMLObject was not an instance of EncryptedElementType");
			        }
			} catch (EncryptionException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Failed to encrypt XMLObject: " + e.getMessage());
			}
//			return (EncryptedElementType) samlObject;
			return (EncryptedElementType) encrID;
			
		}
	// RH, 20210713, en	
	

	/**
	 * Build Logout Request <br>
	 * .
	 * 
	 * @param sServiceProviderUrl
	 *            String with SP .
	 * @param issuerUrl
	 *            String with Issuer .
	 * @param reason
	 *            String with logout reason.
	 * @param sTgT
	 *            the s tg t
	 * @param sNameID
	 *            the s name id
	 * @param  List<String>sessionindexes
	 * 				optional list of sessionindexes to kill
	 * @return the logout request
	 * @throws ASelectException
	 *             If building logout request fails.
	 */
//	public static LogoutRequest buildLogoutRequest(String sServiceProviderUrl, String sTgT, String sNameID,
//			String issuerUrl, String reason)
//	throws ASelectException	{	// for backward compatibility
//		return buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID,
//				issuerUrl, reason, null);
//	}

	public static LogoutRequest buildLogoutRequest(String sServiceProviderUrl, String sTgT, String sNameID,
			String issuerUrl, String reason, List<String>sessionindexes)
	throws ASelectException
	{
		return buildLogoutRequest( sServiceProviderUrl, sTgT, sNameID,
				 issuerUrl,  reason, sessionindexes, null);
	}
	
	@SuppressWarnings("unchecked")
	public static LogoutRequest buildLogoutRequest(String sServiceProviderUrl, String sTgT, String sNameID,
			String issuerUrl, String reason, List<String>sessionindexes, DateTime issueInstant)
	throws ASelectException
	{
		String sMethod = "buildLogoutRequest";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.INFO, MODULE, sMethod, "provider=" + sServiceProviderUrl);

		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		SAMLObjectBuilder<LogoutRequest> logoutRequestBuilder = (SAMLObjectBuilder<LogoutRequest>) builderFactory
				.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
		LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
		// verplichte velden
		logoutRequest.setID((sTgT != null) ? "_" + sTgT : SamlTools.generateIdentifier(systemLogger, MODULE));
		logoutRequest.setVersion(SAMLVersion.VERSION_20);
		
		if (issueInstant == null)  issueInstant = new DateTime();	// RH, 20120307, n
			
//		logoutRequest.setIssueInstant(new DateTime());	// RH, 20120307, o
		logoutRequest.setIssueInstant(issueInstant);	// RH, 20120307, n

		// een van de volgende 3 is verplicht baseId, encryptedId, nameId
		SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
				.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID nameId = nameIdBuilder.buildObject();
//		nameId.setFormat(NameIDType.TRANSIENT);	// RH, 20140801, n. We use transient id's for nameid	// RH, 20180619, o
		nameId.setFormat(sNameID.equals(sTgT) ? NameIDType.TRANSIENT : NameIDType.PERSISTENT);	// RH, 20140801, n. We use transient id's for nameid	// RH, 20180619, n
//		nameId.setFormat(NameIDType.TRANSIENT);	// RH, 20200121, n.For testing ddy
		nameId.setValue(sNameID);
		logoutRequest.setNameID(nameId);

		// optionele velden
		logoutRequest.setReason(reason);
		logoutRequest.setDestination(sServiceProviderUrl);
		
		
		// RH, 20120130, sn
		//	add optional SessionIndexes (Surf requires at least one)
		if (sessionindexes != null) {
			SAMLObjectBuilder<SessionIndex> sessionindexBuilder = (SAMLObjectBuilder<SessionIndex>) builderFactory
			.getBuilder(SessionIndex.DEFAULT_ELEMENT_NAME);
			for (String sSession : sessionindexes) {
				SessionIndex sessionindex = sessionindexBuilder.buildObject();
 				sessionindex.setSessionIndex(sSession);
				logoutRequest.getSessionIndexes().add(sessionindex);
			}
		}
		// RH, 20120130, en
		
		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
//		issuer.setFormat(Issuer.ENTITY); 	// saml specs say, MUST  be omitted or "entity" for Issuer
		issuer.setValue(issuerUrl);
		logoutRequest.setIssuer(issuer);

		return logoutRequest;
	}

	/**
	 * Build Logout Response. <br>
	 * 
	 * @param issuer
	 *            String with issuer.
	 * @param statusCodeValue
	 *            String with ???.
	 * @param inResponseTo
	 *            String with ???.
	 * @return the logout response
	 * @throws ASelectException
	 *             If building logout response fails.
	 */
	@SuppressWarnings("unchecked")
	public static LogoutResponse buildLogoutResponse(String issuer, String statusCodeValue, String inResponseTo)
	throws ASelectException
	{
		String sMethod = "buildLogoutResponse";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		SAMLObjectBuilder<LogoutResponse> logoutResponseBuilder = (SAMLObjectBuilder<LogoutResponse>) builderFactory
				.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();

		// Mandatory fields:
		String random;
		try {
			random = SamlTools.generateIdentifier(systemLogger, MODULE);
		}
		catch (ASelectException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
			// if generator failed we can use this
			random = "random" + Math.random();
		}
		logoutResponse.setID(random);
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setIssueInstant(new DateTime());

		SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
				.getBuilder(Status.DEFAULT_ELEMENT_NAME);
		Status status = statusBuilder.buildObject();
		SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
				.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(statusCodeValue);
		status.setStatusCode(statusCode);
		logoutResponse.setStatus(status);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuerObject = issuerBuilder.buildObject();
		issuerObject.setValue(issuer);
		logoutResponse.setIssuer(issuerObject);
		logoutResponse.setInResponseTo(inResponseTo);

		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(logoutResponse);
		try {
			Node node = marshaller.marshall(logoutResponse);
			String msg = XMLHelper.prettyPrintXML(node);
			systemLogger.log(Level.FINEST, MODULE, sMethod, "Built message:\n" + Auxiliary.obfuscate(msg, Auxiliary.REGEX_PATTERNS));
		}
		catch (MarshallingException e) {
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception marhalling message: " + e.getMessage());
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		return logoutResponse;
	}

	/**
	 * Gets the node.
	 * 
	 * @param node
	 *            the node
	 * @param sSearch
	 *            the s search
	 * @return the node
	 */
	public static Node getNode(Node node, String sSearch)
	{
		Node nResult = null;
		NodeList nodeList = node.getChildNodes();
		for (int i = 0; i < nodeList.getLength() && nResult == null; i++) {
			if (sSearch.equals(nodeList.item(i).getLocalName()))
				nResult = nodeList.item(i);
			else
				nResult = getNode(nodeList.item(i), sSearch);
		}
		return nResult;
	}

	/**
	 * Helper method that marshalls the given message.
	 * 
	 * @param message
	 *            message the marshall and serialize
	 * @return marshalled message
	 * @throws MessageEncodingException
	 *             thrown if the give message can not be marshalled into its DOM representation
	 */
	public static Element marshallMessage(XMLObject message)
	throws MessageEncodingException
	{
		String sMethod = "marshallMessage";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		try {
			Marshaller marshaller = org.opensaml.xml.Configuration.getMarshallerFactory().getMarshaller(message);
			if (marshaller == null) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"Unable to marshall message, no marshaller registered for message object: "
								+ message.getElementQName());
			}
			Element messageElem = marshaller.marshall(message);
			// systemLogger.log(Level.INFO, MODULE, sMethod,
			// "Marshalled message into DOM:\n"+XMLHelper.nodeToString(messageElem));

			return messageElem;
		}
		catch (MarshallingException e) {
			throw new MessageEncodingException("Encountered error marshalling message into its DOM representation", e);
		}
	}

	/**
	 * Unmarshall element.
	 * 
	 * @param element
	 *            the element
	 * @return the xML object
	 * @throws MessageEncodingException
	 *             the message encoding exception
	 */
	public static XMLObject unmarshallElement(Element element)
	throws MessageEncodingException
	{
		String sMethod = "unmarshallMessage";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();

		try {
			Unmarshaller unmarshaller = org.opensaml.xml.Configuration.getUnmarshallerFactory()
					.getUnmarshaller(element);
			if (unmarshaller == null) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"Unable to unmarshall element, no unmarshaller registered for element object: " + element);
			}
			XMLObject xmlObject = unmarshaller.unmarshall(element);
			systemLogger.log(Level.INFO, MODULE, sMethod, "Unmarshalled element to: " + xmlObject.getClass());

			return xmlObject;
		}
		catch (UnmarshallingException e) {
			throw new MessageEncodingException(
					"Encountered error unmarshalling element into its object representation", e);
		}
	}

	// Wrapper class for transition from our "old" "trunk" jars to
	// release version of opensaml/2.1.0, openws/1.1.0, xmltooling/1.0.1
	// Catches old org.opensaml.xml.signature.KeyInfoHelper.getCertificate()
	/**
	 * Gets the certificate.
	 * 
	 * @param cert
	 *            the cert
	 * @return the certificate
	 * @throws CertificateException
	 *             the certificate exception
	 */
	public static java.security.cert.X509Certificate getCertificate(X509Certificate cert)
	throws CertificateException
	{
		return org.opensaml.xml.security.keyinfo.KeyInfoHelper.getCertificate(cert);
	}

	// Wrapper class for transition from our "old" "trunk" jars to
	// release version of opensaml/2.1.0, openws/1.1.0, xmltooling/1.0.1
	// Catches old HttpServletResponseAdapter(HttpServletResponse response) constructor
	/**
	 * Creates the http servlet response adapter.
	 * 
	 * @param response
	 *            the response
	 * @param remoteURL
	 *            the remote url
	 * @return the http servlet response adapter
	 */
	public static HttpServletResponseAdapter createHttpServletResponseAdapter(HttpServletResponse response,
			String remoteURL)
	{
		return new HttpServletResponseAdapter(response, remoteURL == null ? false :
							remoteURL.toLowerCase().startsWith("https"));
	}

	/**
	 * Set saml20 appropriate headers and send the HTTP SOAP response and close the stream.
	 * 
	 * @param servletResponse
	 *            , the servletresponse
	 * @param envelope
	 *            , the (soapenvelope) string to send
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void sendSOAPResponse(HttpServletRequest servletRequest, HttpServletResponse servletResponse, String envelope)
	throws IOException
	{
//		PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);
		PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse, "text/xml");	// SOAP is xml, compatibility prev. rev.
		pwOut.write(envelope);
		pwOut.write("\r\n\r\n\r\n");	// Backward compatibility
		pwOut.close();
	}

	//
	// Create a new HashMap based on an htSource
	// If include is true only include the attributes mentioned in arrAttr
	// Else take htSource, but exclude the attributes in arrAttr from the result.
	//
	/**
	 * Extract from hashtable.
	 * 
	 * @param arrAttr
	 *            the arr attr
	 * @param htSource
	 *            the ht source
	 * @param include
	 *            the include
	 * @return the hash map
	 */
	public static HashMap extractFromHashtable(String[] arrAttr, HashMap<String, Object> htSource, boolean include)
	{
		Object oValue;
		HashMap<String, Object> htResult = new HashMap<String, Object>();

		if (!include)
			htResult.putAll(htSource);
		for (int i = 0; i < arrAttr.length; i++) {
			oValue = htSource.get(arrAttr[i]);
			if (include && oValue != null)
				htResult.put(arrAttr[i], oValue);
			if (!include)
				htResult.remove(arrAttr[i]);
		}
		return htResult;
	}
	
	
	/**
	 * Map SAML statuscodes to aselect errorcodes.
	 * 
	 * @param samlstatuscode
	 *            the saml statuscode ( urn:oasis:names:tc:SAML:2.0:status:xxxx )
	 * 
	 * @return the aselect errorcode
	 */
	public static String mapStatus(String s)
	{
		String sMethod = "mapStatus";
		ASelectSystemLogger systemLogger = ASelectSystemLogger.getHandle();
		systemLogger.log(Level.FINER, MODULE, sMethod, "Mapping StatusCode: " + s);

		if (StatusCode.SUCCESS_URI.equals(s) ) {
			return Errors.ERROR_ASELECT_SUCCESS;
		} else if (StatusCode.AUTHN_FAILED_URI.equals(s) ) {
			return Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
		} else if (StatusCode.NO_AUTHN_CONTEXT_URI.equals(s) ) {
			return Errors.ERROR_ASELECT_AUTHSP_NO_AUTHN_CONTEXT;
		} else if (StatusCode.PARTIAL_LOGOUT_URI.equals(s) ) {
			return Errors.ERROR_ASELECT_AUTHSP_PARTIAL_LOGOUT;
		} else if (StatusCode.REQUEST_DENIED_URI.equals(s) ) {
			return Errors.ERROR_ASELECT_AUTHSP_REQUEST_DENIED;
		} else
		return (String) null;
		
	}
	
}
