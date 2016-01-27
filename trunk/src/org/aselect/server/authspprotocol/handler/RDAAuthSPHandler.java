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
 *
 * 20150501 - Adapted fromSMSAuthSPHandler, implementing RDA (Remote Document Authentication)
 * @author RH - www.anoigo.nl
 * 
 */
package org.aselect.server.authspprotocol.handler;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Random;
import java.util.logging.Level;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.aselect.server.authspprotocol.IAuthSPProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectAuthenticationLogger;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.session.SessionManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;


/**
 * The RDA AuthSP Handler. <br>
 * <br>
 * <b>Description:</b><br>
 * The RDA AuthSP Handler communicates with a remote (document) authenticator by redirecting the client. <br>
 * <b> Usually this would be a "second factor" authentication after a more traditional authentication e.g. username/password
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * <br>
 * <b>Protocol Description</b> <br>
 * <i><a name="outgoing">Outgoing request going to the RDA authenticator:</a></i> <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>as_url</td>
 * <td>Optional: A-Select Server url, not implemented</td>
 * </tr>
 * <tr>
 * <td>uid</td>
 * <td>A-Select Server user ID</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>signature of all parameters in the above sequence</td>
 * </tr>
 * </table>
 * <br>
 * <i><a name="incoming"> Incoming response, which is returned by the SMS AuthSP: </a></i> <br>
 * <table border="1" cellspacing="0" cellpadding="3">
 * <tr>
 * <td style="" bgcolor="#EEEEFF"><b>name</b></td>
 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
 * </tr>
 * <tr>
 * <td>rid</td>
 * <td>A-Select Server request id</td>
 * </tr>
 * <tr>
 * <td>result_code</td>
 * <td>AuthSP result code</td>
 * </tr>
 * <tr>
 * <td>a-select-server</td>
 * <td>A-Select Server ID</td>
 * </tr>
 * <tr>
 * <td>signature</td>
 * <td>Signature over the following data:
 * <ol>
 * <li>rid</li>
 * <li>The URL that was created in <code>computeAuthenticationRequest()</code>
 * <li>result_code</li>
 * <li>a-select-server</li>
 * </ol>
 * </td>
 * </tr>
 * </table>
 */
public class RDAAuthSPHandler extends AbstractAuthSPProtocolHandler implements IAuthSPProtocolHandler
{
	private final String MODULE = "RDAAuthSPHandler";
	private ASelectConfigManager _configManager;
	private SessionManager _sessionManager;
	private ASelectSystemLogger _systemLogger;
	private ASelectAuthenticationLogger _authenticationLogger;
	private String _sAuthsp;
	private String _sAuthspUrl;
	private String _sAuthspLocaRid;
	private String _sHMACInput;
	private String _sRDAQueryParmBSN;
	private String _sRDAQueryParmNonce;
	
	
	private int _iPBKDF2itert;
	private int _iPBKDF2SaltLenght;
	
	private boolean _bAddSignature;
	private String _SigAlg;
	private String _sReturnURL;
	

	private static final String ERROR_RDA_OK = "000";
	private static final String ERROR_RDA_INVALID_CONTEXT = "500";  // maybe verify some sort of context parameter and redirect in case of veification error
	private static final String ERROR_RDA_ACCESS_DENIED = "800";
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final String ENCODING_UTF8 = "UTF-8";
	private static final String ENCODING_ASCII = "ASCII";
	private static final String DEFAULT_HMAC_INPUT_OK = "ok";
	private static final String DEFAULT_RDAQUERYPARMBSN = "bsn";
	private static final String DEFAULT_RDAQUERYPARMNONCE = "nonce";
	private static final int DEFAULT_PBKDF2_ITERATIONS = 1000;
	private static final int DEFAULT_PBKDF2_SALTLENGTH = 32;
	private static final int DEFAULT_PBKDF2_KEYLENGTH = 256;	// bits
	private static final String DEFAULT_LOCALRID = "ctx";	// we use RDA ctx parameter for passing our RID
	private static final String DEFAULT_SIGNATUREALGORITHM = "SHA1withRSA";	//others would be SHA256withRSA, SHA384withRSA, SHA512withRSA
	
	
	private static final boolean DEFAULT_ADDSIGNATURE = true;

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#myRidName()
	 */
	public String getLocalRidName() { return _sAuthspLocaRid; }

	/* (non-Javadoc)
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#init(java.lang.Object, java.lang.Object)
	 */
	public void init(Object oAuthSPConfig, Object oAuthSPResource)
	throws ASelectAuthSPException
	{
		String sMethod = "init";
		_configManager = ASelectConfigManager.getHandle();
		_sessionManager = SessionManager.getHandle();
		_authenticationLogger = ASelectAuthenticationLogger.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
		try {
			try {
				_sAuthsp = _configManager.getParam(oAuthSPConfig, "id");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Parameter 'id' not found in RDA AuthSP configuration", eAC);
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Start initializing authsphandler: " + _sAuthsp);
			
			_sAuthspUrl = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "url", true/*mandatory*/);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using url : " +_sAuthsp);
			_sAuthspLocaRid = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "localrid", false);	// optional
			if (_sAuthspLocaRid == null) {
				_sAuthspLocaRid = DEFAULT_LOCALRID;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using localrid: " + _sAuthspLocaRid);
			_sHMACInput = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "hmacinput", false);	// optional
			if (_sHMACInput == null) {
				_sHMACInput = DEFAULT_HMAC_INPUT_OK;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using hmacinput: " + _sHMACInput);
			_sRDAQueryParmBSN = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "rdaqueryparmbsn", false);	// optional
			if (_sRDAQueryParmBSN == null) {
				_sRDAQueryParmBSN = DEFAULT_RDAQUERYPARMBSN;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using rdaqueryparmbsn: " + _sRDAQueryParmBSN);
			_sRDAQueryParmNonce = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "rdaqueryparmnonce", false);	// optional
			if (_sRDAQueryParmNonce == null) {
				_sRDAQueryParmNonce = DEFAULT_RDAQUERYPARMNONCE;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using rdaqueryparmnonce: " + _sRDAQueryParmNonce);
			String _sPBKDF2itert =  Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "pbkdf2iterations", false);	// optional
			_iPBKDF2itert = DEFAULT_PBKDF2_ITERATIONS;
			if ( _sPBKDF2itert != null ) {
				_iPBKDF2itert = Integer.parseInt(_sPBKDF2itert);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using pbkdf2iterations: " + _iPBKDF2itert);
			String _sPBKDF2SaltLenght = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "pbkdf2saltlength", false);	// optional
			_iPBKDF2SaltLenght = DEFAULT_PBKDF2_SALTLENGTH;
			if ( _sPBKDF2SaltLenght != null ) {
				_iPBKDF2SaltLenght = Integer.parseInt(_sPBKDF2SaltLenght);
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using pbkdf2saltlength: " + _iPBKDF2SaltLenght);

			String _sAddSignature = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "addsignature", false);	// optional
			if ( _sAddSignature != null ) {
				_bAddSignature = Boolean.parseBoolean(_sAddSignature);
			} else {
				_bAddSignature = DEFAULT_ADDSIGNATURE;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using addsignature: " + _bAddSignature);

			_SigAlg = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "signaturealgortihm", false);	// optional
			if ( _SigAlg == null ) {
				_SigAlg = DEFAULT_SIGNATUREALGORITHM;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using signaturealgortihm: " + _SigAlg);

			_sReturnURL = Utils.getSimpleParam(_configManager, _systemLogger, oAuthSPResource, "returnurl", false);	// optional, if null, no returnurl will be included in the request
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Using returnurl: " + _sReturnURL);

			
		}
		catch (ASelectAuthSPException eAA) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", eAA);
			throw eAA;
		}
		catch (ASelectException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to configuration error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initialisation failed due to internal error", e);
			throw new ASelectAuthSPException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Creates the authentication request URL. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method creates a hashtable with the follwing contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if creating the authentication request URL fails</td>
	 * </tr>
	 * <tr>
	 * <td>redirect_url</td>
	 * <td>The URL to the AuthSP including the protocol parameters as specified if the <a href="#outgoing">class
	 * description</a>.</td>
	 * </tr>
	 * </table>
	 * 
	 * @param sRid
	 *            the s rid
	 * @return the hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#computeAuthenticationRequest(java.lang.String)
	 */
	public HashMap computeAuthenticationRequest(String sRid, HashMap htSessionContext)
	{
		String sMethod = "computeAuthenticationRequest";
		StringBuffer sbBuffer = null;
		HashMap htResponse = new HashMap();
		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "sRid=" + sRid);

		try {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Context=" + htSessionContext);
			if (htSessionContext == null) {
				sbBuffer = new StringBuffer("Could not fetch session context for rid='");
				sbBuffer.append(sRid).append("'.");
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			}

			// Get userid from htSessionContext, either from allowed_user_authsps or from sel_uid or user_id, still to be decided after POC
			// For now we take user_id
			String sUserId = (String) htSessionContext.get("user_id");	// get userid from session or better from tgt, but we must get the tgt then

//			String sCF = (String)htSessionContext.get("rda_correction_facility");	// not yet implemented, might be needed
			
			String querystring1 = _sRDAQueryParmBSN+"=" + sUserId;
			// create salt
			byte[] salt = generateSalt(_iPBKDF2SaltLenght);	

			BASE64Encoder encoder = new BASE64Encoder();
			String nonce = encoder.encode(salt);	// nonce will be included (encrypted) to RDA
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "nonce generated: " + nonce);
			
			// generate hashkey
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Generating hash with saltlength/iterations: " +_iPBKDF2SaltLenght + "/" + _iPBKDF2itert);
			byte[] hash = PBKDF2(querystring1.toCharArray(), salt, _iPBKDF2itert);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "hash generated: " + Arrays.toString(hash));
			
			htSessionContext.put("rda_hash", hash);	// save the hash for verification of the result from rda controller
			_sessionManager.setUpdateSession(htSessionContext, _systemLogger);
			
			String querystring2 = querystring1 + "&" + _sRDAQueryParmNonce + "=" + nonce;	// nonce must be last parameter
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "encrypting query string: " + querystring2);	// RH, 20160127, o

			byte[] baCipher = encryptRSA(querystring2, ENCODING_UTF8);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "encrypted query parameter q before UrlTokenEncode as bytes: " + asString(baCipher));
			String sCipher = UrlTokenEncode(baCipher);	// does base64 + fancyURLEncode


			// Build the AuthSP url
			StringBuffer sbRedirect = new StringBuffer( _sAuthspUrl); 
			sbRedirect.append("?q=").append(sCipher);
			sbRedirect.append("&ctx=").append(sRid);	// we put our rid in the ctx parameter

			// set the (optional) return url
			byte[] urlArray = new byte[0];
			if (_sReturnURL != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "adding returnurl: " + _sReturnURL);
				urlArray = _sReturnURL.getBytes(ENCODING_UTF8);
				sbRedirect.append("&returnurl=").append(UrlTokenEncode(urlArray));
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "query parameter returnurl before UrlTokenEncode as bytes: " + asString(urlArray));
			}
			
			// now handle the signature
			if (_bAddSignature) {
				byte[] rawData = concat(baCipher, urlArray);
				byte[] rawSIgnature = CryptoEngine.getHandle().generateSignature(null /* use default private key */, rawData, _SigAlg /*  forcedSignatureAlgoritm */);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "query parameter signature before UrlTokenEncode as bytes: " + asString(rawSIgnature));
				String sSignature = UrlTokenEncode(rawSIgnature);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "adding signature: " + sSignature + " , using algorithm:" + _SigAlg);
				sbRedirect.append("&signature=").append(sSignature);
			}
			
			htResponse.put("redirect_url", sbRedirect.toString());
			htResponse.put("result", Errors.ERROR_ASELECT_SUCCESS);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "redirect_url:" + sbRedirect.toString());
		}
		catch (ASelectAuthSPException eAA) {
			htResponse.put("result", eAA.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not compute authentication request due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
		}
		return htResponse;
	}

	/**
	 * Verifies the response from the AuthSP. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies the response from the AuthSP. The response parameters are placed in
	 * <code>htAuthspResponse</code> and are described in the <a href="#incoming">class description</a>. <br>
	 * <br>
	 * This method creates a hashtable with the following contents:
	 * <table border="1" cellspacing="0" cellpadding="3">
	 * <tr>
	 * <td style="" bgcolor="#EEEEFF"><b>key</b></td>
	 * <td style="" bgcolor="#EEEEFF"><b>value</b></td>
	 * </tr>
	 * <tr>
	 * <td>result</td>
	 * <td>
	 * {@link Errors#ERROR_ASELECT_SUCCESS} or an error code if the authentication response was invalid or the user
	 * was not authenticated.</td>
	 * </tr>
	 * <tr>
	 * <td>rid</td>
	 * <td>The A-Select request identifier of this authentication.</td>
	 * </tr>
	 * </table>
	 * 
	 * @param htAuthspResponse
	 *            the authsp response
	 * @param htSessionContext
	 *            the session context, must be available
	 * @return the result hash map
	 * @see org.aselect.server.authspprotocol.IAuthSPProtocolHandler#verifyAuthenticationResponse(java.util.HashMap)
	 */

	public HashMap verifyAuthenticationResponse(HashMap htAuthspResponse, HashMap htSessionContext)
	{
		String sMethod = "verifyAuthenticationResponse";
		StringBuffer sbBuffer = null;
		HashMap htResponse = new HashMap();

		htResponse.put("result", Errors.ERROR_ASELECT_INTERNAL_ERROR);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "htAuthspRespone=" + htAuthspResponse);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Context=" + htSessionContext);
		try {
			String sRid = (String) htAuthspResponse.get(getLocalRidName());
			String sResultCode = null;	// We wll not have a result code just yet. Used for testing
			String sRDAResult = (String) htAuthspResponse.get("rdaresult");	// this is the answer from the RDA controller

			if (sRid == null || sRDAResult == null ) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Incorrect AuthSP response: one or more parameters missing.");
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			byte[] baRDAResult = UrlTokenDecode(sRDAResult);		// must have a proper value
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "decoded rdaresult="+Arrays.toString(baRDAResult));
			
			String sUserId = (String) htSessionContext.get("user_id");
			if (sUserId == null)
				sUserId = (String) htSessionContext.get("sel_uid");
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sUserId="+sUserId);	// RH, 20160127, o
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sUserId="+Auxiliary.obfuscate(sUserId));	// RH, 20160127, n
			
			String sOrg = (String) htSessionContext.get("organization");

			// now verify the result
			byte[] hash = (byte[]) htSessionContext.get("rda_hash");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved rda_hash="+Arrays.toString(hash));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "used for verification HMACInput="+_sHMACInput);
			
			byte[] resultOKBytes = null;
			byte[] hresult = null;
			try {
				resultOKBytes = _sHMACInput.getBytes("UTF-8");
				hresult = calculateRawRFC2104HMAC(resultOKBytes, hash);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, " calculated HMAC="+Arrays.toString(hresult));
			}
			catch (UnsupportedEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}
			catch (SignatureException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, e.getMessage());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			
			sResultCode = verifyRDAresult(baRDAResult, hresult);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "verifyRDAresult="+sResultCode);
			
			// Log authentication
			if (ERROR_RDA_OK.equalsIgnoreCase(sResultCode)) {
				_authenticationLogger.log(new Object[] {
					MODULE, Auxiliary.obfuscate(sUserId), htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
					"granted"
				});
			} else {
				_authenticationLogger.log(new Object[] {
						MODULE, Auxiliary.obfuscate(sUserId), htAuthspResponse.get("client_ip"), sOrg, (String) htSessionContext.get("app_id"),
						"denied", sResultCode
					});
			}
			
			// Do not throw exceptions only for real errors still to determine which is which
			if (!sResultCode.equalsIgnoreCase(ERROR_RDA_OK) && !sResultCode.equalsIgnoreCase(ERROR_RDA_INVALID_CONTEXT)
					&& !sResultCode.equalsIgnoreCase(ERROR_RDA_ACCESS_DENIED)) {
				StringBuffer sbError = new StringBuffer("Invalid returned errorcode: ").append(sResultCode);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectAuthSPException(Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
			}

			htResponse.put("authsp_type", "rda30");
			
			htResponse.put("result", sResultCode.equalsIgnoreCase(ERROR_RDA_OK)?
							Errors.ERROR_ASELECT_SUCCESS: Errors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "result=" + sResultCode);
		}
		catch (ASelectAuthSPException eAA) {
			htResponse.put("result", eAA.getMessage());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not verify authentication response due to internal error", e);
			htResponse.put("result", Errors.ERROR_ASELECT_AUTHSP_INVALID_RESPONSE);
		}
		return htResponse;
	}
	
	
	public static byte[] generateSalt(int length) {
		byte[] salt = new byte[length];
		CryptoEngine.nextRandomBytes(salt);
		return salt;
	}
	
	/**
	 * RSA Encrypt with public key
	 * @param data
	 * @param key
	 * @param enc
	 * @return
	 */
	private byte[] encryptRSA( String data, String enc) {
		String sMethod = "encryptRSA";
		byte[] baCipher = null;
//		String sCipher = null;
		if (enc == null) {
			enc = "UTF-8";
		}
		// Do the cipher calculation here
		CryptoEngine c = CryptoEngine.getHandle();
		// for now we use alias = _sAuthsp, maybe get this from config
		try {
			// alternatives could be "RSA/None/NoPadding" or "RSA/ECB/PKCS1Padding" or "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
			baCipher = c.RSAEncrypt(_sAuthsp, data.getBytes(enc), "RSA/ECB/PKCS1Padding");// use PKCS1Padding padding method RSA
//			baCipher = c.RSAEncrypt(_sAuthsp, data.getBytes(enc), "RSA");// use default method RSA
//			baCipher = c.RSAEncrypt(_sAuthsp, data.getBytes(enc), "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");// use OAEP padding method RSA
		}
		catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "encodingexception for charset: " + enc);
		}
		return baCipher;
	}
	
	
	public static byte[] calculateRawRFC2104HMAC(byte[] data, byte[] key)
	throws java.security.SignatureException
	{
		return calculateRawRFC2104HMAC(data, key, null);
	}

	
	/**
	* Computes raw (byte[]) RFC 2104-compliant HMAC signature.
	* * @param data
	* The raw (byte[]) data to be signed.
	* @param key
	* The raw signing key byte[].
	* @return
	* The raw (byte[] RFC 2104-compliant HMAC signature.
	* @throws
	* java.security.SignatureException when signature generation fails
	*/
	public static byte[] calculateRawRFC2104HMAC(byte[] data, byte[] key, String alg)
	throws java.security.SignatureException
	{
	byte[] result;
	if ( alg == null ) {
		alg = HMAC_SHA256_ALGORITHM;	// SHA256 used as default
	}
	try {

		// get an hmac_sha1/sha256 key from the raw key bytes
		SecretKeySpec signingKey = new SecretKeySpec(key, alg);	// might not work with this alg, then will throw exception
	
		// get an hmac_sha1/sha256 Mac instance and initialize with the signing key
		Mac mac = Mac.getInstance(alg);
		mac.init(signingKey);
	
		// compute the hmac on input data bytes
		byte[] rawHmac = mac.doFinal(data);
	
		result = rawHmac;

	} catch (Exception e) {
		throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
	}
	return result;
	}

	
	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return PBKDF2(password, salt, noIterations, DEFAULT_PBKDF2_KEYLENGTH);
	}

	/**
	 * 		Rfc2898DeriveBytes 
	 * @param data
	 * @param password
	 * @param salt
	 * @param noIterations
	 * @param keyLength, bits
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		  String ALGORITHM = "PBKDF2WithHmacSHA1";
//		  String ALGORITHM = "PBKDF2WithHmacSHA256";	// unfortunately we need java8 for this
		  
		  byte[] hash = null;
		  
	      PBEKeySpec spec = new PBEKeySpec(password, salt, noIterations, keyLength);
	      SecretKeyFactory factory;
	      factory = SecretKeyFactory.getInstance(ALGORITHM);
	      hash =  factory.generateSecret(spec).getEncoded();
	      return hash;
		}
	
	
	private static String verifyRDAresult(byte[] baRDAResult, byte[] hresult) {
		String result = ERROR_RDA_ACCESS_DENIED;
		
		// Do the RDA result verification here by byte to byte comparison
		boolean eq = java.util.Arrays.equals(baRDAResult, hresult);
		if ( eq )  {
			result =  ERROR_RDA_OK;
		} else {
			result =  ERROR_RDA_ACCESS_DENIED;
		}
		return result;
	}
	
	
	private static String UrlTokenEncode(byte[] cipher) {
		String token = null;
		String sCipher = null;
		if (cipher == null) {
			return null;
		}
		if (cipher.length < 1) {
			return "";
		}
		// Step 1: Do a Base64 encoding
		BASE64Encoder encoder = new BASE64Encoder();
		sCipher = encoder.encode(cipher);
		if (sCipher == null) {
			return null;
		}
		token = fancyURLEncode(sCipher);
		return token;
	}

	/**
	 * @param sCipher
	 * @return
	 */
	public static String fancyURLEncode(String sCipher)
	{
		String token;
		// now do the fancy footwork
		// Step 2: Find how many padding chars are present in the end
		int lastNonPaddingPos = sCipher.length();
		for (int endPos = sCipher.length(); endPos > 0; endPos--) {
            if (sCipher.charAt(endPos - 1) != '=') // Found a non-padding char!
            {
            	lastNonPaddingPos = endPos;
                break; // Stop here
            }
        }
		
        // Step 3: Create char array to store all non-padding chars,
        //      plus a char to indicate how many padding chars are needed
        char[] base64Chars = new char[lastNonPaddingPos + 1];
        base64Chars[lastNonPaddingPos] = (char) ( (int)('0') + (sCipher.length() - lastNonPaddingPos) ); // Store a char at the end, to indicate how many padding chars are needed
        for (int iter = 0; iter < lastNonPaddingPos; iter++) {
            char c = sCipher.charAt(iter);
            switch (c) {
                case '+':
                    base64Chars[iter] = '-';
                    break;
                case '/':
                    base64Chars[iter] = '_';
                    break;
                case '=':
                    // Should not happen
                    base64Chars[iter] = c;
                    break;
                default:
                    base64Chars[iter] = c;
                    break;
            }
        }
        
        token = new String(base64Chars);
		return token;
	}

	
	private static byte[] UrlTokenDecode(String input) {
		   if (input == null)
		        return new byte[0];

		    int len = input.length(); 
		    if (len < 1)
		        return new byte[0]; 

		    // 	now reverse the fancy footwork
		    // Step 1: Find the number of padding chars to append to this string. 
		    //         The number of padding chars to append is stored in the last char of the string.
		    int numPadChars = (int)input.charAt(len - 1) - (int)'0';
		        if (numPadChars < 0 || numPadChars > 10)
		            return null; 

		    // Step 2: Create array to store the chars (not including the last char)
		    //          and the padding chars 
		    char[] base64Chars = new char[len - 1 + numPadChars];

		    // Step 3: Copy in the chars. Transform the "-" to "+", and "*" to "/"
		    for (int iter = 0; iter < len - 1; iter++) { 
		        char c = input.charAt(iter); 

		        switch (c) { 
		            case '-':
		                base64Chars[iter] = '+';
		                    break;

		                case '_':
		                base64Chars[iter] = '/'; 
		                break; 

		            default: 
		                base64Chars[iter] = c;
		                break;
		        }
		    } 

		    // Step 4: Add padding chars 
		    for (int iter = len - 1; iter < base64Chars.length; iter++) {
		        base64Chars[iter] = '='; 
		    }

		    // Do the actual conversion
		    String assembledString = String.copyValueOf(base64Chars);
			BASE64Decoder decoder = new BASE64Decoder();
			byte[] baCipher = decoder.decodeBuffer(assembledString);
		    return baCipher;
	}

	
	private static byte[] concat(byte[]...arrays)
	{
	    // Determine the length of the result array
	    int totalLength = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        totalLength += arrays[i].length;
	    }

	    // create the result array
	    byte[] result = new byte[totalLength];

	    // copy the source arrays into the result array
	    int currentIndex = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
	        currentIndex += arrays[i].length;
	    }

	    return result;
	}
	
	private static String asString(byte[] data) {
		StringBuffer buf = new StringBuffer();
		Formatter f = new Formatter(buf);
		for (byte b : data) {
			   f.format("%02X", b);
		}
		return buf.toString();
		
	}
	
	
	public static void main(String[] args)	// For TESTING only
	{
//		byte[] token = { 1,2, 3, 4, 5, 6, 7, 8, 9, 10,
//				11, 12, 13, 14, 15, 16, 17, 18 ,19, 20,
//				21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
//				31, 32 };

		byte[] token = { 127, 126, 125, 124, 123, 122, 121, 120, 119, 118,
				117, 116, 115, 114, 113, 112, 111, 110 ,109, 108,
				107, 106, 105, 104, 103, 102, 101, 100, 99, 98,
				97, 96 };

		System.out.format("The input\n");

		for (byte b : token) {
			   System.out.format("0x%02X ", b);
		}
		
		
		System.out.format("\n");
		System.out.println("asString:" + asString(token));
		String sEncoded = UrlTokenEncode(token);
		System.out.format("The encoded token: %s ", sEncoded);
		byte[] baDecoded = UrlTokenDecode(sEncoded);
		System.out.format("\nThe output\n");
		for (byte b : baDecoded) {
			   System.out.format("0x%02X ", b);
		}
		System.out.format("\n");
		System.out.format("The input should be equal to the output\n");
		String eq = verifyRDAresult(baDecoded, token);
		System.out.format("The input is " +( ERROR_RDA_OK.equals(eq) ? "" : "NOT " ) + "equal to the output");

		String base64Token =  "+EglStgobPjGXNJtX+VT4T+VAIUDwSF6uEEYAnZ1STQ=";
		
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] salt = decoder.decodeBuffer(base64Token);

		System.out.format("\nThe salt\n");
		for (byte b : salt) {
			   System.out.format("%02X", b);
		}

		
		BASE64Encoder encoder = new BASE64Encoder();
		String nonce = encoder.encode(salt);	// nonce will be send (encrypted) to RDA
		System.out.format("\nnonce: %s ", nonce);
		
		// generate hashkey
		byte[] hash = null;
		try {
			hash = PBKDF2("bsn=900029389" .toCharArray(), salt, 1000);
		}
		catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		}	// does not work, PBKDF2WithHmacSHA256 SecretKeyFactory not available, only java8
//		byte[] hash = PBKDF2("bsn=" .toCharArray(), salt, 1000);	// does not work, PBKDF2WithHmacSHA256 SecretKeyFactory not available, only java8
		System.out.format("\nhash generated: %s ", Arrays.toString(hash));

		System.out.format("\nThe hash\n");
		for (byte b : hash) {
			   System.out.format("%02X", b);
		}

		String sData = "NOK";
//		String sData = "";
		byte[] data;
		try {
			data = sData.getBytes("UTF-8");
			System.out.format("\nThe data\n");
			for (byte b : data) {
				   System.out.format("%02X", b);
			}
			byte[] rdaresult = calculateRawRFC2104HMAC(data, hash);	// use default sha256
//			byte[] rdaresult = calculateRawRFC2104HMAC(data, hash, HMAC_SHA1_ALGORITHM);	// use sha1
			
			System.out.format("\nrdaresult generated: %s ", Arrays.toString(rdaresult));
			System.out.format("\nThe rdaresult\n");
			for (byte b : rdaresult) {
				   System.out.format("%02X", b);
			}
			System.out.format("\nrdaresult as token: %s ", UrlTokenEncode(rdaresult));
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		catch (SignatureException e) {
			e.printStackTrace();
		}
		 

	}
}
