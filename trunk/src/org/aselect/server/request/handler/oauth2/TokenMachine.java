package org.aselect.server.request.handler.oauth2;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import org.aselect.server.crypto.CryptoEngine;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

/**
 * Generates standard oauth2 and openid tokens
 * 
 * @author remy
 *
 */
public class TokenMachine implements ITokenMachine {
	
	HashMap<String, Object> return_parameters = null;
	int return_status = 400; // default


	public TokenMachine() {
		return_parameters = new HashMap<String, Object>();
	}
	
	public Object setParameter (String key, Object value) {
		return return_parameters.put(key, value);
	}

	public Object getParameter (String key) {
		return return_parameters.get(key);
	}

	public void setStatus (int status) {
		return_status = status;
	}

	public int getStatus () {
		return return_status;
	}
	
	public String toJSONString() {
		return ((JSONObject) JSONSerializer.toJSON( return_parameters )).toString(0); 
	}

	/**
	 * @param extractedAselect_credentials
	 * @return created access_token
	 * @throws UnsupportedEncodingException
	 */
	public String createAccessToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk) throws UnsupportedEncodingException,  JoseException {
		// Unfortunately access_token should not contain "*", see rfc6750, par. 2.1 Bearer token
		// our extractedAselect_credentials may contain one or more "*"
		// We must fix that, so we do

		String access_token;
		BASE64Encoder b64enc = new BASE64Encoder();
		access_token = b64enc.encode(extractedAselect_credentials.getBytes("UTF-8"));
		return access_token;
	}

	/**
	 * @return generated authorization_code
	 */
	public String generateAuthorizationCode() {
		// generate authorization_code
		byte[] baRandomBytes = new byte[32];

		CryptoEngine.nextRandomBytes(baRandomBytes);
		String generated_authorization_code = Utils.byteArrayToHexString(baRandomBytes);
		return generated_authorization_code;
	}

	/**
	 * @return generated createRefreshToken
	 */
	public String createRefreshToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk) throws UnsupportedEncodingException, JoseException {
		// Unfortunately access_token should not contain "*", see rfc6750, par. 2.1 Bearer token
		// our extractedAselect_credentials may contain one or more "*"
		// We must fix that, so we do

		String refresh_token;
		BASE64Encoder b64enc = new BASE64Encoder();
		refresh_token = b64enc.encode(extractedAselect_credentials.getBytes("UTF-8"));
		return refresh_token;
		
	}

	public String createIDToken(HashMap attributes, String subject, String issuer, String audience, String nonce, String appidacr, 
			PrivateKey pk, String code) throws UnsupportedEncodingException, JoseException {	// RH, 20181114, n
	
		// JSON Web Tokens (JWTs) and public key cryptography, RSA 256
	    JwtClaims claims = new JwtClaims();
	//        claims.setExpirationTimeMinutesInTheFuture(1);
	    claims.setSubject(subject);
	    claims.setIssuer(issuer);
	    claims.setAudience(audience);
	    claims.setExpirationTimeMinutesInTheFuture(900 / 60);
	    claims.setIssuedAtToNow();
	    claims.setNotBeforeMinutesInThePast(0);
	    claims.setStringClaim("nonce", nonce);
	    claims.setStringClaim("ver", "1.0");
	    claims.setStringClaim("appidacr", appidacr);
	    String c_hash = null;
	    if (code != null) {
	//       	calculate the c_hash over the code, 3.3.2.11. ID Token
	    	// AlgorithmIdentifiers.RSA_USING_SHA256 so SHA-256
	    	String algorithm = "SHA-256";
	    	String charset = "US-ASCII";
			MessageDigest md;
			try {
				md = MessageDigest.getInstance(algorithm);
		        md.update(code.getBytes(charset));
	//		        byte[] b64data = Base64.encodeBase64URLSafe(byteData);	// if we want to use apache
		        // take left-most ( first 128 bits for SHA-256 )
		        byte byteData[] = Arrays.copyOf(md.digest(), 16);
		        c_hash = Base64.getUrlEncoder()
	            .withoutPadding()
	            .encodeToString(byteData);
			}
			catch (NoSuchAlgorithmException e) {
				c_hash = null;
			}
			catch (UnsupportedEncodingException e) {
				c_hash = null;
			}
	    }
	    if (c_hash != null) {
	        claims.setStringClaim("c_hash", c_hash);        	
	    }
    
	    Set<String> attrNames = (Set<String>)(attributes.keySet());
	    for (String attrName : attrNames) {
	    	Object attrValue = attributes.get(attrName);
	    	if (attrValue instanceof Vector) {	// depricated but we still use the Vector type
	    		claims.setStringListClaim(attrName, (Vector)attrValue);
	    	} else {	// should be string
	//    		claims.setStringClaim(attrName, (String)attrValue);	// also allow for other types
	    		claims.setClaim(attrName, attrValue);
	    	}
	    }
	    
	//        Key key = new HmacKey(secret.getBytes("UTF-8"));
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setPayload(claims.toJson());
	//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	//        jws.setKey(key);
	    // Sign using the private key
	//        jws.setKey(ASelectConfigManager.getHandle().getDefaultPrivateKey());	// RH, 20181114, o
	    jws.setKey(pk);	// RH, 20181114, n
	
	    return jws.getCompactSerialization();
	}

}
