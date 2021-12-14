package org.aselect.server.request.handler.oauth2.jwt;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

public class TokenMachine extends org.aselect.server.request.handler.oauth2.TokenMachine {

	public TokenMachine() {
		super();
	}
	
	@Override
	public String createAccessToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk)
			throws UnsupportedEncodingException, JoseException {

		// JSON Web Tokens (JWTs) and public key cryptography, RSA 256
	    JwtClaims claims = new JwtClaims();
	//    claims.setExpirationTimeMinutesInTheFuture(1);
	//    claims.setSubject(subject);
	    claims.setIssuer((String)getParameter("issuer"));	//	RH, 20200214, n
	//    claims.setAudience(audience);
	    claims.setExpirationTimeMinutesInTheFuture(60);	// still to make variable
	    claims.setIssuedAtToNow();
	    NumericDate exptime = NumericDate.now();
	    exptime.addSeconds(3600);
	//    claims.setExpirationTime(expirationTime);	// still to find out what to put here
	    claims.setExpirationTime(exptime);	// still to find out what to put here
	    claims.setStringClaim("ver", "1.0");
	    if (extractedAselect_credentials != null) {
	    	claims.setStringClaim("aselect_credentials", extractedAselect_credentials);
	    }
	    claims.setClaim("scope", (String)getParameter("scope"));	//	RH, 20200214, n
	    claims.setClaim("client_id", (String)getParameter("client_id"));	//	RH, 20200214, n
	    claims.setClaim("appidacr", (String)getParameter("appidacr"));	//	RH, 20200214, n
	    if (attributes != null) {
		    Set<String> attrNames = (Set<String>)(attributes.keySet());
		    for (String attrName : attrNames) {
		    	Object attrValue = attributes.get(attrName);
		    	if (attrValue instanceof Vector) {	// depricated but we still use the Vector type
		    		claims.setStringListClaim(attrName, (Vector)attrValue);
		    	} else {	// might be other type
		    		claims.setClaim(attrName, attrValue);
		    	}
		    }
		}
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setPayload(claims.toJson());
	//    Key key = new HmacKey(secret.getBytes("UTF-8"));
	//    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	    // Sign using the private key
	    jws.setKey(pk);
	    // RH, 20211014, sn
	    if (getKid() != null) {
		    jws.setKeyIdHeaderValue(getKid());
	    }
	    // RH, 20211014, sn

	    return jws.getCompactSerialization();
	}

	/**
	 * @return generated createRefreshToken
	 */
	@Override
	public String createRefreshToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk) throws UnsupportedEncodingException, JoseException {
		// JSON Web Tokens (JWTs) and public key cryptography, RSA 256
	    JwtClaims claims = new JwtClaims();
//	    claims.setExpirationTimeMinutesInTheFuture(1);
//	    claims.setSubject(subject);
	    claims.setIssuer((String)getParameter("issuer"));	//	RH, 20200214, n
//	    claims.setAudience(audience);
	    // either use setExpirationTimeMinutesInTheFuture or setExpirationTime, both set de "exp"
	    claims.setExpirationTimeMinutesInTheFuture(60);	// still to make variable
	    claims.setIssuedAtToNow();
	    NumericDate exptime = NumericDate.now();
	    exptime.addSeconds(3600);
//	    claims.setExpirationTime(expirationTime);	// still to find out what to put here
	    claims.setExpirationTime(exptime);	// still to find out what to put here
	    claims.setStringClaim("ver", "1.0");
	    if (extractedAselect_credentials != null) {
	    	claims.setStringClaim("aselect_credentials", extractedAselect_credentials);
	    }
	    claims.setClaim("scope", (String)getParameter("scope"));	//	RH, 20200214, n
	    claims.setClaim("client_id", (String)getParameter("client_id"));	//	RH, 20200214, n
	    claims.setClaim("appidacr", (String)getParameter("appidacr"));	//	RH, 20200214, n

//	    if (attributes != null) {
//		    Set<String> attrNames = (Set<String>)(attributes.keySet());
//		    for (String attrName : attrNames) {
//		    	Object attrValue = attributes.get(attrName);
//		    	if (attrValue instanceof Vector) {	// depricated but we still use the Vector type
//		    		claims.setStringListClaim(attrName, (Vector)attrValue);
//		    	} else {	// might be other type
//		    		claims.setClaim(attrName, attrValue);
//		    	}
//		    }
//		}
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setPayload(claims.toJson());
//	    Key key = new HmacKey(secret.getBytes("UTF-8"));
//	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	    // Sign using the private key
	    jws.setKey(pk);
	    // RH, 20211014, sn
	    if (getKid() != null) {
		    jws.setKeyIdHeaderValue(getKid());
	    }
	    // RH, 20211014, sn

	    return jws.getCompactSerialization();
	}

	@Override
	public String createIDToken(HashMap attributes, String subject, String issuer, String audience, String nonce, String appidacr, 
			PrivateKey pk, String code) throws UnsupportedEncodingException, JoseException {
	
		// JSON Web Tokens (JWTs) and public key cryptography, RSA 256
	    JwtClaims claims = new JwtClaims();
	//        claims.setExpirationTimeMinutesInTheFuture(1);
	    claims.setSubject((String)(attributes.get("subject")));	// required, should be parameter	// RH, 20200131, o
	    claims.setIssuer(issuer);	// required
	    claims.setAudience(audience);	// required
	    claims.setExpirationTimeMinutesInTheFuture(3600);	// required	// still to make variable
	    claims.setIssuedAtToNow();	// required
	//    claims.setNotBeforeMinutesInThePast(0);
	    claims.setNotBeforeMinutesInThePast(0);

	    if (nonce != null) {
	    	claims.setStringClaim("nonce", nonce);
	    }
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
	//	        byte[] b64data = Base64.encodeBase64URLSafe(byteData);	// if we want to use apache
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
	    
	    if (attributes != null) {
		    Set<String> attrNames = (Set<String>)(attributes.keySet());
		    for (String attrName : attrNames) {
		    	Object attrValue = attributes.get(attrName);
		    	if (attrValue instanceof Vector) {	// depricated but we still use the Vector type
		    		claims.setStringListClaim(attrName, (Vector)attrValue);
		    	} else {	// should be string
	//	    		claims.setStringClaim(attrName, (String)attrValue);
		       		claims.setClaim(attrName, attrValue);
		       	 
		    	}
		    }
	    }
	//    Key key = new HmacKey(secret.getBytes("UTF-8"));
	
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setPayload(claims.toJson());
	//    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
	//    jws.setKey(key);
	    // Sign using the private key
	//    jws.setKey(ASelectConfigManager.getHandle().getDefaultPrivateKey());	// RH, 20181114, o
	    jws.setKey(pk);	// RH, 20181114, n
	    // RH, 20211014, sn
	    if (getKid() != null) {
		    jws.setKeyIdHeaderValue(getKid());
	    }
	    // RH, 20211014, sn
	
	    return jws.getCompactSerialization();
	}

}
