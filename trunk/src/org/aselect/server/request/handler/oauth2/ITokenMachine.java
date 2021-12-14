package org.aselect.server.request.handler.oauth2;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.util.HashMap;

import org.jose4j.lang.JoseException;

public interface ITokenMachine {

	public String createAccessToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk) throws UnsupportedEncodingException, JoseException;
	
	public String generateAuthorizationCode();
	public String createRefreshToken(String extractedAselect_credentials, HashMap attributes, PrivateKey pk) throws UnsupportedEncodingException, JoseException;
	
	public String createIDToken(HashMap attributes, String subject, String issuer, String audience, String nonce, String appidacr, 
			PrivateKey pk, String code) throws UnsupportedEncodingException, JoseException;
	
	public Object setParameter (String key, Object value);
	public Object getParameter (String key);
	public void setStatus (int status);
	public int getStatus ();
	public String getKid();
	public void setKid(String kid);

	
	public String toJSONString();
}
