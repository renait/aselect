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
package org.aselect.server.request.handler.oauth2.jwt;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.request.handler.oauth2.ITokenMachine;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

public class OPEndpointHandler extends org.aselect.server.request.handler.oauth2.OPEndpointHandler {

	private final static String MODULE = "jwt.OPEndpointHandler";

	@Override
	protected ITokenMachine createTokenMachine() {
		return  new TokenMachine();
	}


	@Override
	protected String extractAccessToken(String jwt_access_token) {
//		String sMethod = "extractCredentials";	// RH, 20200915, o
		String sMethod = "extractAccessToken";	// RH, 20200915, n
		// we must decode the jwt token
		
		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
				.setSkipAllValidators()
	            .setDisableRequireSignature()
	            .setSkipSignatureVerification()
	            .build();	// no checking yet
		
		
        JwtClaims jwtClaims = null;
        String aselect_credentials = null;
		try {
			jwtClaims = jwtConsumer.processToClaims(jwt_access_token);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "JWT validation succeeded! " + jwtClaims);
			aselect_credentials = jwtClaims.getStringClaimValue("aselect_credentials");
		} catch (InvalidJwtException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "JWT validation failed! " + e.getMessage());
		} catch (MalformedClaimException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "JWT MalformedClaim! " + e.getMessage());
		}

		BASE64Encoder b64enc = new BASE64Encoder();
		String access_token = null;
		try {
			access_token = b64enc.encode(aselect_credentials.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unsupported encoding exception, should not happen");

		}

		return access_token;
	}

	/**
	 * @param sMethod
	 * @param code
	 * @param return_parameters
	 * @param history
	 * @param access_token
	 * @param tgt
	 * @return HTTP return code
	 * @throws ASelectStorageException
	 */
	@Override
	protected int supplyReturnParameters(String code, ITokenMachine tokenMachine,
			SamlHistoryManager history, String access_token, HashMap tgt, String appidacr) throws ASelectStorageException {
		
		String sMethod = "supplyReturnParameters";
		int return_status;

//		String new_access_token = null;

		HashMap claims = new HashMap();
		String saved_redirect_uri = (String)tgt.get("oauthsessionredirect_uri");
		// not in use
//		if (saved_redirect_uri != null) {
//			claims.put("smart_style_url", saved_redirect_uri);
//			//	return_parameters.put("smart_style_url", saved_redirect_uri);
//			tokenMachine.setParameter("smart_style_url", saved_redirect_uri);
//		}
		String patient = (String)tgt.get("patient");
//		String patient = (String)tgt.get("identifier");
		// better would be to make this a configuration parameter
//		String patient = (String)tgt.get("oauthsession_patient");
		// followiing line for testing only
//		if (patient == null) patient = "f3ecf690-e035-498d-9e8c-1ef1e4db34b7";	// patient from sql call

		if (patient != null) {
			claims.put("patient", patient);
//			return_parameters.put("patient", patient);
			tokenMachine.setParameter("patient", patient);
		}
		
		// not in use
//		String encounter = "4632e61b-9b34-4ad7-a431-f008f35b4dd3";	// don't know yet where to get encounter from
// 		claims.put("encounter", encounter);
////		return_parameters.put("encounter", encounter);
// 		tokenMachine.setParameter("encounter", encounter);

		
		claims.put("token_type", "bearer");
		tokenMachine.setParameter("token_type", "bearer");
		
		String client_id = (String)tgt.get("oauthsessionclient_id");	// get client_id from tgt
		if (client_id != null) {
			claims.put("client_id", client_id);
			tokenMachine.setParameter("client_id", client_id);
		}

		tokenMachine.setParameter("issuer", getIssuer());	// RH, 20200214, n
		
		// Also retrieve the id_token if there is one (Must have been requested with scope parameter in earlier Auth request
		String saved_scope = (String)tgt.get("oauthsessionscope");

		if (saved_scope != null && saved_scope.contains("openid")) {
			if (history != null) {	// get info from historymanager
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieving id_token from history");
			
				String id_token = (String)history.get(ID_TOKEN_PREFIX + code);
				if (id_token != null) {
					// we should generate new id_token with proper appidacr
					//	return_parameters.put("id_token", id_token );
					tokenMachine.setParameter("id_token", id_token );
					claims.put("id_token", id_token);
					try {
						history.remove(ID_TOKEN_PREFIX + code);	// we'll have to handle if there would be a problem with remove
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Removed id token from local storage using auth code: " + Auxiliary.obfuscate(code));
					} catch (ASelectStorageException ase2) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Ignoring problem removing id token from temp storage: " + ase2.getMessage());
					}
				}
			} else {	// create new id_token, 	// we should check the currently requested scope, it might not contain "openid"
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to retrieve id_token from history manager");
			}

		}
		if (isAllow_refresh_token() && (saved_scope != null) && (saved_scope.contains("offline_access"))) {
			try {
				// generate random
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Creating new refresh_token");
				byte[] baRandomBytes = new byte[120];	// just like a tgt
		
				CryptoEngine.nextRandomBytes(baRandomBytes);
				String storeToken = Utils.byteArrayToHexString(baRandomBytes);	// mimic the sTgt
				boolean createOK = persistentStorage.create(REFRESH_TOKEN_PREFIX + storeToken, tgt); // save original tgt
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "persistentStorage.create: " + createOK);
				
				if (createOK) {
					String extractedrefresh_credentials = CryptoEngine.getHandle().encryptTGT(baRandomBytes);
			 		String refresh_token = tokenMachine.createRefreshToken(extractedrefresh_credentials, tgt, ASelectConfigManager.getHandle().getDefaultPrivateKey());
					//	return_parameters.put("refresh_token", refresh_token);
					tokenMachine.setParameter("refresh_token", refresh_token);
				} else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem with persistent storage while storing refresh_token");
					// not sure about setting status if problem only with refresh_token, specs not conclusive 
				}
			} catch (UnsupportedEncodingException | JoseException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem creating refresh_token" + e.getMessage());
			} catch (ASelectException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem encrypting refresh_token" + e.getMessage());
			}
		}

		
		String new_scope = saved_scope;
		tokenMachine.setParameter("scope", new_scope);
		//	return_parameters.put("expires_in", String.valueOf(3600 / 60));	// still to make variable, should be int
//		tokenMachine.setParameter("expires_in", String.valueOf(3600 / 60));	// still to make variable, should be int
		tokenMachine.setParameter("expires_in", new Integer(3600).intValue());
		
		//	return_parameters.put("access_token", new_access_token );
		tokenMachine.setParameter("access_token", access_token );
//		return_parameters.put("token_type", "bearer" );
//		return_parameters.put("expires_in", DEFAULT_EXPIRES_IN );
//		return_status = 200; // all well
		tokenMachine.setStatus(200); // all well
		return tokenMachine.getStatus();
	}
	
}
