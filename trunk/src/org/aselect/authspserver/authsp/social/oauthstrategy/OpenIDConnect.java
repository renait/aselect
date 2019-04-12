/*
 ===========================================================================
 Copyright (c) 2010 BrickRed Technologies Limited

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sub-license, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 ===========================================================================

20170216, RH
Adjusted for OpenID Connect
 */

package  org.aselect.authspserver.authsp.social.oauthstrategy;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.brickred.socialauth.Permission;
import org.brickred.socialauth.exception.ProviderStateException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.brickred.socialauth.oauthstrategy.OAuthStrategyBase;
import org.brickred.socialauth.util.AccessGrant;
import org.brickred.socialauth.util.Constants;
import org.brickred.socialauth.util.HttpUtil;
import org.brickred.socialauth.util.MethodType;
import org.brickred.socialauth.util.OAuthConfig;
import org.brickred.socialauth.util.OAuthConsumer;
import org.brickred.socialauth.util.Response;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.json.JSONException;
import org.json.JSONObject;

public class OpenIDConnect implements OAuthStrategyBase {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3656116053298969608L;
	private final Log LOG = LogFactory.getLog(OpenIDConnect.class);
	private AccessGrant accessGrant;
	private OAuthConsumer oauth;
	private boolean providerState;
	private Map<String, String> endpoints;
	private String scope;
	private Permission permission;
	private String providerId;
	private String successUrl;
	private String accessTokenParameterName;
	Map<String, String> customproperties ;

	public OpenIDConnect(final OAuthConfig config, final Map<String, String> endpoints) {
		oauth = new OAuthConsumer(config);
		this.endpoints = endpoints;
		permission = Permission.DEFAULT;
		providerId = config.getId();
		accessTokenParameterName = Constants.ACCESS_TOKEN_PARAMETER_NAME;
		LOG.debug("ACCESS_TOKEN_PARAMETER_NAME: " + accessTokenParameterName);
		customproperties = config.getCustomProperties();
	}

	@Override
	public String getLoginRedirectURL(final String successUrl) throws Exception {
		return getLoginRedirectURL(successUrl, null);
	}

	@Override
	public String getLoginRedirectURL(String successUrl,
			Map<String, String> requestParams) throws Exception {
		LOG.info("Determining URL for redirection");
		LOG.debug("successUrl: " + successUrl);
		LOG.debug("requestParams: " + requestParams);
		providerState = true;
		try {
			this.successUrl = URLEncoder.encode(successUrl, Constants.ENCODING);
		} catch (UnsupportedEncodingException e) {
			this.successUrl = successUrl;
		}
		StringBuffer sb = new StringBuffer();
		sb.append(endpoints.get(Constants.OAUTH_AUTHORIZATION_URL));
		char separator = endpoints.get(Constants.OAUTH_AUTHORIZATION_URL)
				.indexOf('?') == -1 ? '?' : '&';
		sb.append(separator);
		sb.append("client_id=").append(oauth.getConfig().get_consumerKey());
		///////////////////	RH, 20190114, sn
		String resp_type = "code+id_token";	// default for OpenID Connect
		String custom_response_type = customproperties.get("reponse_type");
		if (custom_response_type != null && custom_response_type.length() > 0) {
			resp_type = custom_response_type;
		}
		sb.append("&response_type="+resp_type);
		///////////////////	RH, 20190114, sn
//		sb.append("&response_type=code");	// RH, 20160216, o	// RH, 20190114, o
//		sb.append("&response_type=code+id_token");	// RH, 20160216, n	// for OpenID Connect	// RH, 20181218, o
//		sb.append("&response_type=id_token");	// RH, 20160216, n	// for OpenID Connect	// RH, 20181218, n	// implicit
		sb.append("&redirect_uri=").append(this.successUrl);
		if (scope != null) {
			sb.append("&scope=").append(scope);
		}
		// This can be made better
		// For OpenID Connect should always include: scope, response_mode post_form or query, state, nonce, p b2c_1_xxx
		if (requestParams != null && !requestParams.isEmpty()) {
			for (String key : requestParams.keySet()) {
				sb.append("&");
				sb.append(key).append("=").append(requestParams.get(key));
			}
		}
		String url = sb.toString();

		LOG.info("Redirection to following URL should happen : " + url);
		return url;
	}

	@Override
	public AccessGrant verifyResponse(final Map<String, String> requestParams)
			throws Exception {		
//		return verifyResponse(requestParams, MethodType.GET.toString());
		return verifyResponse(requestParams, MethodType.POST.toString());	// Should be POST for OpenID Connect

	}

	@Override
	public AccessGrant verifyResponse(final Map<String, String> requestParams,
			final String methodType) throws Exception {
		LOG.info("Verifying the authentication response from provider using: " + methodType );

		// we'll probably won't need this because we'll use the id_token + code and request access_token later
//		if (requestParams.get("access_token") != null) {
//			LOG.debug("Creating Access Grant");
//			String accessToken = requestParams.get("access_token");
//			Integer expires = null;
//			if (requestParams.get(Constants.EXPIRES) != null) {
//				expires = new Integer(requestParams.get(Constants.EXPIRES));
//			}
//			accessGrant = new AccessGrant();
//			accessGrant.setKey(accessToken);
//			accessGrant.setAttribute(Constants.EXPIRES, expires);
//			if (permission != null) {
//				accessGrant.setPermission(permission);
//			} else {
//				accessGrant.setPermission(Permission.ALL);
//			}
//			accessGrant.setProviderId(providerId);
//			LOG.debug(accessGrant);
//			return accessGrant;
//		} else {
//			LOG.info("No access_token in response, searching for code");
//		}

		if (!providerState) {
			throw new ProviderStateException();
		}

		String code = requestParams.get("code");
		if (code == null || code.length() == 0) {
			LOG.info("No code in response, searching for id_token");
		}
		LOG.debug("Verification Code : " + code);
		String id_token = requestParams.get("id_token");
		Map<String, Object> claims = null;
		if (id_token == null || id_token.length() == 0) {
			LOG.info("No id_token in response, searching");
			// maybe throw exception here
		} else {
//			LOG.debug("ID Token : " + id_token);
			LOG.debug("ID Token retrieved");
			// verify and decode id_token here
			// Azure uses list of email addresses
			// Still to verify types in the claim
			claims = consumeJWT(id_token);
			// We should verify nonce, aud, iad and exp here
//			LOG.debug("claims : " + claims);
		}
		
//		String acode;
		String accessToken = null;
//		try {
//			acode = URLEncoder.encode(code, "UTF-8");	// no need, using POST
//		} catch (Exception e) {
//			acode = code;
//		}
		StringBuffer sb = new StringBuffer();
	//	if (MethodType.GET.toString().equals(methodType)) {
//			sb.append(endpoints.get(Constants.OAUTH_ACCESS_TOKEN_URL));
//			char separator = endpoints.get(Constants.OAUTH_ACCESS_TOKEN_URL)
//					.indexOf('?') == -1 ? '?' : '&';
//			sb.append(separator);
//			// p must be added to the query string
//		}
		sb.append("client_id=").append(oauth.getConfig().get_consumerKey());
		sb.append("&redirect_uri=").append(this.successUrl);
		sb.append("&client_secret=").append(
				oauth.getConfig().get_consumerSecret());
//		sb.append("&code=").append(acode);
		sb.append("&code=").append(code);
		
		sb.append("&grant_type=authorization_code");
		// scope openid and/or offline_access should be appended
//		sb.append("&scope=10fd3b2c-1325-4168-be9d-690412ab8fb2 offline_access");
		// using client_id in scope should return access_token for azure
		sb.append("&scope=" + oauth.getConfig().get_consumerKey() + " offline_access");

		Response response;
		String authURL = null;
		String result = null;
		Map<String, Object> attributes = new HashMap<String, Object>();
		Integer expires = null;
		try {
				authURL = endpoints.get(Constants.OAUTH_ACCESS_TOKEN_URL);
				LOG.debug("POST URL for Access Token request : " + authURL);
//				LOG.debug("Sending POST parameterst : " + sb.toString());
				response = HttpUtil.doHttpRequest(authURL, methodType,
						sb.toString(), null);
				if (response != null) {
					result = response.getResponseBodyAsString(Constants.ENCODING);
					LOG.debug("POST URL getResponseBodyAsString : " + result);

					if (result != null) {
						// azure returns json object
						JSONObject jObj = new JSONObject(result);
						LOG.debug("POST URL jObj : " + jObj.toString());
						if (jObj.has("access_token")) {
							accessToken = jObj.getString("access_token");
						}
						// RH, 20190115, sn
						if ( (id_token == null  || id_token.length() == 0) && jObj.has("id_token") ) {
							LOG.debug("POST URL ID Token retrieved");
							id_token = jObj.getString("id_token");
							// verify and decode id_token here
							// Azure uses list of email addresses
							// Still to verify types in the claim
							claims = consumeJWT(id_token);
						}
						// RH, 20190115, en

						// expires_in can come in several different types, and newer
						// org.json versions complain if you try to do getString over an
						// integer...
						if (jObj.has("expires_in") && jObj.opt("expires_in") != null) {
							String str = jObj.get("expires_in").toString();
							if (str != null && str.length() > 0) {
								expires = Integer.valueOf(str);
							}
						}
						if (accessToken != null) {
							Iterator<String> keyItr = jObj.keys();
							while (keyItr.hasNext()) {
								String key = keyItr.next();
								if (!"access_token".equals(key)
										&& !"expires_in".equals(key)
										&& jObj.opt(key) != null) {
									attributes.put(key, jObj.opt(key).toString());
								}
							}
						}
					}
				} else {
					LOG.warn("response == null");
				}
		} catch (JSONException jex) {
			LOG.warn("No or invalid json object returned for access_token from : " + authURL);
			LOG.warn("Error in json : " + jex.getMessage());
		} catch (Exception sex) {
			LOG.warn("Exception retrieving access_token from : " + authURL);
			LOG.warn("Exception : " + sex.getMessage());
		}
//		LOG.debug("result : " + result);
		
		if (id_token != null) {	// id_token takes precedence, still have to decide on access token
//			LOG.debug("OpenID Token : " + id_token);
			accessGrant = new AccessGrant();
			accessGrant.setKey(id_token);
			if (claims != null) {
				LOG.debug("Expires : " + claims.get("exp"));
				accessGrant.setAttribute(Constants.EXPIRES, expires);
				accessGrant.setAttributes(claims);
			}
			if (permission != null) {
				accessGrant.setPermission(permission);
			} else {
				accessGrant.setPermission(Permission.ALL);
			}
			accessGrant.setProviderId(providerId);
//		} else {
		}
//			LOG.debug("Access Token : " + accessToken);
			LOG.debug("Access Token retrieved");
			LOG.debug("Expires : " + expires);
			if (accessToken != null) {
				// add the token to the result somehow
				if (accessGrant == null) accessGrant = new AccessGrant();
				
				accessGrant.setAttribute("access_token", accessToken);
				// for now we just return the token
				// we might want to return access_token attributes separately
				
//				accessGrant = new AccessGrant();
//				accessGrant.setKey(accessToken);
//				accessGrant.setAttribute(Constants.EXPIRES, expires);
//				if (attributes.size() > 0) {
//					accessGrant.setAttributes(attributes);
//				}
//				if (permission != null) {
//					accessGrant.setPermission(permission);
//				} else {
//					accessGrant.setPermission(Permission.ALL);
//				}
//				accessGrant.setProviderId(providerId);
			} else {
				LOG.info("NO Access Token returned ");
//				throw new SocialAuthException(
//						"Access token and expires not found from " + authURL);
			}
//		}
		return accessGrant;
	}

	@Override
	public void setScope(final String scope) {
		this.scope = scope;
	}

	@Override
	public void setPermission(final Permission permission) {
		this.permission = permission;
	}

	@Override
	public Response executeFeed(final String url) throws Exception {
		if (accessGrant == null) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		char separator = url.indexOf('?') == -1 ? '?' : '&';
		String urlStr = url + separator + accessTokenParameterName + "="
				+ accessGrant.getKey();
		LOG.debug("Calling URL : " + urlStr);
		return HttpUtil.doHttpRequest(urlStr, MethodType.GET.toString(), null,
				null);
	}

	@Override
	public Response executeFeed(final String url, final String methodType,
			final Map<String, String> params,
			final Map<String, String> headerParams, final String body)
			throws Exception {
		if (accessGrant == null) {
			throw new SocialAuthException(
					"Please call verifyResponse function first to get Access Token");
		}
		String reqURL = url;
		String bodyStr = body;
		StringBuffer sb = new StringBuffer();
		sb.append(accessTokenParameterName).append("=")
				.append(accessGrant.getKey());
		if (params != null && params.size() > 0) {
			for (String key : params.keySet()) {
				if (sb.length() > 0) {
					sb.append("&");
				}
				sb.append(key).append("=").append(params.get(key));
			}
		}
		if (MethodType.GET.toString().equals(methodType)) {
			if (sb.length() > 0) {
				int idx = url.indexOf('?');
				if (idx == -1) {
					reqURL += "?";
				} else {
					reqURL += "&";
				}
				reqURL += sb.toString();
			}
		} else if (MethodType.POST.toString().equals(methodType)
				|| MethodType.PUT.toString().equals(methodType)) {
			if (sb.length() > 0) {
				if (bodyStr != null) {
					if (headerParams != null
							&& headerParams.containsKey("Content-Type")) {
						String val = headerParams.get("Content-Type");
						if (!"application/json".equals(val)
								&& val.indexOf("text/xml") == -1) {
							bodyStr += "&";
							bodyStr += sb.toString();
						}
					} else {
						bodyStr += "&";
						bodyStr += sb.toString();
					}
				} else {
					bodyStr = sb.toString();
				}

			}
		}
		LOG.debug("Calling URL	:	" + reqURL);
		LOG.debug("Body		:	" + bodyStr);
		LOG.debug("Header Params	:	" + headerParams);
		return HttpUtil
				.doHttpRequest(reqURL, methodType, bodyStr, headerParams);
	}

	@Override
	public void setAccessGrant(final AccessGrant accessGrant) {
		this.accessGrant = accessGrant;
	}

	@Override
	public void setAccessTokenParameterName(
			final String accessTokenParameterName) {
		this.accessTokenParameterName = accessTokenParameterName;
	}

	@Override
	public void logout() {
		accessGrant = null;
		providerState = false;
	}

	@Override
	public Response uploadImage(final String url, final String methodType,
			final Map<String, String> params,
			final Map<String, String> headerParams, final String fileName,
			final InputStream inputStream, final String fileParamName)
			throws Exception {
		Map<String, String> map = new HashMap<String, String>();
		map.put(accessTokenParameterName, accessGrant.getKey());
		if (params != null && params.size() > 0) {
			map.putAll(params);
		}
		return HttpUtil.doHttpRequest(url, methodType, map, headerParams,
				inputStream, fileName, null);
	}

	@Override
	public AccessGrant getAccessGrant() {
		return accessGrant;
	}

	private Map<String, Object> consumeJWT(String jwt) throws InvalidJwtException  {
		
		Map<String, Object> claims = null;
//		LOG.debug("jwt : " + jwt);
	    // Build a JwtConsumer that doesn't check signatures or do any validation.
	    JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
	            .setSkipAllValidators()
	            .setDisableRequireSignature()
	            .setSkipSignatureVerification()
	            .build();

//		LOG.debug("firstPassJwtConsumer : " + firstPassJwtConsumer);

	    //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
	    JwtContext jwtContext = firstPassJwtConsumer.process(jwt);
//		LOG.debug("jwtContext : " + jwtContext);

		// maybe we can save the raw token as well
//		LOG.debug("getJwt: " + jwtContext.getJwt());
	    claims = jwtContext.getJwtClaims().getClaimsMap();
//		LOG.debug("claims : " + claims);
//		LOG.debug("getRawJson() : " + jwtContext.getJwtClaims().getRawJson());

	    

	    // From the JwtContext we can get the issuer, or whatever else we might need,
	    // to lookup or figure out the kind of validation policy to apply
	    String issuer;
		try {
			issuer = jwtContext.getJwtClaims().getIssuer();
			LOG.debug("issuer : " + issuer);
	
//		    String jwtid = jwtContext.getJwtClaims().getJwtId();
//			LOG.debug("jwtid : " + jwtid);
	
		    List<String> audience = jwtContext.getJwtClaims().getAudience();
			LOG.debug("audience : " + audience);
		}
		catch (MalformedClaimException e1) {
			LOG.warn("Trying to continuing after exception: " + e1.getMessage());
		}

//		String kid = jwtContext.getJwtClaims().getStringClaimValue("kid");	// zit in json header, wordt niet herkend in claims
		LOG.debug("kid : " + claims.get("kid"));
	    
	    String tfp = (String) claims.get("tfp");
		LOG.debug("httpsJkws : " + tfp);
	    
		
		claims = null;	// reset claims until verified
	    // The HttpsJwks retrieves and caches keys from a the given HTTPS JWKS endpoint.
	    // Because it retains the JWKs after fetching them, it can and should be reused
	    // to improve efficiency by reducing the number of outbound calls the the endpoint.
		String JwksLocation = customproperties.get("jwksurl");
		if (JwksLocation == null) {
			LOG.warn("Unable to verify token, values not to be trusted! " + "No custom property: Jwksurl");
			return claims;
		}
//	    HttpsJwks httpsJkws = new HttpsJwks("https://login.microsoftonline.com/anoigob2c.onmicrosoft.com/discovery/v2.0/keys?p=" 
//	    +tfp);
	    HttpsJwks httpsJkws = new HttpsJwks(JwksLocation + "?p=" +tfp);
		LOG.debug("httpsJkws : " + httpsJkws);
	    
	    // The HttpsJwksVerificationKeyResolver uses JWKs obtained from the HttpsJwks and will select the
	    // most appropriate one to use for verification based on the Key ID and other factors provided
	    // in the header of the JWS/JWT.
	    HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

	    
	    
	    // Using info from the JwtContext, this JwtConsumer is set up to verify
	    // the signature and validate the claims.
	    JwtConsumer secondPassJwtConsumer = new JwtConsumerBuilder()
//	            .setExpectedIssuer(issuer)
//	            .setVerificationKey(verificationKey)
	            .setVerificationKeyResolver(httpsJwksKeyResolver)
	            .setRequireExpirationTime()
	            // probably get clockskew from config
//	            .setAllowedClockSkewInSeconds(30)
	            .setAllowedClockSkewInSeconds(120)
	            .setRequireSubject()
//	            .setExpectedAudience("10fd3b2c-1325-4168-be9d-690412ab8fb2")	// to be made variable, get client id from config
	            .setExpectedAudience( oauth.getConfig().get_consumerKey())	// should be client id for azure
	            .build();
		LOG.debug("secondPassJwtConsumer : " + secondPassJwtConsumer);

	    // Finally using the second JwtConsumer to actually validate the JWT. This operates on
	    // the JwtContext from the first processing pass, which avoids redundant parsing/processing.
	    try {
			secondPassJwtConsumer.processContext(jwtContext);
			LOG.info("Passed token verification, values are to be trusted");
		    claims = jwtContext.getJwtClaims().getClaimsMap();	//. retrieve verified claims
		}
		catch (InvalidJwtException e) {
			// for testing
			LOG.warn("Unable to verify token, values not to be trusted: " + e.getMessage());
		}
		return claims;
		
		
	}
}
