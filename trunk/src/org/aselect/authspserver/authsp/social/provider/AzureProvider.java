/*
 ===========================================================================
 Copyright (c) 2012 BrickRed Technologies Limited

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


package org.aselect.authspserver.authsp.social.provider;

import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aselect.authspserver.authsp.social.oauthstrategy.OpenIDConnect;
import org.brickred.socialauth.AbstractProvider;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Contact;
import org.brickred.socialauth.Permission;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.exception.AccessTokenExpireException;
import org.brickred.socialauth.exception.SocialAuthException;
import org.brickred.socialauth.exception.UserDeniedPermissionException;
import org.brickred.socialauth.oauthstrategy.OAuthStrategyBase;
import org.brickred.socialauth.util.AccessGrant;
import org.brickred.socialauth.util.Constants;
import org.brickred.socialauth.util.OAuthConfig;
import org.brickred.socialauth.util.Response;


public class AzureProvider extends AbstractProvider implements
AuthProvider, Serializable {

	

	/**
	 * 
	 */
	private static final long serialVersionUID = 8420581005918578880L;
	private final Log LOG = LogFactory.getLog(AzureProvider.class);
	private Permission scope;
	private OAuthConfig config;
	private Profile userProfile;
	private AccessGrant accessGrant;
	private OAuthStrategyBase authenticationStrategy;

	private final Map<String, String> ENDPOINTS;


	public AzureProvider(final OAuthConfig providerConfig)
			throws Exception {
		config = providerConfig;
//		LOG.debug("providerConfig: " + config);
		
		if (config.getCustomPermissions() != null) {
			scope = Permission.CUSTOM;
		}
		LOG.debug("scope: " + scope);
		ENDPOINTS = new HashMap<String, String>();
		LOG.debug("OAUTH_AUTHORIZATION_URL: " + Constants.OAUTH_AUTHORIZATION_URL);
		ENDPOINTS.put(Constants.OAUTH_AUTHORIZATION_URL,
				providerConfig.getAuthenticationUrl());
		LOG.debug("OAUTH_ACCESS_TOKEN_URL: " + Constants.OAUTH_ACCESS_TOKEN_URL);
		ENDPOINTS.put(Constants.OAUTH_ACCESS_TOKEN_URL,
				providerConfig.getAccessTokenUrl());
		authenticationStrategy = new OpenIDConnect(config, ENDPOINTS);
		authenticationStrategy.setPermission(scope);
		authenticationStrategy.setScope(getScope());
	}

	/**
	 * Stores access grant for the provider
	 * 
	 * @param accessGrant
	 *            It contains the access token and other information
	 * @throws AccessTokenExpireException
	 */
	@Override
	public void setAccessGrant(final AccessGrant accessGrant)
			throws AccessTokenExpireException {
		this.accessGrant = accessGrant;
		LOG.debug("accessGrant: " + accessGrant);
		authenticationStrategy.setAccessGrant(accessGrant);
	}
	
	/**
	 * This is the most important action. It redirects the browser to an
	 * appropriate URL which will be used for authentication with the provider
	 * that has been set using setId()
	 * 
	 */
	@Override
	public String getLoginRedirectURL(final String successUrl) throws Exception {
		return authenticationStrategy.getLoginRedirectURL(successUrl);
	}


	/**
	 * Verifies the user when the external provider redirects back to our
	 * application.
	 * 
	 * 
	 * @param requestParams
	 *            request parameters, received from the provider
	 * @return Profile object containing the profile information
	 * @throws Exception
	 */

	@Override
	public Profile verifyResponse(final Map<String, String> requestParams)
			throws Exception {
		return doVerifyResponse(requestParams);
	}	
	
	private Profile doVerifyResponse(final Map<String, String> requestParams)
			throws Exception {
		LOG.info("Retrieving Access Token in verify response function");
		if (requestParams.get("error_reason") != null
				&& "user_denied".equals(requestParams.get("error_reason"))) {
			throw new UserDeniedPermissionException();
		}
		if (requestParams.get("error") != null
				&& "access_denied".equals(requestParams.get("error"))) {
			LOG.info("User access denied: " + requestParams.get("error_description"));
			throw new UserDeniedPermissionException();
		}
		accessGrant = authenticationStrategy.verifyResponse(requestParams);

		if (accessGrant != null) {
			LOG.debug("Access grant available");
			return null;
		} else {
			throw new SocialAuthException("Access token not found");
		}
	}	
	
	
	/**
	 * Updates the status on the chosen provider if available. This may not be
	 * implemented for all providers.
	 * 
	 * @param msg
	 *            Message to be shown as user's status
	 * @throws Exception
	 */

	@Override
	public Response updateStatus(final String msg) throws Exception {
		LOG.warn("WARNING: Not implemented for AzureProvider");
		throw new SocialAuthException(
				"Update Status is not implemented for AzureProvider");
	}
	

	@Override
	public List<Contact> getContactList() throws Exception {
		LOG.warn("WARNING: Not implemented for AzureProvider");
		throw new SocialAuthException(
				"Get Contacts is not implemented for AzureProvider");
	}	
	
	
	private Profile getProfile() throws Exception {
//		String presp;

		AccessGrant grant = getAccessGrant();
//		LOG.debug("getProfile using grant : " + grant);
		Profile p = new Profile();

		p.setValidatedId((String)grant.getAttribute("oid"));
		p.setFirstName((String)grant.getAttribute("given_name"));
		p.setLastName((String)grant.getAttribute("family_name"));
//		emails default for azureb2c
		String uid_claim = (config.getCustomProperties().get("uid_claim") != null) ? config.getCustomProperties().get("uid_claim") : "emails";
		
		LOG.debug("getProfile using uid_claim : " + uid_claim);
		
		p.setEmail(grant.getAttribute(uid_claim).toString());
		
		p.setProviderId(grant.getProviderId());
		userProfile = p;

		return p;
	}
	
	
	@Override
	public Profile getUserProfile() throws Exception {
		if (userProfile == null && accessGrant != null) {
			getProfile();
		}
		return userProfile;

	}	
	
	/**
	 * Logout
	 */
	@Override
	public void logout(){
		accessGrant = null;
		authenticationStrategy.logout();
	}
	
	@Override
	public void setPermission(final Permission p){
		LOG.debug("Permission requested : " + p.toString());
		this.scope = p;
		authenticationStrategy.setPermission(this.scope);
		authenticationStrategy.setScope(getScope());

	}	
	
	
	private String getScope()	{
		if (Permission.CUSTOM.equals(scope)
				&& config.getCustomPermissions() != null) {
			return config.getCustomPermissions();
		} else {
			return null;
		}
	}

}