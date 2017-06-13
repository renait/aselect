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


	
	@Override
	protected OAuthStrategyBase getOauthStrategy(){
// TODO Auto-generated method stub
return null;
}


}