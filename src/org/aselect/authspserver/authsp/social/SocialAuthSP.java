package org.aselect.authspserver.authsp.social;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.authspserver.authsp.AbstractAuthSP;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;
import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Permission;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.SocialAuthConfig;
import org.brickred.socialauth.SocialAuthManager;
import org.brickred.socialauth.util.AccessGrant;
import org.brickred.socialauth.util.SocialAuthUtil;

/*
 * How to implement logout from a servlet or JSP file?
 * 
 * You have to just call manager.disconnectProvider(id) method where manager is a object of SocialAuthManager? class
 * and id is the provider id from which you want to logout or disconnect in your application.
 * For more info http://code.google.com/p/socialauth/issues/detail?id=88 
 */
public class SocialAuthSP extends AbstractAuthSP  // 20141201, Bauke: inherit goodies from AbstractAuthSP
{
	private static final long serialVersionUID = 1L;
	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static String MODULE = "SocialAuthSP";
	/**
	 * The version string
	 */
	private static String VERSION = "Social AuthSP";

	// different from the server-rid
	public static final String RID_POSTFIX = "_Social";

	//private String _sFailureHandling;
	
	private String _sUrlOverride;
	
	/* (non-Javadoc)
	 * @see org.aselect.system.servlet.ASelectHttpServlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig oConfig)
	throws ServletException
	{
		String sMethod = "init";

		try {
			super.init(oConfig, true, Errors.ERROR_SOCIAL_INTERNAL_ERROR);
			StringBuffer sbInfo = new StringBuffer("Starting: ").append(MODULE);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());

			// Load HTML templates.
			Utils.loadTemplateFromFile(_systemLogger, _sWorkingDir, _sConfigID, "error.html", null, _sFriendlyName, VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Successfully loaded 'error.html' template.");

			try {  // for testing purposes, to use instead of the real authspserver URL
				_sUrlOverride = _configManager.getParam(_oAuthSpConfig, "url_override");
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'url_override' found, using server url", e);
				//throw new ASelectException(Errors.ERROR_SOCIAL_INTERNAL_ERROR, e);
			}

			sbInfo = new StringBuffer("Successfully started ").append(VERSION);
			_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Initializing failed", e);
			throw new ServletException("Initializing failed");
		}
	}
	
	/* https://siam.plains.nl/authspserver/social?
	 * as_url=https%3A%2F%2Fsiam.plains.nl%2Faselectserver%2Fserver?
	 * authsp%3DSocial&
	 * app_id=app1&
	 * rid=RCFAAC558E754535206046F69308068850549E016&
	 * a-select-server=siam.plains.nlserver&
	 * signature=ezTx0GyFo...&language=nl&requestorfriendlyname=friendly_app2&
	 * social_login=google
	 */
	/**
	 * Processes requests for HTTP <code>GET</code>. <br>
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, java.io.IOException
	{
		String sMethod = "doGet";
		HashMap<String,Object> htSessionContext = null;
		String sRid = null;
		String sSignRid = null;
	
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Enter");

		PrintWriter pwOut = Utils.prepareForHtmlOutput(servletRequest, servletResponse);

		String sQueryString = servletRequest.getQueryString();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "initial sQueryString="+sQueryString);
//		String sURI = servletRequest.getRequestURI();
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "sURI="+sURI);
		StringBuffer sURL = servletRequest.getRequestURL();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "sURL="+sURL);
		try {
			URI uri = new URI(sURL.toString());
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "uri="+uri);
//			URL url = new URL(sURL.toString());
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "url="+url);
			String uri_fragment = uri.getFragment();
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "uri_fragment="+uri_fragment);
//			String url_path = url.getPath();	// url has no fragment
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "url_path="+url_path);
			if (uri_fragment != null && uri_fragment.length()>0) {
				if (sQueryString != null && sQueryString.length()>0) {
					sQueryString += "&" + uri_fragment;
				} else {
					sQueryString = uri_fragment;
				}
			}			
		} catch (URISyntaxException e1) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Invalid URI syntax: "+e1);
			handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, null, null);
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "final sQueryString="+sQueryString);
		HashMap htServiceRequest = Utils.convertCGIMessage(sQueryString, true);  // URL decoded result
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Enter - htServiceRequest:" + htServiceRequest);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Enter");
		
		// If 'state' is present this is the return call from the socialauth provider
		String sState = (String)htServiceRequest.get("state");
		if (Utils.hasValue(sState)) {
			BASE64Decoder base64Dec = new BASE64Decoder();
			sState = new String(base64Dec.decodeBuffer(sState));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "state="+sState);
			String[] aStateArgs = sState.split("_");
			sRid = aStateArgs[0];
			if (aStateArgs.length > 1)
				sSignRid = aStateArgs[1];
			doGetReturn(servletRequest, servletResponse, sRid, sSignRid, pwOut);
			return;
		}
		
		String sLanguage = (String) htServiceRequest.get("language");  // optional language code
		if (sLanguage == null || sLanguage.trim().length() < 1)
			sLanguage = null;

		sRid = (String)htServiceRequest.get("rid");
		//String sIsReturn = (String)htServiceRequest.get("is_return");		
		//boolean isReturn = Boolean.parseBoolean(sIsReturn);
		
		/*if (!Utils.hasValue(sRid) || isReturn) {
			// handle return from social login provider
			sSignRid = (String)htServiceRequest.get("sign_rid");
			BASE64Decoder base64Dec = new BASE64Decoder();
			if (Utils.hasValue(sSignRid))
				sSignRid = new String(base64Dec.decodeBuffer(sSignRid));  //URLDecoder.decode(sSignRid, "UTF-8");  // should not be necessary
			doGetReturn(servletRequest, servletResponse, sRid, sSignRid, pwOut);
			return;
		}*/

		// To social login provider
		try {
			// Check signature from aselectserver
			String sAsUrl = (String)htServiceRequest.get("as_url");
			String sAppId = (String)htServiceRequest.get("app_id");
			String sServerId = (String)htServiceRequest.get("a-select-server");
			String sCountry = (String)htServiceRequest.get("country");
			String sSocialLogin = (String)htServiceRequest.get("social_login");
			String sSignature = (String)htServiceRequest.get("signature");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Signature="+sSignature);
			// Fields have been URL decoded

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "social_login="+sSocialLogin);

			StringBuffer sbTemp = new StringBuffer(sAsUrl).append(sRid).append(sAppId).append(sServerId).append(sSocialLogin);
			if (sLanguage != null) sbTemp.append(sLanguage);
			if (sCountry != null) sbTemp.append(sCountry);

			if (!_cryptoEngine.verifySignature(sServerId, sbTemp.toString(), sSignature)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid signature from A-Select Server "+sServerId);
				throw new ASelectException(Errors.ERROR_SOCIAL_INVALID_REQUEST);
			}

			// User chooses provider - Create a page where you ask the user to choose a provider.
			// When the user clicks on a provider, in your handling code you should do the following:
			// Create a instance of !SocialAuthConfig and call load() method to load configuration for providers.
			// Create a instance of !SocialAuthManager and call setSocialAuthConfig() to set the configuration.
			// Store !!SocialAuthManager object in session.
			// Redirect to the URL obtained by calling the function getAuthenticationUrl()
	
			//Create an instance of SocialAuthConfig object
			SocialAuthConfig config = SocialAuthConfig.getDefault();
	
			// Load configuration. By default load the configuration from oauth_consumer.properties. 
			// You can also pass input stream, properties object or properties file name.
			config.load();
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "config getApplicationProperties="+config.getApplicationProperties());
	
			// Create an instance of SocialAuthManager and set config
			SocialAuthManager socialAuthspManager = new SocialAuthManager();
			socialAuthspManager.setSocialAuthConfig(config);
			
			// URL of YOUR application which will be called after authentication
			String sMyUrl = servletRequest.getRequestURL().toString();
			if (Utils.hasValue(_sUrlOverride))
				sMyUrl = _sUrlOverride;
			_systemLogger.log(Level.FINE, MODULE, sMethod, "myUrl="+sMyUrl+" manager="+socialAuthspManager);

			// Protect the rid against unauthorized changes. Using URL encoding did not work correctly.
			// The sReturnUrl will completely be URL encoded, but upon return it was not properly decoded.
			StringBuffer sbWork = new StringBuffer(sRid);
			String sMySignRid = _cryptoEngine.generateSignature(sbWork.toString());
			// Since 'google' and 'facebook' do not know how to correctly URL decode our Return URL, just leave the =-signs at the end out
			sMySignRid = sMySignRid.replaceAll("=*$", "");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "SignRid="+sMySignRid);
			String sData = sRid+"_"+sMySignRid;
			
			{	// This works (no state passed though):
				// https://accounts.google.com/o/oauth2/auth?
				//client_id=346265140534-8rp175o275hrtv2cehdcl2hvd1cbol4q.apps.googleusercontent.com&
				//response_type=code&redirect_uri=https%3A%2F%2Fsiam1.test.anoigo.nl%2Fauthspserver%2Fsocial&
				//scope=https://www.googleapis.com/auth/userinfo.profile+https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/plus.login+https://www.google.com/m8/feeds+https://picasaweb.google.com/data/
				// Result:
				// qry=code=4/2JRIkUGfnd7e54pbb8fw33U6RehE.gmWiNKbSnuEROl05ti8ZT3ZDcH1XiQI&
				//authuser=0&num_sessions=1&hd=anoigo.nl&prompt=consent&
				//session_state=6fb52ad8dbda78c168d8e3249370804701ca7672..da7d
			}
			
			// GooglePlus must be tricked
			BASE64Encoder base64Enc = new BASE64Encoder();
			String sReturnUrl = null;
//			if ( "azure".equals(sSocialLogin) ) {
			if ( sSocialLogin.toLowerCase().startsWith("azure") ) {
				sReturnUrl = sMyUrl ;
			} else {
				sReturnUrl = sMyUrl + ("googleplus".equals(sSocialLogin)? "?state=googleplus_": "?state=") + base64Enc.encode(sData.getBytes("UTF-8"));
			}
//			String sReturnUrl = sMyUrl + ("googleplus".equals(sSocialLogin)? "?state=googleplus_": "?state=") + base64Enc.encode(sData.getBytes("UTF-8"));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sReturnUrl="+sReturnUrl);

			//String sUrl = socialAuthspManager.getAuthenticationUrl(sSocialLogin, sReturnUrl, Permission.AUTHENTICATE_ONLY); 
			String sUrl = socialAuthspManager.getAuthenticationUrl(sSocialLogin, sReturnUrl, Permission.AUTHENTICATE_ONLY);	// RH, 20200403, o
//			String sUrl = socialAuthspManager.getAuthenticationUrl(sSocialLogin, sReturnUrl, Permission.CUSTOM);	// RH, 20200403, n	// TEST
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "getAuthenticationUrl="+sUrl);
			// The complete value of sUrl is URL encoded now
			// Store in session
			String nonce = newToken();
//			if ( "azure".equals(sSocialLogin) ) {
			if ( sSocialLogin.toLowerCase().startsWith("azure") ) {
				sUrl += "&state=" + URLEncoder.encode( base64Enc.encode(sData.getBytes("UTF-8")), "UTF-8");
//				sUrl = sUrl.replace("response_type=code", "response_type=code+id_token&scope=openid&response_mode=query&nonce=12345");
//				sUrl += "&scope=openid%20offline_access&response_mode=query&nonce=" + nonce;	// RH, 20181213, o 
				sUrl += "&scope=openid&response_mode=query&nonce=" + nonce;	// RH, 20181213, n
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "authenticationUrl after manipulation="+sUrl);
			String sFabricatedRid = sRid + RID_POSTFIX;
			try {
				htSessionContext = _sessionManager.getSessionContext(sFabricatedRid);
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Not found: "+sFabricatedRid);
			}
			
			boolean doUpd = (htSessionContext != null);
			if (!doUpd)
				htSessionContext = new HashMap();
			htSessionContext.put("rid", sRid);
			htSessionContext.put("social_authsp_manager", socialAuthspManager);
			//_socialAuthManager = socialAuthspManager;
			htSessionContext.put("social_login", sSocialLogin);
			htSessionContext.put("nonce", nonce);
			
			Utils.copyHashmapValue("language", htSessionContext, htServiceRequest);
			Utils.copyHashmapValue("country", htSessionContext, htServiceRequest);
			Utils.copyHashmapValue("as_url", htSessionContext, htServiceRequest);
			Utils.copyHashmapValue("a-select-server", htSessionContext, htServiceRequest);
			
			if (doUpd) {
				_sessionManager.updateSession(sFabricatedRid, htSessionContext);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Updated session with id:" + sFabricatedRid);
			}
			else {
		        _sessionManager.createSession(sFabricatedRid, htSessionContext);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Created session with id:" + sFabricatedRid);
			}
			
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIRECT to: " + sUrl);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIRECT");
			servletResponse.sendRedirect(sUrl);
		}
		catch (ASelectException ae) {
			handleResult(htSessionContext, servletResponse, pwOut, ae.toString(), sLanguage, null);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process request due to internal error: "+e);
			handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, sLanguage, null);
		}
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Leave");
		}
	}

	/*
	 * Returning from google:
	 * http://opensource.brickred.com/authspserver/social?is_return=true&rid=R7ADFC87E9836CE7DB2341F834E2D0519B4E0F732&
	 * openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&
	 * openid.mode=id_res&
	 * openid.op_endpoint=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fud&
	 * openid.response_nonce=2014-02-18T13%3A30%3A23ZaQo1GHsvlkvZvw&
	 * openid.return_to=http%3A%2F%2Fopensource.brickred.com%2Fauthspserver%2Fsocial%3Fis_return%3Dtrue%26rid%3DR7ADFC87E9836CE7DB2341F834E2D0519B4E0F732&
	 * openid.assoc_handle=1.AMlYA9WrXgojzdigAMoAQOoN8kxIj9gZeS5T6h3tCzHrCcgB8OT5ggpWGnC20g&
	 * openid.signed=op_endpoint%2Cclaimed_id%2Cidentity%2Creturn_to%2Cresponse_nonce%2Cassoc_handle%2Cns.ext1%2Cns.ext2%2Cext1.mode%2Cext1.type.firstname%2Cext1.value.firstname%2Cext1.type.lastname%2Cext1.value.lastname%2Cext1.type.language%2Cext1.value.language%2Cext1.type.email%2Cext1.value.email%2Cext2.scope%2Cext2.request_token&
	 * openid.sig=x1LlWDK83WvAjjVQ%2FkKSPZkaXUQ%3D&
	 * openid.identity=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawmOIeTmK3Cxj1j6OOYRxoH7mUkcWJv5SXQ&
	 * openid.claimed_id=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fid%3Fid%3DAItOawmOIeTmK3Cxj1j6OOYRxoH7mUkcWJv5SXQ&
	 * openid.ns.ext1=http%3A%2F%2Fopenid.net%2Fsrv%2Fax%2F1.0&openid.ext1.mode=fetch_response&
	 * openid.ext1.type.firstname=http%3A%2F%2Faxschema.org%2FnamePerson%2Ffirst&
	 * openid.ext1.value.firstname=xxxxx&openid.ext1.type.lastname=http%3A%2F%2Faxschema.org%2FnamePerson%2Flast&
	 * openid.ext1.value.lastname=xxxxx&openid.ext1.type.language=http%3A%2F%2Faxschema.org%2Fpref%2Flanguage&openid.ext1.value.language=en&
	 * openid.ext1.type.email=http%3A%2F%2Faxschema.org%2Fcontact%2Femail&openid.ext1.value.email=xxxxx%40anoigo.nl&
	 * openid.ns.ext2=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Foauth%2F1.0&openid.ext2.scope=https%3A%2F%2Fwww.google.com%2Fm8%2Ffeeds%2F&
	 * openid.ext2.request_token=4%2FC83KiuJq649LQ3oxBoIkzTHUBiIz.wsj1uEWpLzgdOl05ti8ZT3ZnD2WKiAI#
	 *
	 * Cancelled:
	 * http://opensource.brickred.com/socialauthdemo/socialAuthSuccessAction.do?
	 * openid.mode=cancel&
	 * openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0
	 */
	protected void doGetReturn(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
								String sRid, String sRequestSignRid, PrintWriter pwOut)
	throws ServletException
	{
		String sMethod = "doGetReturn";
		String sUid = null;
		String sLanguage = null;
		HashMap<String,Object> htSessionContext = null;
        
		try {
			SocialAuthManager socialAuthManager;
			// get session from sRid
			_systemLogger.log(Level.INFO, MODULE, sMethod, "get session "+sRid);
			String sFabricatedRid = sRid + RID_POSTFIX;
			try {
				htSessionContext = _sessionManager.getSessionContext(sFabricatedRid);
			}
			catch (ASelectException ae) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Session not found: "+sFabricatedRid);
				throw new ASelectException(Errors.ERROR_SOCIAL_INTERNAL_ERROR);
			}
			sLanguage = (String)htSessionContext.get("language");
			
			StringBuffer sbWork = new StringBuffer(sRid);
			String sMySignRid = _cryptoEngine.generateSignature(sbWork.toString());
			// Since 'google' and 'facebook' do not know how to correctly URL decode our Return URL, just leave the =-signs at the end out
			sMySignRid = sMySignRid.replaceAll("=*$", "");
			if (!Utils.hasValue(sRequestSignRid))
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "No SIGNATURE received");

			if (!Utils.hasValue(sRequestSignRid) || !sMySignRid.equals(sRequestSignRid)) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Rid signature does not match or absent, has 'rid' been tampered with?");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "mySign="+sMySignRid+" Sign="+sRequestSignRid);
				handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, sLanguage, sUid);
				return;
			}

			// Provider redirects back
			//
			// When you redirect the user to the provider URL, the provider would validate the user,
			// either by asking for username / password or by existing session
			// and will then redirect the user back to you application URL mentioned above,
			// i.e. "http://opensource.brickred.com/socialauthdemo/socialAuthSuccessAction.do".
			// Now you can obtain any profile information using the following code
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Signing OK, get manager");
			// Get the auth provider manager from session
			socialAuthManager = (SocialAuthManager)htSessionContext.get("social_authsp_manager");
			
			// Call the manager's connect method which returns the provider object. 
			// Pass request parameter map while calling connect method.
			_systemLogger.log(Level.INFO, MODULE, sMethod, "getRequestParametersMap");
			Map<String, String> paramsMap = SocialAuthUtil.getRequestParametersMap(servletRequest); 
			_systemLogger.log(Level.INFO, MODULE, sMethod, "connect");
			AuthProvider provider = socialAuthManager.connect(paramsMap);

			// Get the user profile
			_systemLogger.log(Level.INFO, MODULE, sMethod, "getUserProfile");
			Profile p = provider.getUserProfile();

			// You can obtain profile information
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Result: First="+Auxiliary.obfuscate(p.getFirstName())+" Last="+Auxiliary.obfuscate(p.getLastName())+
					" Display="+Auxiliary.obfuscate(p.getDisplayName())+" Email="+Auxiliary.obfuscate(p.getEmail())+" ValidId="+Auxiliary.obfuscate(p.getValidatedId())+
					" ProviderId="+Auxiliary.obfuscate(p.getProviderId()));

			String sSocialLogin = (String)htSessionContext.get("social_login");
//			if ("azure".equalsIgnoreCase(sSocialLogin)) {
			if ("azure".equalsIgnoreCase(sSocialLogin)) {
				// verify the nonce
				String orig_nonce = (String)htSessionContext.get("nonce");
				AccessGrant grant = provider.getAccessGrant();
				String nonce = (String)grant.getAttribute("nonce");
				if (!orig_nonce.equals(nonce)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Nonces not equal, id_token may be tempered with!");
					throw new ASelectException(Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER);
				}
			}
			// We're using the email address as 'uid'
			sUid = p.getEmail();
			if (!Utils.hasValue(sUid)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No email address returned");
				throw new ASelectException(Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER);
			}

			
//			if (!"azure".equalsIgnoreCase(sSocialLogin)) {	// backwards compatibility
			if ("azure".equalsIgnoreCase(sSocialLogin)) {
				sSocialLogin = "google"; //= (String)htSessionContext.get("social_login");
			}
//			String sSocialLogin = "google"; //= (String)htSessionContext.get("social_login");
			_authenticationLogger.log(new Object[] {
				MODULE, Auxiliary.obfuscate(sUid), servletRequest.getRemoteAddr(), Auxiliary.obfuscate(p.getEmail()), "granted,"+sSocialLogin
			});
			
			// We'd like to give some more info back to the server.
			// The only more or less stable populated elements seem to be getEmail(), getValidatedId() and getProviderId()
			// Latest of which might be important to the server
//			handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_SUCCESS, sLanguage, sUid);	// RH, 20170413, o
			handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_SUCCESS, sLanguage, sUid, p.getProviderId(), p.getValidatedId());	// RH, 20170413, n
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Sending error to client "+eAS.getMessage());
			handleResult(htSessionContext, servletResponse, pwOut, eAS.getMessage(), sLanguage, null);
		}
		catch (Exception e) {  // Unsuccessful authentication (including Cancel)
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not authenticate user: "+e.getMessage());
			handleResult(htSessionContext, servletResponse, pwOut, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, sLanguage, sUid);
		}		
		finally {
			if (pwOut != null) {
				pwOut.close();
				pwOut = null;
			}
		}
	}
	
	/**
	 * Private entry point of the AuthSP.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @throws ServletException
	 *             the servlet exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 *             
	 * @see javax.servlet.http.HttpServlet#doPost(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doPost(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws ServletException, IOException
	{
		String sMethod = "doPost";

		// Google likes to return using a POST request
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "POST " + servletRequest + ", qry="+servletRequest.getQueryString());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "POST " + servletRequest);
		doGet(servletRequest, servletResponse);
	}

	/**
	 * @return true, if checks if is restartable servlet
	 * @see org.aselect.system.servlet.ASelectHttpServlet#isRestartableServlet()
	 */
	@Override
	protected boolean isRestartableServlet()
	{
		return false;
	}
	
	private void handleResult(HashMap<String, Object> htSessionContext, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sResultCode, String sLanguage, String sUid)
	{
		handleResult(htSessionContext, servletResponse, pwOut,  sResultCode,  sLanguage, sUid, null, null);
	}	
	
	/**
	 * Handle result.
	 * 
	 * @param htSessionContext
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sResultCode
	 *            the s result code
	 * @param sResultCode
	 *            the uid retrieved user identity
	 */
//	private void handleResult(HashMap<String, Object> htSessionContext, HttpServletResponse servletResponse,
//			PrintWriter pwOut, String sResultCode, String sLanguage, String sUid)
	private void handleResult(HashMap<String, Object> htSessionContext, HttpServletResponse servletResponse,
					PrintWriter pwOut, String sResultCode, String sLanguage, String sUid, String providerId, String validatedId)
	{
		String sMethod = "handleResult";
		StringBuffer sbTemp = null;

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Result="+sResultCode);
		try {
//			if (_sFailureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_SOCIAL_SUCCESS)) {	// RH, 20181004, o
			if (htSessionContext != null && (_sFailureHandling.equalsIgnoreCase("aselect") || sResultCode.equals(Errors.ERROR_SOCIAL_SUCCESS))) {	// RH, 20181004, n
				// A-Select handles error or success
				String sRid = (String)htSessionContext.get("rid");
				String sAsUrl = (String)htSessionContext.get("as_url");
				String sAsServer = (String)htSessionContext.get("a-select-server");
				if (sRid == null || sAsUrl == null || sAsServer == null) {
					getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
				}
				else {
					sbTemp = new StringBuffer(sRid).append(sAsUrl).append(sResultCode).append(sAsServer);
					if (sUid != null) {
						sbTemp.append(sUid);
					}

					// RH, 20170413, sn
					BASE64Encoder base64Encoder = new BASE64Encoder();
					if (providerId != null) {
						providerId = base64Encoder.encode(providerId.getBytes("UTF-8"));
						sbTemp.append(providerId);
					}
					if (validatedId != null) {
						validatedId = base64Encoder.encode(validatedId.getBytes("UTF-8"));
						sbTemp.append(validatedId);
					}
					// RH, 20170413, en
					
					String sSignature = _cryptoEngine.generateSignature(sbTemp.toString());
					sbTemp = new StringBuffer(sAsUrl);  // do not encode the URL please
					sbTemp.append("&rid=").append(sRid);
					sbTemp.append("&result_code=").append(sResultCode);
					sbTemp.append("&a-select-server=").append(sAsServer);
					if (sUid != null) {
						sbTemp.append("&uid=").append(URLEncoder.encode(sUid, "UTF-8"));
					}
					
					// RH, 20170413, sn
					if (providerId != null)
						sbTemp.append("&providerid=").append(providerId);
					if (validatedId != null)
						sbTemp.append("&validatedid=").append(validatedId); // Bauke: added
					// RH, 20170413, en

					sbTemp.append("&signature=").append(URLEncoder.encode(sSignature, "UTF-8"));

//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIRECT TO: "+sbTemp.toString());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "REDIRECT");
					servletResponse.sendRedirect(sbTemp.toString());
				}
			}
			else {  // Local error handling
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
		}
		catch (ASelectException eAS) // could not generate signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not generate signature", eAS);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, sResultCode, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (UnsupportedEncodingException eUE) // could not encode signature
		{
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encode signature", eUE);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
		catch (IOException eIO) {  // Redirect failed
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not redirect to: '"+sbTemp.toString()+"', "+eIO);
			try {
				getTemplateAndShowErrorPage(pwOut, sResultCode, Errors.ERROR_SOCIAL_COULD_NOT_AUTHENTICATE_USER, sLanguage, VERSION);
			}
			catch (ASelectException e) {
			}
		}
	}
}