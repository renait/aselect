package org.aselect.server.request.handler.xsaml20.idp;

import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlHistoryManager;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

//
// IdP SLO Http Response Handler
//
public class Xsaml20_SLO_Response extends Saml20_BrowserHandler
{
	private static final String MODULE = "LogoutResponseHandler";
	private final String LOGOUTRESPONSE = "LogoutResponse";

	private int _iRedirectLogoutTimeout = 30;
	private boolean _bTryRedirectLogoutFirst = true;

	public void destroy()
	{
	}

	/**
	 * Init for class LogoutResponseHandler. <br>
	 * 
	 * @param oServletConfig
	 *            ServletConfig.
	 * @param oConfig
	 *            Object.
	 * @throws ASelectException
	 *             If initialization fails.
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		super.init(oServletConfig, oConfig);
		String sMethod = "init()";
		
		String sTryRedirect = ASelectConfigManager.getSimpleParam(oConfig, "try_redirect_logout_first", false);
		if (sTryRedirect != null && !sTryRedirect.equals("true"))
			_bTryRedirectLogoutFirst = false;

		try {
			_iRedirectLogoutTimeout = new Integer(_configManager.getParam(oConfig, "redirect_logout_timeout")).intValue();
		}
		catch (ASelectConfigException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"No config item 'redirect_logout_timeout' found in 'handler' section", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	//
	// Signature was checked
	//
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest,
					HttpServletResponse httpResponse, SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request";
		LogoutResponse logoutResponse = (LogoutResponse)samlMessage;

		// check if the logoutResponse was successful
		String status = logoutResponse.getStatus().getStatusCode().getValue();
		if (!status.equals(StatusCode.SUCCESS_URI)) {
			// not much we can do about it, we continue logging out
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "LogoutResponse failed, StatusCode="+status);
		}

		// determine which user belongs to this response
		String inResponseTo = logoutResponse.getInResponseTo();
		Element element = (Element)SamlHistoryManager.getHandle().get(inResponseTo);

		// Get the original LogoutRequest sent by the initiating SP
		XMLObject oXml = null;
		try {
			oXml = SamlTools.unmarshallElement(element);
		}
		catch (MessageEncodingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error while unmarshalling " + element, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		if (!(oXml instanceof LogoutRequest)) {
			// Must be a LogoutRequest
			String msg = "LogoutRequest expected from SamlMessageHistory but received: " + oXml.getClass();
			_systemLogger.log(Level.INFO, MODULE, sMethod, msg);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		LogoutRequest originalLogoutRequest = (LogoutRequest) oXml;
//		String uid = originalLogoutRequest.getNameID().getValue();
		
        logoutNextSessionSP(httpRequest, httpResponse, originalLogoutRequest, null, null,
					_bTryRedirectLogoutFirst, _iRedirectLogoutTimeout, null);
	}
    
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
    {
		if (elementName.equals(LOGOUTRESPONSE)) {
			LogoutResponse logoutResponse = (LogoutResponse) samlMessage;
			return logoutResponse.getIssuer();
		}
		return null;
    }
}