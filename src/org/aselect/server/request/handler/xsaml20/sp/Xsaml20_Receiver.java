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
package org.aselect.server.request.handler.xsaml20.sp;

import java.io.PrintWriter;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.aselect.server.application.Application;
import org.aselect.server.application.ApplicationManager;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.xsaml20.PartnerData;
import org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.SecurityLevel;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.Audit;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;

public class Xsaml20_Receiver extends Saml20_BrowserHandler
{
	private final static String MODULE = "Xsaml20_Receiver";
	private final String ACCEPTREQUEST = "Response";

	//private String _sMyAppId = null;

	//HashMap<String, String> _htKnownApplications = new HashMap<String, String>(); // contains the know application id's
	
	/**
	 * Initializes the request handler
	 *  
	 * @param oServletConfig
	 *            the o servlet config
	 * @param oHandlerConfig
	 *            the o handler config
	 * @throws ASelectException
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oHandlerConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oHandlerConfig);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Overrides the default.
	 * 
	 * @param request
	 *            - HttpServletRequest
	 * @param response
	 *            - HttpServletResponse
	 * @return RequestState
	 * @throws ASelectException
	 */
	public RequestState process(HttpServletRequest request, HttpServletResponse response)
	throws ASelectException
	{
		String sMethod = "process";
		String sPathInfo = request.getPathInfo();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== Path=" + sPathInfo + " RequestQuery: "	+ request.getQueryString());
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request received === Path=" + sPathInfo+
				" Locale="+request.getLocale().getLanguage()+" Method="+request.getMethod());

		if (request.getParameter("SAMLRequest") != null || "POST".equals(request.getMethod())) {
			handleSAMLMessage(request, response);
		}
		else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Request: " + request.getQueryString()+ " is not recognized");
			throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, "> Request handled ");
		return new RequestState(null);
	}
	
	/**
	 * Handle specific saml20 request.
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @param httpRequest
	 *            the HTTP request
	 * @param httpResponse
	 *            the HTTP response
	 * @param samlMessage
	 *            the saml message to be handled
	 * @throws ASelectException
	 */
	@SuppressWarnings("unchecked")
	protected void handleSpecificSaml20Request(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
					PrintWriter pwOut, SignableSAMLObject samlMessage, String sRelayState)
	throws ASelectException
	{
		String sMethod = "handleSpecificSaml20Request " + Thread.currentThread().getId();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "PathInfo="+httpRequest.getPathInfo());
		String sApplicationResource = null;
		String sPresence = null;

		// The Assertion signature was checked in the Saml20_BrowserHandler already
		try {
			Assertion assertObj = (Assertion)samlMessage;
			//HandlerTools.marshallAssertion(assertObj, true);  // for debugging
			
			// Get the user id
			Subject oSubject = assertObj.getSubject();
			String sNameId = oSubject.getNameID().getValue();

			// Get the desired application
			List<AuthzDecisionStatement> lAuthzDec = assertObj.getAuthzDecisionStatements();
			if (lAuthzDec != null && lAuthzDec.size()>0) {
				AuthzDecisionStatement authzDec = lAuthzDec.get(0);
				if (authzDec != null)
					sApplicationResource = authzDec.getResource();
			}

			String elementName = samlMessage.getElementQName().getLocalPart();
			Issuer _oSamlIssuer = retrieveIssuer(elementName, samlMessage);

//			Application appData = ApplicationManager.getHandle().getApplication(get_SamlIssuer().getValue());
			Application appData = ApplicationManager.getHandle().getApplication(_oSamlIssuer.getValue());
			HashMap<String,String> htValidResources = appData.getValidResources();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Resource="+sApplicationResource+" valid="+htValidResources);

			// And check it against the known applications
			if (sApplicationResource == null && htValidResources.size() == 1) {
				Set<String> setAppl = htValidResources.keySet();
				Iterator itr = setAppl.iterator();
				sPresence = sApplicationResource = (String)itr.next();  // entry is present, use key value
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Default Found="+sApplicationResource);
			}
			else {
				sPresence = (String) htValidResources.get(sApplicationResource);  // if found, result is an empty string
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Present Found="+sApplicationResource);
			}
			if (sPresence == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unknown application: " + sApplicationResource);
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			_systemLogger.log(Level.INFO, MODULE, sMethod, "NameID="+sNameId+" Resource="+sApplicationResource);
			
			AuthnStatement oAuthn = assertObj.getAuthnStatements().get(0);
			AuthnContext oContext = oAuthn.getAuthnContext();
			AuthnContextClassRef oClassRef = oContext.getAuthnContextClassRef();
			String sClassRef = oClassRef.getAuthnContextClassRef();
			// RH, 20180810, sn
			// We want to get the partnerdata
			String sEntityId = _oSamlIssuer.getValue();
//			PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(sEntityId);	// RH, 20190322, o
			PartnerData partnerData = MetaDataManagerSp.getHandle().getPartnerDataEntry(_sResourceGroup, sEntityId);	// RH, 20190322, o
			String specialSettings = (partnerData == null)? null: partnerData.getSpecialSettings();
			//////////////////////
			// Maybe per application, not sure yet
//			String addedPatching = appData.getAddedPatching();
			////////////////////////////////
			boolean useLoa = (specialSettings != null && specialSettings.contains("use_loa"));
			_systemLogger.log(Level.FINER, MODULE, sMethod, "useLoa="+useLoa);
//			boolean useNewLoa = (_sSpecialSettings != null && _sSpecialSettings.contains("use_newloa"));
			boolean useNewLoa = (specialSettings != null && specialSettings.contains("use_newloa"));
			_systemLogger.log(Level.FINER, MODULE, sMethod, "useNewLoa="+useNewLoa);
			String sSecLevel = null;
			if (useNewLoa) {
				sSecLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sClassRef, useLoa, SecurityLevel.getNewLoaLevels(), _systemLogger);
			} else {
				sSecLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sClassRef, useLoa, SecurityLevel.getDefaultLevels(), _systemLogger);
			}
			// RH, 20180810, en
//			String sSecLevel = SecurityLevel.convertAuthnContextClassRefURIToLevel(sClassRef, false/*useLoa*/, _systemLogger);// RH, 20180810, o
			_systemLogger.log(Level.INFO, MODULE, sMethod, "ClassRef="+sClassRef+" level="+sSecLevel);
			
			Conditions oCond = assertObj.getConditions();
			DateTime oDateTime = oCond.getNotOnOrAfter();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Nooa="+oDateTime.toString()+" VerifyInterval="+is_bVerifyInterval());
			if (is_bVerifyInterval() && !SamlTools.checkValidityInterval(assertObj)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Bad validity interval");
				throw new ASelectException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
			}
			
			// Get the Attribute statement and retrieve the attributes from it
			HashMap htAttributes = new HashMap();
			htAttributes.put("uid", sNameId);
			htAttributes.put("sel_level", sSecLevel);
			htAttributes.put("authsp_type", "saml");
			htAttributes.put("friendly_name", appData.getFriendlyName());
			AttributeStatement attrStatement = assertObj.getAttributeStatements().get(0);
			List<Attribute> lAttr = attrStatement.getAttributes();
			for (int i=0; i<lAttr.size(); i++) {
				Attribute attr = lAttr.get(i);
				List<XMLObject> aValues = attr.getAttributeValues();
				XSString obj = (XSString)aValues.get(0);
				htAttributes.put(attr.getName(), obj.getValue());
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Attr "+attr.getName()+"="+obj.getValue());
			}
			
			// RH, 20150917, sn, oldTgt can be null
			// Assertion issuer must be equal to app_id to avoid signature verification problem in upgrade_tgt
			// if we have a tgt we'll have to update it
			String oldTgt = getCredentialsFromCookie(httpRequest);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== Found tgt=" + oldTgt );
			String _sCookieDomain = _configManager.getCookieDomain();
			// Remove the TGT cookie

			// RH, 20150917, sn, oldTgt can be null
			
			// Create a ticket with attributes and set a cookie
//			String sTgt = createContextAndIssueTGT(httpResponse, null, null, _sMyServerId, _sASelectOrganization,
////									get_SamlIssuer().getValue(), null, htAttributes);	// RH, 20150917, o
//									get_SamlIssuer().getValue(), oldTgt, htAttributes);	// RH, 20150917, n, oldTgt can be null
			String sTgt = createContextAndIssueTGT(httpResponse, null, null, _sMyServerId, _sASelectOrganization,
//					get_SamlIssuer().getValue(), null, htAttributes);	// RH, 20150917, o
					_oSamlIssuer.getValue(), oldTgt, htAttributes);	// RH, 20150917, n, oldTgt can be null
			// and redirect the user to the destination url
			_systemLogger.log(Level.INFO, MODULE, sMethod, "REDIRECT to "+sApplicationResource);
			httpResponse.sendRedirect(sApplicationResource);
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not process", e);
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, Auxiliary.obfuscate(XMLHelper.prettyPrintXML(samlMessage.getDOM()), Auxiliary.REGEX_PATTERNS));
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		_systemLogger.log(Audit.AUDIT, MODULE, sMethod, ">>> SAML Response handled");
	}

	/**
	 * Override of the default supplied by Saml20_BrowserHandler
	 * Extract the part we're interested in from the 'samlMessage'
	 * Also retrieve the Issuer from the message and set _oSamlIssuer accordingly
	 * 
	 * @param samlMessage - the complete incoming message
	 * @return - the interesting part of the message
	 * @throws ASelectException
	 */
	protected SignableSAMLObject extractSamlObject(SignableSAMLObject samlMessage)
	throws ASelectException
	{
		String sMethod = "extractSamlObject";
		
		// Extract the "Assertion" from the message
		Response response = (Response)samlMessage;
		Assertion assertObj = response.getAssertions().get(0);  // pointer in samlMessage
		//HandlerTools.marshallAssertion(assertObj, true);  // for debugging
		// RH, 20210805, so
//		set_SamlIssuer(assertObj.getIssuer());
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "Issuer="+get_SamlIssuer().getValue()+" ObjectId="+assertObj.getID()); 
		// RH, 20210805, eo
		return (SignableSAMLObject) assertObj;
	}
	
	
	/**
	 * Override ProtoRequestHandler version to use signing key from Application
	 * 
	 * @param sEntityId - to retrieve key for
	 * @return - the public key
	 * @throws ASelectException
	 */
	/*
	public PublicKey retrievePublicSigningKey(String sEntityId)
	throws ASelectException
	{
		String sMethod = "retrievePublicSigningKey";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Application Key for: "+sEntityId);
		return ApplicationManager.getHandle().getSigningKey(sEntityId);
	}
	*/

	// RH, 20200918, sn
	@Override
	public List <PublicKey> retrievePublicKeys(String resourceGroup, String sEntityId)
	throws ASelectException
	{
		String sMethod = "retrievePublicKeys";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Public key for for: "+sEntityId);
		return retrievePublicSigningKey(sEntityId);
	}
	// RH, 20200918, en
	
	
	
	// RH, 20181119, sn
	/**
	 * Override ProtoRequestHandler version to use signing key from Application
	 * 
	 * @param sEntityId - to retrieve key for
	 * @return - the public key
	 * @throws ASelectException
	 */
	public List<PublicKey> retrievePublicSigningKey(String sEntityId)
	throws ASelectException
	{
		String sMethod = "retrievePublicSigningKey";
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Get Application Key for: "+sEntityId);
		List<PublicKey> pkeys = new ArrayList<PublicKey>();
		pkeys.add(ApplicationManager.getHandle().getSigningKey(sEntityId));
//		return ApplicationManager.getHandle().getSigningKey(sEntityId);
		return pkeys;
	}
	// RH, 20181119, en

	/* (non-Javadoc)
	 * @see org.aselect.server.request.handler.xsaml20.Saml20_BrowserHandler#retrieveIssuer(java.lang.String, org.opensaml.common.SignableSAMLObject)
	 */
	public Issuer retrieveIssuer(String elementName, SignableSAMLObject samlMessage)
	{
		Assertion assertObj = (Assertion)samlMessage;
		return assertObj.getIssuer();
	}
	
	/**
	 * Tell caller the XML type we want recognized
	 * Overrides the abstract method called in handleSAMLMessage().
	 * 
	 * @return
	 *		the XML type
	 */
	protected String retrieveXmlType()
	{
		return ACCEPTREQUEST;
	}
}
