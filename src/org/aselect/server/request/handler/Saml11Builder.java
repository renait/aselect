/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 *
 * @author Bauke Hiemstra - www.anoigo.nl
 * 
 * Version 1.0 - 14-11-2007
 */
package org.aselect.server.request.handler;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Base64;
import org.aselect.system.utils.Tools;
import org.opensaml.*;
import org.w3c.dom.Node;

//
//
//
public class Saml11Builder
{
    final String MODULE = "SAML11Builder";
    private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();
    private TGTManager _oTGTManager = TGTManager.getHandle();
    
    private String _sAttributeNamespace = "";
    private boolean _bSendAttributeStatement = false;
    private long _lAssertionExpireTime = 0;
    private String _sASelectServerID = "";
    private String SESSION_ID_PREFIX = "";
    
    public Saml11Builder()
    {
    }
    
    public Saml11Builder(String nameSpace, boolean sendAttr, long expTime, String serverID, String sesPrefix)
    {
    	_sAttributeNamespace = nameSpace;
    	_bSendAttributeStatement = sendAttr;
    	_lAssertionExpireTime = expTime;
    	_sASelectServerID = serverID;
    	SESSION_ID_PREFIX = sesPrefix;
    }
    
    public SAMLAssertion createAssertionFromString(String s)
    throws SAMLException
    {
        _systemLogger.log(Level.WARNING, MODULE, "createAssertionFromString()", "Assert="+s);
		InputStream i = new ByteArrayInputStream(s.getBytes());
		SAMLAssertion p = new SAMLAssertion(i);
		return p;
    }
    
	public SAMLAssertion createSAMLAssertionFromCredentials(
			String sUid, String sRequestID, String sNameIdFormat, String sIP, String sHost, String sConfirmationMethod,
			String sProviderId, String sAudience, Hashtable htInfo) 
            throws ASelectException
    {
        String sMethod = "createSAMLAssertion()";
        Hashtable htAttributes = null;
        try
        {
            String sAuthSPID = (String)htInfo.get("authsp");
            if (sAuthSPID == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'authsp' item in response from 'verify_credentials'");
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sAppID = (String)htInfo.get("app_id");
            if (sAppID == null) {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'app_id' item in response from 'verify_credentials'");
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            _systemLogger.log(Level.INFO, MODULE, sMethod, "genAUTH sAuthSPID="+sAuthSPID+" sAppID"+sAppID);
            String sAttributes = (String)htInfo.get("attributes");
            if (sAttributes != null)
            {
                htAttributes = deserializeAttributes(sAttributes);
            }
            else {
                _systemLogger.log(Level.FINE, MODULE, sMethod, "No parameter 'attributes' found");
                htAttributes = new Hashtable();
                htAttributes.put("uid", sUid);
                htAttributes.put("authsp", sAuthSPID);
                htAttributes.put("app_id", sAppID);
                String sPar = (String)htInfo.get("betrouwbaarheidsniveau");
                if (sPar != null) htAttributes.put("betrouwbaarheidsniveau", sPar);
            }
            
            // The real work!
            SAMLAssertion oSAMLAssertion = createMySAMLAssertion(sProviderId, sUid, sNameIdFormat, sIP, sHost,
            		sConfirmationMethod, sAudience, htAttributes);

            if (sRequestID != null) {  
            	// Add InResponseTo="<sRequestID>"
            	//_systemLogger.log(Level.INFO, MODULE, sMethod, "Generated Assertion="+oSAMLAssertion);
	            Node n = oSAMLAssertion.toDOM();
	            Tools.addAttributeToElement(n, _systemLogger, "Assertion", "InResponseTo", sRequestID);
	            //_systemLogger.log(Level.INFO, MODULE, sMethod, "Modified Assertion="+oSAMLAssertion);
            }
            
            //stores all SAML information to build SAML queries in the TGT Manager storage
            storeSessionInformation(sUid, sProviderId, sAppID, sAuthSPID, htAttributes);
            return oSAMLAssertion;
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAssertion", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }

	public SAMLAssertion createMySAMLAssertion(String sProviderId, String sUid, String sNameIdFormat, String sIP,
			String sHost, String sConfirmationMethod, String sAudience, Hashtable htAttributes)
	throws ASelectException, SAMLException
	{
		String sMethod = "createMySAMLAssertion()";
		Date dCurrent = new Date();
		Vector vSAMLStatements = new Vector();
		
		SAMLAuthenticationStatement oSAMLAuthenticationStatement = 
			generateSAMLAuthenticationStatement(sUid, sNameIdFormat, sIP, sHost, dCurrent, sConfirmationMethod);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML oSAMLAuthenticationStatement="+oSAMLAuthenticationStatement);
		if (oSAMLAuthenticationStatement != null) vSAMLStatements.add(oSAMLAuthenticationStatement);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML htAttributes="+htAttributes);
		if (_bSendAttributeStatement)
		{
		    _systemLogger.log(Level.INFO, MODULE, sMethod, "sUid="+sUid);
		    SAMLAttributeStatement oSAMLAttributeStatement =
		    				generateSAMLAttributeStatement(sUid, sNameIdFormat, htAttributes);
		    //_systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAttributeStatement="+oSAMLAttributeStatement);
		    if (oSAMLAttributeStatement != null) vSAMLStatements.add(oSAMLAttributeStatement);
		}
		Date dExpire = new Date(System.currentTimeMillis() + _lAssertionExpireTime);
		
		SAMLAudienceRestrictionCondition oAudienceRestr = null;
		Vector vConditions = null;
		if (sAudience != null && !sAudience.equals("")) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SAML sAudience="+sAudience);
			oAudienceRestr = new SAMLAudienceRestrictionCondition();
			oAudienceRestr.addAudience(sAudience);
			vConditions = new Vector();
			vConditions.add(oAudienceRestr);
		}
		SAMLAssertion oSAMLAssertion = new SAMLAssertion(
		    sProviderId, // Issuer: Our (IdP) Id
		    dCurrent,                   // Valid from
		    dExpire,                    // Valid until
		    vConditions,                // Audience condition
		    null,                       // Advice(s)
		    vSAMLStatements             // Contained statements
		    );
		return oSAMLAssertion;
	}

    private SAMLAuthenticationStatement generateSAMLAuthenticationStatement(
        String sUid, String sNameIdFormat, String sIP, String sHost, Date dCurrent, String sConfirmationMethod)
    throws ASelectException
    {
        String sMethod = "generateSAMLAuthenticationStatement()";
        SAMLAuthenticationStatement oSAMLAuthenticationStatement = null;
        try {
            _systemLogger.log(Level.INFO, MODULE, sMethod, "IDENT Uid="+sUid+" ServerID="+_sASelectServerID);
            SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, null/*qualifier*/, // _sASelectServerID,
            		(sNameIdFormat==null)? SAMLNameIdentifier.FORMAT_UNSPECIFIED: sNameIdFormat);               
           _systemLogger.log(Level.INFO, MODULE, sMethod, "SUBJECT oSAMLNameIdentifier="+oSAMLNameIdentifier);
           
            SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);               
            oSAMLSubject.addConfirmationMethod(SAMLSubject.CONF_BEARER); // sConfirmationMethod
            _systemLogger.log(Level.INFO, MODULE, sMethod, "AUTH oSAMLSubject="+oSAMLSubject);
            
            oSAMLAuthenticationStatement = new SAMLAuthenticationStatement(
                    oSAMLSubject,           // The subject 
                    sConfirmationMethod, // SAMLAuthenticationStatement.AuthenticationMethod_Password, // Authentication method
                    dCurrent,               // Issue instant
                    null,  // sIP,                    // The subject's IP
                    null,  // sHost,                  // The subject's hostname
                    null);                  // Authority bindings
        }
        catch (Exception e) {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAuthenticationStatement", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        
        return oSAMLAuthenticationStatement;
    }
    
    private SAMLAttributeStatement generateSAMLAttributeStatement(String sUid, String sNameIdFormat, Hashtable htAttributes) 
    throws ASelectException
    {
        String sMethod = "generateSAMLAttributeStatement()";
        SAMLAttributeStatement oSAMLAttributeStatement = null;
        SAMLAttribute oSAMLAttribute = null;
        try
        {
            Vector vAttributes = new Vector();
            Enumeration enumAttributeNames = htAttributes.keys();
            while (enumAttributeNames.hasMoreElements())
            {
                String sKey = (String)enumAttributeNames.nextElement();
                Object oValue = htAttributes.get(sKey);
                oSAMLAttribute = createSAMLAttribute(sKey, oValue, _sAttributeNamespace);
                _systemLogger.log(Level.INFO, MODULE, sMethod, "Attr Key="+sKey+", oValue="+oValue);  // +", oSAMLAttribute="+oSAMLAttribute);
                // TODO: opensaml escapes < and > signs in an attribute which is fatal for SymLabs
                if (!sKey.equals("DiscoveryResourceOffering"))
                	vAttributes.add(oSAMLAttribute);
            }
            // Make ADFS happy?
            oSAMLAttribute = createSAMLAttribute("group", "ClaimAppMapping", "http://schemas.xmlsoap.org/claims");
            vAttributes.add(oSAMLAttribute);
            
            SAMLNameIdentifier oSAMLNameIdentifier = new SAMLNameIdentifier(sUid, null/*qualifier: _sASelectServerID*/,
            		(sNameIdFormat==null)? SAMLNameIdentifier.FORMAT_UNSPECIFIED: sNameIdFormat);   
            
            SAMLSubject oSAMLSubject = new SAMLSubject(oSAMLNameIdentifier, null, null, null);              
            _systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLSubject="+oSAMLSubject);
            oSAMLAttributeStatement = new SAMLAttributeStatement(oSAMLSubject, vAttributes);
            _systemLogger.log(Level.INFO, MODULE, sMethod, "oSAMLAttributeStatement="+oSAMLAttributeStatement);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAttributeStatement", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return oSAMLAttributeStatement;
    }
    
    // Store Session info with the UserID
    private void storeSessionInformation(String sUid, String sProviderId, String sAppID,
    		String sAuthSPID, Hashtable htAttributes) 
    throws ASelectException
    {
        String sMethod = "storeSessionInformation()";
        try
        {
            String sSAMLID = SESSION_ID_PREFIX + sUid;
            _systemLogger.log(Level.INFO, MODULE, sMethod, "SAMLID="+sSAMLID);
            
            Hashtable htSAMLTGT = null;
            if(!_oTGTManager.containsKey(sSAMLID))
            {
                htSAMLTGT = new Hashtable();
                if (sProviderId != null && sAppID != null)
                {
                    Hashtable htResources = new Hashtable();
                    htResources.put(sProviderId, sAppID);
                    htSAMLTGT.put("resources", htResources);
                }
                                
                if (sAuthSPID != null)
                {
                    Vector vAuthSPs = new Vector();
                    vAuthSPs.add(sAuthSPID);
                    htSAMLTGT.put("authsps", vAuthSPs);
                }
                
                if (sProviderId != null && htAttributes != null)
                {
                    //store authentication information in session
                    //put attribute collection in TGTManager with id=saml11_[A-Select_username]
                    
                    Hashtable htAttribs = new Hashtable();
                    htAttribs.put(sProviderId, htAttributes);
                    htSAMLTGT.put("attributes", htAttribs);
                }
                _oTGTManager.put(sSAMLID, htSAMLTGT);
            }
            else
            {
                htSAMLTGT = _oTGTManager.getTGT(sSAMLID);
                
                if (sProviderId != null && sAppID != null)
                {
                    Hashtable htResources = (Hashtable)htSAMLTGT.get("resources");
                    htResources.put(sProviderId, sAppID);
                    htSAMLTGT.put("resources", htResources);
                }
                
                if (sAuthSPID != null)
                {
                    Vector vTGTAuthSPs = (Vector)htSAMLTGT.get("authsps");
                    vTGTAuthSPs.add(sAuthSPID);
                    htSAMLTGT.put("authsps", vTGTAuthSPs);
                }
                
                if (sProviderId != null && htAttributes != null)
                {
                    Hashtable htAttribs = (Hashtable)htSAMLTGT.get("attributes");
                    if (htAttribs != null)
                    {
                        Hashtable htAppIDAttribs = null;
                        if ((htAppIDAttribs = (Hashtable)htAttribs.get(sProviderId)) == null)
                        {
                            htAttribs.put(sProviderId, htAttributes);
                        }
                        else
                        {
                            htAppIDAttribs.putAll(htAttributes);
                            htAttribs.put(sProviderId, htAppIDAttribs);
                        }
                        htSAMLTGT.put("attributes", htAttribs);
                    }
                }
                _oTGTManager.updateTGT(sSAMLID, htSAMLTGT);
            }
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create SAMLAssertion", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
    }
    
    // From AbstractAPIRequestHandler()
    public Hashtable deserializeAttributes(String sSerializedAttributes) 
        throws ASelectException
    {
        String sMethod = "deSerializeAttributes()";
        Hashtable htAttributes = new Hashtable();
        if(sSerializedAttributes != null) //Attributes available
        {
            try
            {
                //base64 decode
                String sDecodedUserAttrs = new String(Base64.decode(sSerializedAttributes));
                
                //decode & and = chars
                String[] saAttrs = sDecodedUserAttrs.split("&");
                for (int i = 0; i < saAttrs.length; i++)
                {
                    int iEqualChar = saAttrs[i].indexOf("=");
                    String sKey = "";
                    String sValue = "";
                    Vector vVector = null;
                    
                    if (iEqualChar > 0)
                    {
                        sKey = URLDecoder.decode(
                            saAttrs[i].substring(0 , iEqualChar), "UTF-8");
                        
                        sValue= URLDecoder.decode(
                            saAttrs[i].substring(iEqualChar + 1), "UTF-8");
                        
                        if (sKey.endsWith("[]"))
                        { //it's a multi-valued attribute
                            // Strip [] from sKey
                            sKey = sKey.substring(0,sKey.length() - 2);
                            
                            if ((vVector = (Vector)htAttributes.get(sKey)) == null)
                                vVector = new Vector();                                
                            
                            vVector.add(sValue);
                        }                        
                    }
                    else
                        sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
                    
                    
                    if (vVector != null)
                        //store multivalue attribute
                        htAttributes.put(sKey, vVector);
                    else
                        //store singlevalue attribute
                        htAttributes.put(sKey, sValue);
                }
            }
            catch (Exception e)
            {
                _systemLogger.log(Level.WARNING, MODULE, sMethod, 
                    "Error during deserialization of attributes", e);
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
            }
        }
        return htAttributes;
    }
    
    // From AbstractAPIRequestHandler()
    public String serializeAttributes(Hashtable htAttributes)
    throws ASelectException
    {
        final String sMethod = "serializeAttributes()";
        try
        {
            if (htAttributes == null || htAttributes.isEmpty())
                return null;
            StringBuffer sb = new StringBuffer();
            for (Enumeration e = htAttributes.keys();
                e.hasMoreElements(); )
            {
                String sKey = (String)e.nextElement();
                Object oValue = htAttributes.get(sKey);
                
                if (oValue instanceof Vector)
                {//it's a multivalue attribute
                    Vector vValue = (Vector)oValue;
                    
                    sKey = URLEncoder.encode(sKey + "[]", "UTF-8");
                    Enumeration eEnum = vValue.elements();
                    while (eEnum.hasMoreElements())
                    {
                        String sValue = (String)eEnum.nextElement();

                        //add: key[]=value 
                        sb.append(sKey);
                        sb.append("=");
                        sb.append(URLEncoder.encode(sValue, "UTF-8")); 
                        
                        if (eEnum.hasMoreElements())
                            sb.append("&");
                    }
                }
                else if(oValue instanceof String)
                {//it's a single value attribute
                    String sValue = (String)oValue;

                    sb.append(URLEncoder.encode(sKey, "UTF-8"));
                    sb.append("=");
                    sb.append(URLEncoder.encode(sValue, "UTF-8"));
                }
                
                if (e.hasMoreElements())
                    sb.append("&");
            }
            BASE64Encoder b64enc = new BASE64Encoder();
            return b64enc.encode(sb.toString().getBytes("UTF-8"));
        }
        catch(Exception e)
        {
            _systemLogger.log(Level.WARNING, MODULE, sMethod,
                "Could not serialize attributes", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    // Bauke: TODO: createSAMLAttribute() html-escapes the attribute value
    private SAMLAttribute createSAMLAttribute(String sName, Object oValue, String sNameSpace)
    throws ASelectException
    {
        String sMethod = "generateSAMLAttribute()";
        SAMLAttribute oSAMLAttribute = new SAMLAttribute();
        
        try {
            oSAMLAttribute.setNamespace(sNameSpace);
            oSAMLAttribute.setName(sName);
            
            if (oValue instanceof Vector)
            {
                Vector vValue = (Vector)oValue;
                Enumeration enumValues = vValue.elements();
                while(enumValues.hasMoreElements())
                    oSAMLAttribute.addValue(enumValues.nextElement());                                
            }
            else
                oSAMLAttribute.addValue(oValue);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not create a SAML attribute object", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
        }
        return oSAMLAttribute;
    }    
}
