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
 */

/* 
 * $Id: AuthSPHandlerManager.java,v 1.3 2006/04/26 12:16:36 tom Exp $ 
 * 
 * Changelog:
 * $Log: AuthSPHandlerManager.java,v $
 * Revision 1.3  2006/04/26 12:16:36  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.1.2.6  2006/04/07 09:52:05  leon
 * java doc
 *
 * Revision 1.1.2.5  2006/04/06 07:49:53  leon
 * improved error handling when handler isn't an instance of interface
 *
 * Revision 1.1.2.4  2006/04/03 12:57:45  erwin
 * - Fixed error handling during initialization.
 * - Removed some warnings
 *
 * Revision 1.1.2.3  2006/03/20 11:20:41  leon
 * function renamed
 *
 * Revision 1.1.2.2  2006/03/16 08:26:21  leon
 * Boolean.parseBoolean(x) changed to Boolean.valueOf(x).booleanValue()
 * to keep compatible with java 1.4
 *
 * Revision 1.1.2.1  2006/03/16 08:05:39  leon
 * New AuthSPHandler handling
 *
 */
 
package org.aselect.server.authspprotocol.handler;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.authspprotocol.IAuthSPDirectLoginProtocolHandler;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMResource;

/**
 * The AuthSPHandler manager for the A-Select Server.
 * <br><br>
 * <b>Description:</b><br>
 * A singleton AuthSPHandler manager, containing the authsp handler configuration.
 * It loads several authsp handler settings in memory during initialize.   
 * <br><br>
 * <b>Concurrency issues:</b>
 * <br>
 * The class is a singleton, so the same class is used in all the classes of 
 * the A-Select Server.
 * <br>
 * @author Alfa & Ariss
 * 
 */
public class AuthSPHandlerManager
{
    private static final String MODULE = "AuthSPHandlerManager";
    private static AuthSPHandlerManager _oAuthSPHandlerManager;
    
    private Hashtable _htAuthSPHandlers;
    private ASelectConfigManager _oASelectConfigManager;
    private SystemLogger _systemLogger;

    /**
     * Must be used to get an AuthSPHandlerManager instance.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Creates a new <code>AuthSPHandlerManager</code> instance if it's still <code>null</code>.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * Always the same instance of the AuthSPHandlerManager is returned, because it's a
     * singleton.
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return A satic handle to the <code>AuthSPHandlerManager</code>.
     */
    public static AuthSPHandlerManager getHandle()
    {
        if (_oAuthSPHandlerManager == null)
        {
            _oAuthSPHandlerManager = new AuthSPHandlerManager();
        }
        return _oAuthSPHandlerManager;
    }
    
    /**
     * Initialization of the AuthSPHandlerManager singleton
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Must be successfully run once, before it can be used.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * - Singleton <code>ASelectConfigManager</code> should be initialized.<BR>
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @throws ASelectException
     */
    public void init() throws ASelectException
    {
       String sMethod = "init()";
       try
       {
           _oASelectConfigManager = ASelectConfigManager.getHandle();
           _systemLogger = ASelectSystemLogger.getHandle();
           Object oAuthSPsConfigSection = null;
           _htAuthSPHandlers = new Hashtable();
           try
           {
               oAuthSPsConfigSection = _oASelectConfigManager
               		.getSection(null, "authsps");
           }
           catch (ASelectConfigException e)
           {
               _systemLogger.log(Level.CONFIG, MODULE, sMethod,
                   "No 'authsps' section found in A-Select config, AuthSP's are disabled");
               return;
           }
           
           Object oAuthSPHandlerConfig = null;
           try
           {
               oAuthSPHandlerConfig = _oASelectConfigManager.getSection(
                   oAuthSPsConfigSection, "authsp");
           }
           catch (ASelectConfigException e)
           {
               _systemLogger.log(Level.CONFIG,MODULE, sMethod,
                   "Not a single 'authsp' section found in A-Select config",e);
               throw e;
           }
           
           while (oAuthSPHandlerConfig != null)
           {
               String sAuthSPId = null;
               String sHandler = null;
               String sResourceGroup = null;
               String sType = null;
               String sFriendlyName = null;
               String sPopup = null;
               String sLevel = null;
               boolean bDirectAuthSP = false;
               try
               {
                   //Get all required parameters.
                   sAuthSPId = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "id");
                   
                   sResourceGroup = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "resourcegroup");
                   
                   sHandler = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "handler");
                   
                   sType = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "type");
                   
                   sFriendlyName = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "friendly_name");

                   sPopup = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "popup");
                   
                   sLevel = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "level");
                                     
               }
               catch(ASelectConfigException e)
               {
                   _systemLogger.log(Level.CONFIG,MODULE, sMethod,
                       "failed to retrieve required parameter for configured authsp.",e);
                   throw e;
               }
               try
               {
                   //Get optional parameters.
                   String sDirectAuthSP = _oASelectConfigManager.getParam(
                       oAuthSPHandlerConfig, "direct_authsp");
                   bDirectAuthSP = Boolean.valueOf(sDirectAuthSP).booleanValue();
               }
               catch(ASelectConfigException e)
               {
                   bDirectAuthSP = false;
               }
               Integer intLevel = null;
               try
               {
                   intLevel = new Integer(sLevel);
               }
               catch(NumberFormatException e)
               {
                   _systemLogger.log(Level.SEVERE, MODULE, sMethod,
                       "Error during initializing", e);
                   throw new ASelectException(Errors.ERROR_ASELECT_AGENT_INTERNAL_ERROR);
               }
               Boolean bPopup = new Boolean(sPopup);
               
               AuthSPHandler oAuthSPHandler = new AuthSPHandler(sAuthSPId, sHandler, sResourceGroup, sType, sFriendlyName,  intLevel, bPopup.booleanValue());
               oAuthSPHandler.setDirectAuthSP(bDirectAuthSP);
               _htAuthSPHandlers.put(sAuthSPId,oAuthSPHandler);
               oAuthSPHandlerConfig = _oASelectConfigManager
                   .getNextSection(oAuthSPHandlerConfig);
           }
       }
       catch(ASelectException e)
       {
           throw e;
       }
       catch(Exception e)
       {
           _systemLogger.log(Level.SEVERE, MODULE, sMethod,
               "Error during initializing", e);
           throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
       }
    }

    /**
     * Get all the configured AuthSP handlers.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns a {@link Vector} object containing the Id's of all configured AuthSP handlers.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @return Vector with all the AuthSP Id's.
     */
    public Vector getConfiguredAuthSPs()
    {
        Vector vResult = new Vector();
        Enumeration enumElements = _htAuthSPHandlers.elements();
        while(enumElements.hasMoreElements())
        {
            AuthSPHandler oAuthSPHandler = (AuthSPHandler)enumElements.nextElement();
            vResult.add(oAuthSPHandler.getId());

        }
        return vResult;
     }
    
    /**
     * Get all the configured AuthSP handlers between two levels.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns a {@link Vector} containing the AuthSP Id's of all configured 
     * AuthSP handlers with an level between the suplied minimum and maximum level.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param intMinLevel Minimum level of the AuthSP Handlers to return. 
     * @param intMaxLevel Maximum level of the AuthSP Handlers to return. 
     * @return Vector with the AuthSP Id's.
     */
    public Vector getConfiguredAuthSPs(Integer intMinLevel, Integer intMaxLevel)
    {
        if(intMaxLevel == null)
        {
            return getConfiguredAuthSPs(intMinLevel);
        }

        Vector vResult = new Vector();
        Enumeration enumElements = _htAuthSPHandlers.elements();
        while(enumElements.hasMoreElements())
        {
            AuthSPHandler oAuthSPHandler = (AuthSPHandler)enumElements.nextElement();
            Integer intLevel = oAuthSPHandler.getLevel();
            if(intLevel.intValue() >= intMinLevel.intValue() && intLevel.intValue() <= intMaxLevel.intValue())
            {
                vResult.add(oAuthSPHandler.getId());
            }
        }
        return vResult;
    }  
    
    /**
     * Get all the configured AuthSP handlers with a minimum level.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns a {@link Vector} containing the AuthSP Id's of all 
     * configured AuthSP handlers with an level higher than the 
     * suplied minimum level.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param intMinLevel Minimum level of the AuthSP Handlers to return. 
     * @return Vector with the AuthSP Id's.
     */
    public Vector getConfiguredAuthSPs(Integer intMinLevel)
    {
        Vector vResult = new Vector();
        Enumeration enumElements = _htAuthSPHandlers.elements();
        while(enumElements.hasMoreElements())
        {
            AuthSPHandler oAuthSPHandler = (AuthSPHandler)enumElements.nextElement();
            Integer intLevel = oAuthSPHandler.getLevel();
            if(intLevel.intValue() >= intMinLevel.intValue())
            {
                vResult.add(oAuthSPHandler.getId());
            }
        }
        return vResult;
    } 
    
    /**
     * Checks if an AuthSP is a DirectAuthSP or not.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns wether an AuthSP is a DirectAuthSP or not and throws an ASelectException if the supplied id doesn't exists.       
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The Id of the AuthSP
     * @return  Returns true if the AuthSP with the given Id is a 
     * Direct Authsp and false if not.
     * @throws ASelectException if AuthSP with sAuthSPId not exists.
     */
    public boolean isDirectAuthSP(String sAuthSPId) throws ASelectException
    {
        String sMethod = "isDirectAuthSP()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.isDirectAuthSP();
    }
    
    /**
     * Returns the Friendly Name of an AuthSP handler.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the Friendly Name of the AuthSP handler with the supplied Id
     * and throws an ASelectException if the supplied id doesn't exists.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The Id of the AuthSP
     * @return The Friendly Name
     * @throws ASelectException
     */
    public String getFriendlyName(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getFriendlyName()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.getFriendlyName();  
    }
    
    /**
     * Returns the class name of the AuthSP Handler.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the class name of the AuthSP Handler.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The Id of the AuthSP
     * @return handler class name.
     * @throws ASelectException
     */
    public String getHandler(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getHandler()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.getHandler();      
    }
    
    /**
     * Returns the type of an AuthSP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns local if it is a local AuthSP and remote if 
     * it is a remote AuthSP. 
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The Id of the AuthSP
     * @return local or remote.
     * @throws ASelectException
     */
    public String getType(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getType()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.getType();  
    }
    
    /**
     * Returns the level of an AuthSP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the level of an AuthSP, 
     * this is a security indicator of the AuthSP, the higher the level the more secure the 
     * AuthSP is.  
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The Id of the AuthSP
     * @return local or remote.
     * @throws ASelectException
     */
    public Integer getLevel(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getLevel()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.getLevel();  
    }
    
    /**
     * Returns the resource group of an AuthSP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the resource group of an AuthSP.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The id of the AuthSP
     * @return local or remote.
     * @throws ASelectException
     */
    public String getResourceGroup(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getResourceGroup()";
        AuthSPHandler oAuthSPHandler = (AuthSPHandler)_htAuthSPHandlers.get(sAuthSPId);
        if(oAuthSPHandler == null)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "No AuthSPHandler found with Id: '"+sAuthSPId+"'.");
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oAuthSPHandler.getResourceGroup();  
    }
    
    /**
     * Returns the URL an AuthSP.
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the URL an AuthSP.
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -)
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The id of the AuthSP
     * @return The URL of the AuthSP
     * @throws ASelectException
     */
    public String getUrl(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getUrl()";
        String sUrl = null;
        String sResourceGroup = getResourceGroup(sAuthSPId);
        SAMResource mySAMResource = null;
        try
        {
            try
            {
                mySAMResource = ASelectSAMAgent.getHandle()
            		.getActiveResource(sResourceGroup);            
	        }
	        catch(ASelectSAMException e)
	        {
	            _systemLogger.log(Level.WARNING,MODULE, sMethod,
	                "No resource retrieved for AuthSP: '"+sAuthSPId+"'.");
	            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
	        }
	        Object objAuthSPResource = mySAMResource.getAttributes();
	        try
	        {
	            sUrl = _oASelectConfigManager.getParam(objAuthSPResource, "url");
	        }
	        catch(ASelectConfigException e)
	        {
	            _systemLogger.log(Level.WARNING,MODULE, sMethod,
	                "No resource retrieved for AuthSP: '"+sAuthSPId+"'.");
	            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
	        }
        }
        catch(ASelectException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _systemLogger.log(Level.WARNING,MODULE, sMethod,
                "Exception occured",e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return sUrl;
    }
    
    /**
     * Returns the handler which is able to handle direct_login requests
     * <br><br>
     * <b>Description:</b>
     * <br>
     * Returns the handler which is able to handle direct_login requests
     * <br><br>
     * <b>Concurrency issues:</b>
     * <br>
     * -
     * <br><br>
     * <b>Preconditions:</b>
     * <br>
     * -
     * <br><br>
     * <b>Postconditions:</b>
     * <br>
     * -
     * <br>
     * @param sAuthSPId The id of the AuthSP
     * @return IAuthSPDirectLoginProtocolHandler
     * @throws ASelectException
     */
    public IAuthSPDirectLoginProtocolHandler getAuthSPDirectLoginProtocolHandler(String sAuthSPId) throws ASelectException
    {
        String sMethod = "getAuthSPAPIProtocolHandler()";
        IAuthSPDirectLoginProtocolHandler oProtocolHandler = null;
        String sHandlerName = getHandler(sAuthSPId);
        try
        {
            Class oClass = Class.forName(sHandlerName);
            Object oInstance  = oClass.newInstance();
            if(!(oInstance instanceof IAuthSPDirectLoginProtocolHandler))
            {
                _systemLogger.log(Level.SEVERE, MODULE, sMethod, "Failed to initialize handler AuthSPHandler, " +
                        "because handler: '"+sHandlerName+"' is not an instance of IAuthSPDirectLoginProtocolHandler");
                throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            oProtocolHandler = (IAuthSPDirectLoginProtocolHandler)oInstance;
            oProtocolHandler.init(sAuthSPId);
        }
        catch(ASelectException e)
        {
            // allready handled
            throw e;
        }
        catch(ClassNotFoundException e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod,
                "Failed to initialize IAuthSPDirectLoginProtocolHandler due to class not found exception", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        catch (Exception e)
        {
            _systemLogger.log(Level.SEVERE, MODULE, sMethod,
                "Failed to initialize IAuthSPDirectLoginProtocolHandler due to unhandled exception", e);
            throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
        }
        return oProtocolHandler;
    }
}
