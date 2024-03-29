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
 * $Id: GenericAttributeRequestor.java,v 1.6 2006/04/26 12:15:59 tom Exp $ 
 * 
 * Changelog:
 * $Log: GenericAttributeRequestor.java,v $
 * Revision 1.6  2006/04/26 12:15:59  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.5  2005/03/24 14:36:58  erwin
 * Improved Javadoc.
 *
 * Revision 1.4  2005/03/17 10:25:28  martijn
 * added ASelectSAMAgent
 *
 * Revision 1.3  2005/03/17 10:13:43  martijn
 *
 * Revision 1.2  2005/03/17 10:06:20  erwin
 * Removed abstract method.
 *
 * Revision 1.1  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 */
package org.aselect.server.attributes.requestors;

import java.util.HashMap;
import java.util.logging.Level;

import org.aselect.server.attributes.AttributeGatherer;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * A base class for attribute requestors. <br>
 * <br>
 * <b>Description:</b><br>
 * This base class for attribute requestors contains the default managers and a system logger. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public abstract class GenericAttributeRequestor implements IAttributeRequestor
{
	/** The configuration */
	protected ASelectConfigManager _configManager;
	/** The SAM agent. */
	protected ASelectSAMAgent _samAgent;
	/** The logger for system entries. */
	protected ASelectSystemLogger _systemLogger;

	private static final String MODULE = "GenericAttributeRequestor";
	
	protected String _sUseKey = null;
	protected boolean _bFromTgt = false;
	protected int _iGathererVersion = -1;
	protected boolean bAllowresultsetaccumulation = false;	// RH, 20150922, n	// allows for multiple search results to map onto single multi valued attribute

	/**
	 * The default constructor. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieves handles to managers and the logger. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <ul>
	 * <li><code>_configManager != null</code></li>
	 * <li><code>_samAgent != null</code></li>
	 * <li><code>_systemLogger != null</code></li>
	 * </ul>
	 */
	public GenericAttributeRequestor()
	{
		_configManager = ASelectConfigManager.getHandle();
		_samAgent = ASelectSAMAgent.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
	}
	
	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		String sID = _configManager.getParam(oConfig, "id");					
		_sUseKey = ASelectConfigManager.getSimpleParam(oConfig, "use_key", false);
		if (!Utils.hasValue(_sUseKey)) {
			_sUseKey = ASelectConfigManager.getSimpleParam(oConfig, "use_tgt_key", false);
			if (!Utils.hasValue(_sUseKey))
				_sUseKey = "uid";
			_bFromTgt = true;
		}
		// RH, 20150922, sn
		String _sAllowresultsetaccumulation = ASelectConfigManager.getSimpleParam(oConfig, "allow_resultset_accumulation", false);
		bAllowresultsetaccumulation = Boolean.parseBoolean(_sAllowresultsetaccumulation);
		// RH, 20150922, en
		_iGathererVersion = AttributeGatherer.getHandle().getGathererVersion();
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "Requestor id="+sID+" version="+_iGathererVersion+" use_key="+_sUseKey+" tgt="+_bFromTgt);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Requestor id="+sID+" version="+_iGathererVersion+" use_key="+_sUseKey+" tgt="+_bFromTgt + " allow_resultset_accumulation=" + bAllowresultsetaccumulation);
}
	
	/**
	 * Gather a user's organizations. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Default implementation, reports not implemented <br>
	 * Should be overridden by gatherers that want to support this feature.<br>
	 * @param htTGTContext
	 *         the TGT context.
	 * @return null result.
	 * @throws ASelectAttributesException
	 *         If gathering fails.
	 */
	public HashMap<String,String> getOrganizations(HashMap htTGTContext)
	throws ASelectAttributesException
	{
		final String sMethod = "getOrganizations";
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Not supported by this Attribute Gatherer");
		return null;
	}
}
