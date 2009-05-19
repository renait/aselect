package org.aselect.lbsensor;

import java.io.File;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

public class LbSensorConfigManager extends ConfigManager
{
	private final String MODULE = "LbSensorConfigManager";

	// The singleton instance
	private static LbSensorConfigManager _oLbSensorConfigManager;

	// The system logger
	private LbSensorSystemLogger _systemLogger;
	
	// The working directory
	private String _sWorkingDir = null;

	// The private constructor forces a singleton
	private LbSensorConfigManager() {
	}

	// Return the singleton class
	public static LbSensorConfigManager getHandle()
	{
		if (_oLbSensorConfigManager == null)
			_oLbSensorConfigManager = new LbSensorConfigManager();

		return _oLbSensorConfigManager;
	}

	/**
	 * Initialize the configuration.
	 *    
	 * @param sWorkingDir The working directory.
	 */
	public void init(String sWorkingDir)
	throws ASelectConfigException, ASelectException
	{
		final String sMethod = "init";
		
		_sWorkingDir = sWorkingDir;
		_systemLogger = LbSensorSystemLogger.getHandle();

		StringBuffer sb = new StringBuffer(_sWorkingDir).append(File.separator).append("lbsensor.xml");
		_systemLogger.log(Level.INFO, MODULE, sMethod, "xml="+sb);
		super.init(sb.toString(), _systemLogger);
	}

	// Convenience function
	public String getParamFromSection(Object oConfig, String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getParamFromSection(getHandle(), LbSensorSystemLogger.getHandle(),
								oConfig, sSection, sParam, bMandatory);
	}

	// Convenience function
	public Object getSimpleSection(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSimpleSection(getHandle(), LbSensorSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public String getSimpleParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleParam(getHandle(), LbSensorSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public int getSimpleIntParam(Object oConfig, String sParam, boolean bMandatory)
	throws ASelectException
	{
		return Utils.getSimpleIntParam(getHandle(), LbSensorSystemLogger.getHandle(),
								oConfig, sParam, bMandatory);
	}

	// Convenience function
	public Object getSectionFromSection(Object oConfig, String sParam, String sValue, boolean bMandatory)
	throws ASelectConfigException
	{
		return Utils.getSectionFromSection(getHandle(), LbSensorSystemLogger.getHandle(),
								oConfig, sParam, sValue, bMandatory);
	}

}
