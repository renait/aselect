package org.aselect.authspserver.session;

import java.util.logging.Level;

import org.aselect.authspserver.config.AuthSPConfigManager;
import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.authspserver.sam.AuthSPSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.storagemanager.StorageManager;

public class PersistentStorageManager extends StorageManager
{

	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "PersistentStorageManager";
	
	/** The logger for system log entries. */
	private SystemLogger _systemLogger;

	private String id = null;

	private PersistentStorageManager() {
	
	}

	public PersistentStorageManager(String id) {
		this.id = id;
	}

	/**
	 * Initializes the <code>PersistentStorageManager</code>. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Read configuration settings and initializes the components. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * The instance variables and components are initialized. <br>
	 * 
	 * @throws ASelectException
	 *             If initialization fails.
	 * @throws ASelectConfigException
	 *             If one or more mandatory configuration settings are missing or invalid.
	 */
	public void init()
	throws ASelectException, ASelectConfigException
	{
		String sMethod = "init";
		try {
			_systemLogger = AuthSPSystemLogger.getHandle();
			AuthSPConfigManager oConfigManager = AuthSPConfigManager.getHandle();

			Object oSessionConfig = null;
			try {
				oSessionConfig = oConfigManager.getSection(null, "storagemanager", "id=" + id);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No 'storagemanager' section with id=" + id + " found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			super.init(oSessionConfig, oConfigManager, _systemLogger, AuthSPSAMAgent.getHandle());
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Session manager Successfully started.");
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

}
