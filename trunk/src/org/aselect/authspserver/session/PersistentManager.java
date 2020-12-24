/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */

package org.aselect.authspserver.session;

import java.util.HashMap;
import java.util.Map;

import org.aselect.system.exception.ASelectException;

public class PersistentManager
{

	/**
	 * The name of this module, that is used in the system logging.
	 */
	private static final String MODULE = "PersistentManager";
	

	private String id = null;
	private static Map<String, PersistentStorageManager> _mPersistentStorageManagers = new HashMap<String, PersistentStorageManager>();

	private PersistentManager() {
	
	}

	// We use this Map so we don't have to initialize the storagemanager for every bind call
	public static PersistentStorageManager getHandle(String id) throws ASelectException
	{
		if (_mPersistentStorageManagers.get(id) == null) {
			PersistentStorageManager oPersistentStorageManager = new PersistentStorageManager(id);
			oPersistentStorageManager.init();
			_mPersistentStorageManagers.put(id, oPersistentStorageManager);
		}
		return _mPersistentStorageManagers.get(id);
	}
}
