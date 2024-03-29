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
package org.aselect.system.storagemanager.handler;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.storagemanager.IStorageHandler;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * Concurrent Memory storage handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * The MemoryStorageHandler uses a <code>HashMap</code> for storing objects in memory. <br>
 * <br>
 * In the MemoryStorageHandler an additional HashMap is created in which information about the stored record is kept:
 * <code><pre>
 * 
 *  HashMap htStorage { 
 *  	key: Object xKey 
 *  	value: HashMap htStorageContainer {
 *  		key: String &quot;timestamp&quot; value: Long xTimestamp
 *  		key: String &quot;contents&quot; value: Object xValue } 
 *  }
 */
public class MemoryStorageHandler implements IStorageHandler
{
	/** The module name. */
	public final static String MODULE = "MemoryStorageHandler";

	/** The actual storage */
	private ConcurrentHashMap _htStorage;

	/** The logger that is used for system entries */
	private SystemLogger _systemLogger;
	
	private ConfigManager _configManager;
	
	/**
	 * Initialize the <code>MemoryStorageHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> Initalises the <code>MemoryStorageHandler</code>:
	 * <ul>
	 * <li>Set system logger</li>
	 * <li>create new storage <code>HashMap</code></li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>systemLogger != null</code></li> <br>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>All instance variables are set</li>
	 * <li>A new storage <code>Hashmap</code> is created</li>
	 * </ul>
	 * 
	 * @param oConfigSection
	 *            the o config section
	 * @param oConfigManager
	 *            the o config manager
	 * @param systemLogger
	 *            the system logger
	 * @param oSAMAgent
	 *            the o sam agent
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#init(java.lang.Object,
	 *      org.aselect.system.configmanager.ConfigManager, org.aselect.system.logging.SystemLogger,
	 *      org.aselect.system.sam.agent.SAMAgent)
	 */
	public void init(Object oConfigSection, ConfigManager oConfigManager, SystemLogger systemLogger, SAMAgent oSAMAgent)
	throws ASelectStorageException
	{
		_systemLogger = systemLogger;
		_htStorage = new ConcurrentHashMap(200);
		_configManager = oConfigManager;
	}

	/**
	 * Get a object from memory.
	 * 
	 * @param oKey
	 *            the key object
	 * @return the object
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#get(java.lang.Object)
	 */
	public Object get(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "get";
		Object oValue = null;

		String sTxt = Utils.firstPartOf(oKey.toString(), 30);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "key="+sTxt); // +" store="+_htStorage);
		try {
			HashMap htStorageContainer = (HashMap) _htStorage.get(oKey);
			if (htStorageContainer != null) {
				oValue = htStorageContainer.get("contents");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH get(" + sTxt + ") -->" + Auxiliary.obfuscate(htStorageContainer));
			}
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Not found: " + sTxt);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}

		if (oValue == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Key "+sTxt+" was not found, cause: "
					+ Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
		}
		return oValue;
	}

	/**
	 * Retrieve an object's timestamp from storage. <br>
	 * <br>
	 * 
	 * @param oKey
	 *            the o key
	 * @return the timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getTimestamp(java.lang.Object)
	 */
	public long getTimestamp(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "getTimestamp";
		long lTimestamp = 0;

		try {
			// synchronized (_htStorage) {
			HashMap htStorageContainer = (HashMap) _htStorage.get(oKey);
			Long lValue = (Long) htStorageContainer.get("timestamp");
			lTimestamp = lValue.longValue();
			//_systemLogger.log(Level.FINER, MODULE, sMethod, "Timestamp=" + lTimestamp);
			// }
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Empty (null) key-object was supplied.");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}

		if (lTimestamp == 0) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value,cause: "
					+ Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
		}
		return lTimestamp;
	}

	// added 1.5.4
	/**
	 * Returns the number of objects stored in memory.
	 * 
	 * @return the count
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getCount()
	 */
	public long getCount()
	throws ASelectStorageException
	{
		return _htStorage.size();
	}

	/**
	 * Get all objects from memory table.
	 * 
	 * @return the all
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getAll()
	 */
	public HashMap getAll()
	throws ASelectStorageException
	{
		String sMethod = "getAll";
		HashMap htReturnTable = new HashMap();
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "this=" + this); // +" store="+_htStorage);

		// synchronized (_htStorage) {
		Enumeration eKeys = _htStorage.keys();
		while (eKeys.hasMoreElements()) {
			Object oKey = eKeys.nextElement();

			HashMap htStorageContainer = (HashMap) _htStorage.get(oKey);
			Object oValue = htStorageContainer.get("contents");
			htReturnTable.put(oKey, oValue);
		}
		// }
		return htReturnTable;
	}

	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	public void put(Object oKey, Object oValue, Long lTimestamp, IStorageHandler.UpdateMode eMode)
	throws ASelectStorageException
	{
		// RM_70_01
		// For now we just call the old one
		switch (eMode) {
		case INSERTFIRST: // do insert first
			put(oKey, oValue, lTimestamp);
			break;
		case UPDATEFIRST: // do updatefirst
			put(oKey, oValue, lTimestamp);
			break;
		case INSERTONLY: // do create, throw exception if key exists
			synchronized (_htStorage) {
				if ( containsKey(oKey) ) {
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_DUPLICATE_KEY);
				} else {
					put(oKey, oValue, lTimestamp);
				}
			}
			break;
		default:	// do the old stuff for backward compatibility
			put(oKey, oValue, lTimestamp);
			break;
		}
	
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////	
	
	
	
	/**
	 * Put object in memory.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	public void put(Object oKey, Object oValue, Long lTimestamp)
	throws ASelectStorageException
	{
		String sMethod = "put";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "this=" + this); // +" store="+_htStorage);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH put(" + Utils.firstPartOf(oKey.toString(), 30) + ") ="
//				+ oValue.toString() + " TS=" + lTimestamp);
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH put(" + Utils.firstPartOf(oKey.toString(), 30) + ") ="
//				+ Auxiliary.obfuscate(oValue.toString()) + " TS=" + lTimestamp);

		HashMap htStorageContainer = new HashMap();
		try {
			htStorageContainer.put("timestamp", lTimestamp);
			htStorageContainer.put("contents", oValue);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH put(" + Utils.firstPartOf(oKey.toString(), 30) + ") ="
					+ Auxiliary.obfuscate(htStorageContainer) + " TS=" + lTimestamp);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied value was null", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eNP);
		}
		try {
			// synchronized (_htStorage) {
			_htStorage.put(oKey, htStorageContainer);
			// }
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object supplied", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, eNP);
		}
	}

	/**
	 * Remove an object from memory storage.
	 * 
	 * @param oKey
	 *            the o key
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#remove(java.lang.Object)
	 */
	public void remove(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "remove";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, " this=" + this); // +" "+_htStorage);
		_systemLogger.log(Level.FINER, MODULE, sMethod, "MSH remove(" + Utils.firstPartOf(oKey.toString(), 30) + ") ");
		try {
			// synchronized (_htStorage) {
			if (_htStorage.remove(oKey) == null) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not remove object: " + oKey);
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
			// }
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object supplied", eNP);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, eNP);
		}
	}

	/**
	 * Remove all objects from memmory table.
	 * 
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#removeAll()
	 */
	public void removeAll()
	throws ASelectStorageException
	{
		// synchronized (_htStorage) {
		_htStorage.clear();
		// }
	}

	/**
	 * Removes the objects from memory table that have been expired.
	 * 
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#cleanup(java.lang.Long)
	 */
	public void cleanup(Long lTimestamp)
	throws ASelectStorageException
	{
		String sMethod = "cleanup";
		int countAll = 0, countRemoved = 0;

		_systemLogger.log(Level.FINER, MODULE, sMethod, " CleanupTime=" + lTimestamp);
		// synchronized (_htStorage) {
		Enumeration eKeys = _htStorage.keys();
		while (eKeys.hasMoreElements()) {
			Object oKey = eKeys.nextElement();

			countAll++;
			HashMap htStorageContainer = (HashMap)_htStorage.get(oKey);
			Long lStorageTime = (Long)htStorageContainer.get("timestamp");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "StorageTime=" + lStorageTime);

			if (lTimestamp.longValue() >= lStorageTime.longValue()) {
				// Try, report left-over sessions
				
//				HashMap hm = (HashMap)htStorageContainer.get("contents");	// RH, 20130614, o 	// unfortunately we cannot be sure this is a HashMap
				if ( htStorageContainer.get("contents") instanceof HashMap) {	// RH, 20130614, n 	// so test first
					HashMap hm = (HashMap)htStorageContainer.get("contents");
					String sFirstContact = (String)hm.get("first_contact");
					if (sFirstContact != null) {  // it's a session
						Tools.calculateAndReportSensorData(_configManager, _systemLogger, "srv_mem", (String)oKey, hm, null, false);
					}
				}
				_htStorage.remove(oKey);
				countRemoved++;
				String sTxt = Utils.firstPartOf(oKey.toString(), 30);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "MSH Key=" + sTxt + " TimeStamp=" + lStorageTime
						+ " Left=" + (lStorageTime - lTimestamp) + " removed");
			}
		}
		// }
		int countLeft = countAll - countRemoved;
		_systemLogger.log(Level.FINER, MODULE, sMethod, " CleanupTime=" + lTimestamp + " total was " + countAll
				+ " removed " + countRemoved + " left " + countLeft);
	}

	/**
	 * Clear the storage <code>HashMap</code>.
	 * 
	 * @see org.aselect.system.storagemanager.IStorageHandler#destroy()
	 */
	public void destroy()
	{
		if (_htStorage != null) {
			_htStorage.clear();
			_htStorage = null;
		}
	}

	/**
	 * Checks if the configured maximum items is reached. <br>
	 * <br>
	 * 
	 * @param lItemCount
	 *            the l item count
	 * @return true, if checks if is maximum
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#isMaximum(long)
	 */
	public boolean isMaximum(long lItemCount)
	throws ASelectStorageException
	{
		return (_htStorage.size() >= lItemCount);
	}

	/**
	 * Checks if the supplied key already exists in the <code>HashMap</code> <br>
	 * <br>
	 * .
	 * 
	 * @param oKey
	 *            the o key
	 * @return true, if contains key
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#containsKey(java.lang.Object)
	 */
	public boolean containsKey(Object oKey)
	throws ASelectStorageException
	{
		_systemLogger.log(Level.FINER, MODULE, "containsKey", "Key=" + Utils.firstPartOf(oKey.toString(), 30));
		return _htStorage.containsKey(oKey);
	}
}