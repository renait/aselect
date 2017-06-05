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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;

import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.db.connection.IConnectionHandler;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.sam.agent.SAMAgent;
import org.aselect.system.sam.agent.SAMResource;
import org.aselect.system.storagemanager.IStorageHandler;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * DBMS storage handler. <br>
 * <br>
 * <b>Description: </b> <br>
 * The JDBCStorageHandler uses a DBMS for physical storage. <br>
 * <br>
 * The DBMS is accessed through JDBC. Objects that are written to the DBMS are encoded to bytes, using the
 * <code>ObjectOutputStream</code> mechanism of Java. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * -<br>
 * 
 * @author Alfa & Ariss
 */
public class JDBCMapStorageHandler implements IStorageHandler
{
	private static final String DEFAULT_CONNECTION_HANDLER = "org.aselect.system.db.connection.impl.NonClosingConnectionHandler";
	// private static final String DEFAULT_CONNECTION_HANDLER =
	// "org.aselect.system.db.connection.impl.ClosingConnectionHandler";
	protected static final String DEFAULTIDENTIFIERQUOTE = "\""; // use double-quote as default
	protected String identifierQuote = DEFAULTIDENTIFIERQUOTE;

	/** name of this module, used for logging */
	protected static final String MODULE = "JDBCMapStorageHandler";

	/** The database connection. */
	// protected Connection _oActiveConnection;

	/** The active SAM resource. */
	protected SAMResource _oActiveResource;

	/** The database table name. */
	protected String _sTableName;

	/** The resource group containing database connection information */
	protected String _sResourceGroup;


	/** The context timestamp */
	protected String _sContextTimestamp;

	/** The context key name (no quotation */
	protected String _sContextKeyName;

	/** The context key */
	protected String _sContextKey;


	/** The logger that is used for system entries */
	protected SystemLogger _systemLogger;

	/** The configuration. */
	protected ConfigManager _oConfigManager;

	/** The SAM agent. */
	protected SAMAgent _oSAMAgent;

	protected IConnectionHandler _oConnectionHandler;
	protected Class cClass;

	/**
	 * Initialize the <code>JDBCStorageHandler</code>. <br>
	 * <br>
	 * <b>Description: </b> Initalises the <code>JDBCStorageHandler</code>:
	 * <ul>
	 * <li>Set system logger and managers</li>
	 * <li>Reads the necessary configuration</li>
	 * <li>Initialise the database connection</li>
	 * </ul>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * -<br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oConfigSection != null</code></li>
	 * <li><code>oConfigManager != null</code></li>
	 * <li><code>systemLogger != null</code></li>
	 * <li><code>oSAMAgent != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b>
	 * <ul>
	 * <li>All instance variables are set</li>
	 * <li>The database is connected</li>
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
		String sMethod = "init";
		Object oTableSection = null;

		try {
			_systemLogger = systemLogger;
			_oConfigManager = oConfigManager;
			_oSAMAgent = oSAMAgent;

			try {
				_sResourceGroup = oConfigManager.getParam(oConfigSection, "resourcegroup");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found resourcegroup: " + _sResourceGroup);
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'resourcegroup' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			if (_oActiveResource == null || !_oActiveResource.live()	 ||	!_oActiveResource.getId().equals(  _oSAMAgent.getActiveResource(_sResourceGroup).getId() ) 	)	// RH, 20131125, n
				_oActiveResource = _oSAMAgent.getActiveResource(_sResourceGroup);
			Object oResourceConfigSection = _oActiveResource.getAttributes();
			try {
				String _connHandler = _oConfigManager.getParam(oResourceConfigSection, "connectionhandler");
				systemLogger.log(Level.INFO, MODULE, sMethod, "Found connectionhandler: " + _connHandler);
				cClass = Class.forName(_connHandler);
			}
			catch (ASelectConfigException ace) {
				systemLogger.log(Level.INFO, MODULE, sMethod,
						"No connectionhandler given in the configuration file, using '"+DEFAULT_CONNECTION_HANDLER+"'");
				cClass = Class.forName(DEFAULT_CONNECTION_HANDLER);
			}

			_oConnectionHandler = (IConnectionHandler) cClass.newInstance();
			systemLogger.log(Level.INFO, MODULE, sMethod, "Using connectionhandler: " + _oConnectionHandler.getClass().getCanonicalName());
			_oConnectionHandler.Init(_oConfigManager, _systemLogger, _oSAMAgent, _sResourceGroup);

			// This also prepares the connection
			String intentifierQuoteString = getConnection().getMetaData().getIdentifierQuoteString();
			// getIdentifierQuoteString() returns " " (space) if quoting is unsupported
			if (intentifierQuoteString != null)
				identifierQuote = intentifierQuoteString.trim();

			try {
				oTableSection = oConfigManager.getSection(oConfigSection, "table");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'table' config section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sTableName = identifierQuote + oConfigManager.getParam(oTableSection, "name") + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'name' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextTimestamp = identifierQuote + oConfigManager.getParam(oTableSection, "timestamp")
						+ identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"No valid 'timestamp' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			try {
				_sContextKeyName =  oConfigManager.getParam(oTableSection, "key");
				_sContextKey = identifierQuote +_sContextKeyName + identifierQuote;
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No valid 'key' config item in 'table' section found");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "The JDBC IStorageHandler could not be initialized");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Returns a particular object from the database.
	 * 
	 * @param oKey
	 *            the o key
	 * @return the object
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#get(java.lang.Object)
	 */
	public Object get(Object oKey)
	throws ASelectStorageException
	{
		String sMethod = "get";
		Object oRet = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {

			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append("*").append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?"); // new
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer);  // 20120405: + " -> " + oKey);

			oConnection = getConnection();
			oStatement = oConnection.prepareStatement(sbBuffer.toString());

			oStatement.setObject(1, oKey); // must have valid type after standard mapping
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) { // record exists.

				HashMap<String, Object> reslt = new HashMap<String, Object>();
				ResultSetMetaData meta = oResultSet.getMetaData();
				int noc = meta.getColumnCount();
				while  (noc > 0) {
					reslt.put(meta.getColumnName(noc), oResultSet.getObject(noc));
					noc--;
				}
				oRet = reslt;
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "result=" + Auxiliary.obfuscate(oRet));
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "The supplied key is not mapped to any value.");
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object was supplied");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}
		catch (Exception e) {
			//_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null) {
					oResultSet.close();
				}
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.");
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
		if (oRet == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
		}
		return oRet;
	}

	/**
	 * Retrieve an object its timestamp from storage. <br>
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
		long lRet = 0;
		PreparedStatement oStatement = null;
		Connection oConnection = null;
		ResultSet oResultSet = null;
		StringBuffer sbQuery = new StringBuffer();

		try {
			int iKey = 0; // oKey.hashCode();

			sbQuery.append("SELECT ").append(_sContextTimestamp).append(" ");
			sbQuery.append("FROM ").append(_sTableName).append(" ");
			sbQuery.append("WHERE ").append(_sContextKey).append(" = ?");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbQuery + " -> " + iKey + " key=" + oKey);

			oConnection = getConnection();
			oStatement = oConnection.prepareStatement(sbQuery.toString());
			oStatement.setObject(1, oKey); // must have valid type after standard mapping
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) // record exists.
			{
				Timestamp oTimestamp = oResultSet.getTimestamp(1);
				lRet = oTimestamp.getTime();
			}
			else {
				StringBuffer sbError = new StringBuffer("The supplied key is not mapped to any value - key: ");
				sbError.append(oKey);
				_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer(
					"Could not resolve the timestamp from the JDBC database by executing the query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString());
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (NullPointerException eNP) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Empty (null) key-object was supplied");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, eNP);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve the object from the database");
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null) {
					oResultSet.close();
				}
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.");
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}

		}
		if (lRet == 0) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The supplied key is not mapped to any value",
					new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE));
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE);
		}
		return lRet;
	}

	/**
	 * Returns the number of objects stored in the table.
	 * 
	 * @return the count
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getCount()
	 */
	public long getCount()
	throws ASelectStorageException
	{
		String sMethod = "getCount";
		long lCount = -1;
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT COUNT(*) ").append("FROM ").append(_sTableName);

			oConnection = getConnection();
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oResultSet = oStatement.executeQuery();

			while (oResultSet.next()) {
				lCount = oResultSet.getLong(1);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while retrieving objects from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally { // RH, 20090604, sn
				_oConnectionHandler.releaseConnection(oConnection);
			} // RH, 20090604, en

		}
		return lCount;
	}

	/**
	 * Returns all the objects stored in the table.
	 * 
	 * @return the all
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#getAll()
	 */
	public HashMap getAll()
	throws ASelectStorageException
	{
		// NOT yet implemented!
		HashMap htResponse = new HashMap();
		return htResponse;
	}

	public void put(Object oKey, Object oValue, Long lTimestamp, IStorageHandler.UpdateMode eMode)
	throws ASelectStorageException
	{
		String sMethod = "put(), with MODE flag";
		// RM_69_02
		switch (eMode) {
		case INSERTFIRST: // do insert first
			_systemLogger.log(Level.FINER, MODULE, sMethod,
					"Doing put with eMode INSERTFIRST" );
			try {
				create(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				// If create fails we try update
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"INSERTFIRST fails where it should succeed, trying update" );
				try {
					update(oKey, oValue, lTimestamp);
				}
				catch (SQLException e1) {
					// If update also fails we throw an ASelectStorageException
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Could not insert or update",  e1);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT,  e1);
				}
			}
			break;
		case UPDATEFIRST: // do updatefirst
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode UPDATEFIRST" );
			try {
				update(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"UPDATEFIRST fails where it should succeed, trying create" );
				try {
					create(oKey, oValue, lTimestamp);
				}
				catch (SQLException e1) {
					// If create also fails we throw an ASelectStorageException
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
							"Could not update or insert",  e1);
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT,  e1);
				}
			}
			break;
		case INSERTONLY: // do only insert, throw exception on duplicate key
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode INSERTONLY" );
			try {
				create(oKey, oValue, lTimestamp);
			}
			catch (SQLException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
				"INSERTONLY fails where it should succeed, might be duplicate key" );
				// Is this a duplicate key?
				if (containsKey(oKey)) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Insert on duplicate key attempt, resuming" );
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_DUPLICATE_KEY);
				} else {
					throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT);
				}
			}
			break;
		default:	// do the old stuff for backward compatibility
			_systemLogger.log(Level.FINER, MODULE, sMethod,
			"Doing put with eMode default" );
			put(oKey, oValue, lTimestamp);
			break;
		}
	}

	/**
	 * Inserts a particular object into the database.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException 
	 *             the a select storage exception
	 * @throws SQLException
	 * 				if not exactly one row was affected, e.g. if duplicate key was encountered
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	private void create(Object oKey, Object oValue, Long lTimestamp)
	throws SQLException, ASelectStorageException
	{
		String sMethod = "create";
		Connection oConnection = null;
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			StringBuffer sbBuffer = new StringBuffer();
			oConnection = getConnection();
			
			sbBuffer = new StringBuffer();
			sbBuffer.append("INSERT INTO ").append(_sTableName).append(" ");
			sbBuffer.append("( ");
			// Map holds no order, LinkedHashMap should
			 LinkedHashMap<String, Object> values = new LinkedHashMap<String, Object>((Map)oValue);
			String[] columnames = values.keySet().toArray(new String[values.keySet().size()]);
			StringBuffer qMarks = new StringBuffer();
			for (int i=0; i<columnames.length; i++) {
				if (i>0) {
					sbBuffer.append(", ");
					qMarks.append(",");
				}
				sbBuffer.append(identifierQuote + columnames[i] + identifierQuote);
				qMarks.append("?");
			}
			sbBuffer.append(") ");
			sbBuffer.append("VALUES (" +qMarks.toString() + ")");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + Auxiliary.obfuscate(oValue));

			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			int noc =columnames.length;;
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "number of columns=" + noc);
			while (noc > 0) {
				oStatement.setObject(noc, values.get(columnames[--noc]));
			}
			int rowsAffected = oStatement.executeUpdate();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Rows affected -> " + rowsAffected);
			if (rowsAffected != 1) {
				throw new SQLException("Invalid number of rows affected");
			}
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	
	/**
	 * Updates a particular object in the database.
	 * 
	 * @param oKey
	 *            the o key
	 * @param oValue
	 *            the o value
	 * @param lTimestamp
	 *            the l timestamp
	 * @throws ASelectStorageException 
	 *             the a select storage exception
	 * @throws SQLException
	 * 				if not exactly one row was affected
	 * @see org.aselect.system.storagemanager.IStorageHandler#put(java.lang.Object, java.lang.Object, java.lang.Long)
	 */
	private void update(Object oKey, Object oValue, Long lTimestamp)
	throws SQLException, ASelectStorageException
	{
		String sMethod = "update";
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			StringBuffer sbBuffer = new StringBuffer();
			oConnection = getConnection(); // RH, 20090604, n
				sbBuffer = new StringBuffer();
				sbBuffer.append("UPDATE ").append(_sTableName).append(" ");
				sbBuffer.append("SET ");

				// Map holds no order, LinkedHashMap should
				 LinkedHashMap<String, Object> values = new LinkedHashMap<String, Object>((Map)oValue);
				String[] columnames = values.keySet().toArray(new String[values.keySet().size()]);
				for (int i=0; i<columnames.length; i++) {
					if (i>0) {
						sbBuffer.append(", ");
					}
					sbBuffer.append(identifierQuote + columnames[i] + identifierQuote).append(" = ? ");
				}
				sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + Auxiliary.obfuscate(oValue));

				oStatement = oConnection.prepareStatement(sbBuffer.toString());
				int noc =columnames.length;;
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "number of columns=" + noc);
				oStatement.setObject(noc+1, oKey);	// set the key
				while (noc > 0) {
					oStatement.setObject(noc, values.get(columnames[--noc]));
				}

			int rowsAffected = oStatement.executeUpdate();
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Rows affected -> " + rowsAffected);
			if (rowsAffected != 1) {
				throw new SQLException("Invalid number of rows affected");
			}
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	/**
	 * Inserts a particular object into the database.
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
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;

		try {
			StringBuffer sbBuffer = new StringBuffer();
			sbBuffer.append("SELECT ").append(_sContextTimestamp).append(" ");
			sbBuffer.append("FROM ").append(_sTableName).append(" ");
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + Auxiliary.obfuscate(oValue));

			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.setObject(1, oKey); // new
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) { // record exists.

				try {
					oResultSet.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource ResultSet", e);
				}
				try {
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource Statement", e);
				}
				_oConnectionHandler.releaseConnection(oConnection);

				// do update
				update(oKey, oValue, lTimestamp);

				
			}
			else { // new record.
				try {
					oResultSet.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource ResultSet", e);
				}
				try {
					oStatement.close();
				}
				catch (SQLException e) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource Statement", e);
				}
				_oConnectionHandler.releaseConnection(oConnection);
				create(oKey, oValue, lTimestamp);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while inserting objects into the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_INSERT, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	/**
	 * Removes a particular object from the database.
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
		StringBuffer sbBuffer = null;
		Connection oConnection = null;
		PreparedStatement oStatement = null;
		int iKey = 0; // oKey.hashCode();
		_systemLogger.log(Level.FINER, MODULE, sMethod, " -> " + iKey + " key=" + oKey);

		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName).append(" ");
			sbBuffer.append("WHERE ").append(_sContextKey).append(" = ?");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer + " -> " + iKey + " key=" + oKey);

			oConnection = getConnection();

			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.setObject(1, oKey); // oKey must have valid type for database column after standard mapping
			if (oStatement.executeUpdate() == 0) {
				StringBuffer sbError = new StringBuffer("Could not remove object: ");
				sbError.append(oKey);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString());
				throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_NO_SUCH_KEY);
			}
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while removing an object from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	/**
	 * Removes all the stored objects from the database.
	 * 
	 * @throws ASelectStorageException
	 *             the a select storage exception
	 * @see org.aselect.system.storagemanager.IStorageHandler#removeAll()
	 */
	public void removeAll()
	throws ASelectStorageException
	{
		String sMethod = "removeAll";
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		try {
			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbBuffer);

			oConnection = getConnection(); 
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.executeUpdate();
		}
		catch (ASelectStorageException eAS) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not decode one or more objects that were retrieved from the database.", eAS);
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"An error occured while removing objects from the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_REMOVE, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	/**
	 * Removes the objects from the database that have expired.
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
		StringBuffer sbBuffer = null;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		try {
			Timestamp oTimestamp = new Timestamp(lTimestamp.longValue());

			sbBuffer = new StringBuffer();
			sbBuffer.append("DELETE FROM ").append(_sTableName).append(" ");
			sbBuffer.append("WHERE ").append(_sContextTimestamp).append(" <= ?");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "sql=" + sbBuffer + " -> " + lTimestamp); 

			oConnection = getConnection(); // RH, 20090604, n
			oStatement = oConnection.prepareStatement(sbBuffer.toString());
			oStatement.setTimestamp(1, oTimestamp);
			oStatement.executeUpdate();
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "An error occured while cleaning up the database", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_CLEAN_UP, e);
		}
		finally {
			try {
				if (oStatement != null) {
					oStatement.close();
					oStatement = null;
				}
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
	}

	/**
	 * Clean up all used recourses.
	 * 
	 * @see org.aselect.system.storagemanager.IStorageHandler#destroy()
	 */
	public void destroy()
	{
		// try {
		// if (_oActiveConnection != null) {
		// _oActiveConnection.close();
		// _oActiveConnection = null;
		// }
		// }
		// catch (Exception e) { // Only log to system logger.
		// _systemLogger.log(Level.FINE, MODULE, "destroy", "An error occured while trying to destroy the module", e);
		// }
	}

	/**
	 * Checks if the maximum items is reached. <br>
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
		String sMethod = "isMaximum";
		boolean bReturn = false;
		StringBuffer sbQuery = new StringBuffer("SELECT count(*) FROM ");
		sbQuery.append(_sTableName);
		long lMaximum = -1;
		Connection oConnection = null;
		Statement oStatement = null;
		ResultSet oResultSet = null;

		try {
			oConnection = getConnection();
			oStatement = oConnection.createStatement();
			oResultSet = oStatement.executeQuery(sbQuery.toString());

			if (oResultSet.next()) { // record exists.
				lMaximum = oResultSet.getLong(1);
			}
			if (lMaximum >= lItemCount)
				bReturn = true;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer(
					"Could not resolve the maximum number of items by executing the query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Error during resolve of the maximum number of items", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
		return bReturn;
	}

	/**
	 * Checks if the supplied key already exists in the database <br>
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
		String sMethod = "containsKey";
		boolean bReturn = false;
		Connection oConnection = null; // RH, 20090604, n
		PreparedStatement oStatement = null;
		ResultSet oResultSet = null;
		int iKey = 0; // oKey.hashCode();
		
		StringBuffer sbQuery = new StringBuffer("SELECT ").append(_sContextKey);
		sbQuery.append(" FROM ").append(_sTableName);
		sbQuery.append(" WHERE ").append(_sContextKey);
		sbQuery.append(" = ?");
		_systemLogger.log(Level.FINER, MODULE, sMethod, "sql=" + sbQuery + " -> " + iKey + " key=" + oKey);

		try {
			oConnection = getConnection();
			oStatement = oConnection.prepareStatement(sbQuery.toString());

			oStatement.setObject(1, oKey); // key must have valid type when mapped to database
			oResultSet = oStatement.executeQuery();

			if (oResultSet.next()) // record exists.
				bReturn = true;
			else
				bReturn = false;
		}
		catch (ASelectStorageException e) {
			throw e;
		}
		catch (SQLException e) {
			StringBuffer sbError = new StringBuffer("Could not execute query: ");
			sbError.append(sbQuery.toString());
			_systemLogger.log(Level.FINE, MODULE, sMethod, sbError.toString(), e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_STORAGE_RETRIEVE, e);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Error during resolve of the maximum number of items", e);
			throw new ASelectStorageException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		finally {
			try {
				if (oResultSet != null)
					oResultSet.close();
				if (oStatement != null)
					oStatement.close();
			}
			catch (SQLException e) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not close database resource.", e);
			}
			finally {
				_oConnectionHandler.releaseConnection(oConnection);
			}
		}
		return bReturn;
	}

	/**
	 * Create a database connection. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * First checks whether or not the database is still up. If not, an alternative resource will be obtained from de
	 * SAMAgent. Second, a check is done on the status of the database connection. If closed, a new connection will be
	 * opened. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b>
	 * <ul>
	 * <li>The database driver is initialised.</li>
	 * <li>The active database connection is established</li>
	 * </ul>
	 * 
	 * @return A <code>Connection</code> with the database.
	 * @throws ASelectStorageException
	 *             If connecting fails.
	 */
	// private Connection getConnection() throws ASelectStorageException
	// Keep this method for backward compatibility with other/extending classes
	protected Connection getConnection()
	throws ASelectStorageException
	{

		return _oConnectionHandler.getConnection();
	}


}