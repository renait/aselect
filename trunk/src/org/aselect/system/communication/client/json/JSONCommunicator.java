/*
 * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.system.communication.client.json;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.aselect.system.communication.DataCommunicator;
import org.aselect.system.communication.client.IClientCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;

/**
 * Client communicator which uses CGI messages in json. <br>
 * <br>
 * <b>Description: </b> <br>
 * The JSON communicator used by the A-Select agent to create, retrieve, and send URL encoded CGI messages. <br>
 * 
 */
public class JSONCommunicator implements IClientCommunicator
{
	private final String MODULE = "JSONCommunicator";

	/** The Logger for this JSONCommunicator */
	private SystemLogger _systemLogger;
	
	private String user= null;
	private String pw = null;



	/**
	 * Creates a new <code>JSONCommunicator</code>. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>systemLogger</code> should be initialized. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>_systemLogger</code> is set with <code> systemLogger</code>. <br>
	 * 
	 * @param systemLogger
	 *            the <code>logger</code> to log system information.
	 */
	public JSONCommunicator(SystemLogger systemLogger) {
		_systemLogger = systemLogger;
	}

	/**
	 * Sends a (JSON) api call to the target. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Executes the following steps:
	 * <ul>
	 * <li>Create empty return HashMap</li>
	 * <li>Convert non-string parameters to JSON message string</li>
	 * <li>Convert string parameters to CGI message string</li>
	 * <li>Send request to target server</li>
	 * <li>Response is supposed to be JSON string</li>
	 * <li>Convert response to HashMap</li>
	 * </ul>
	 * <br>
	 * 
	 * @param parameters
	 *            the parameters
	 * @param target
	 *            the target
	 * @return the hash map
	 * @throws ASelectCommunicationException
	 *             If sending fails.
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendMessage(java.util.HashMap, java.lang.String)
	 */
	public HashMap sendMessage(HashMap parameters, String target)
	throws ASelectCommunicationException
	{
		String sMethod = "sendMessage";
		HashMap htReturn = new HashMap();
		HashMap request = new HashMap();

		_systemLogger.log( Level.FINEST, MODULE, sMethod, "composing message from:" +  parameters);

		StringBuffer sRequest = new StringBuffer();
		Iterator itr = parameters.keySet().iterator();
		boolean first = true;
		while ( itr.hasNext() ) {
			if ( !first ) {
				sRequest.append('&');
			}
			String s = (String)itr.next();
			sRequest.append(s).append('=').append(parameters.get(s) instanceof String ? parameters.get(s) : 
				((JSONObject) JSONSerializer.toJSON( parameters.get(s) )).toString(0) ); 
			first = false;
		}
		
		_systemLogger.log( Level.FINEST, MODULE, sMethod, "sending message():" + sRequest.toString() );
		
		// Send request to server
		String sResponse = sendRequestToAnotherServer(target, sRequest.toString());
		_systemLogger.log( Level.FINEST, MODULE, sMethod, "received sResponse:" + sResponse );
		// Convert response to HashMap
		if (sResponse != null) {
//				htReturn = convertCGIMessage(sResponse);
			_systemLogger.log( Level.FINEST, MODULE, sMethod, "parsing message." );
			try {
			JSONArray jsonArray = (JSONArray) JSONSerializer.toJSON( sResponse );  
			_systemLogger.log( Level.FINEST, MODULE, sMethod, "received message parsed to JSONArray:" + jsonArray.toString() );
			htReturn = new HashMap((Map<String, Object>) JSONObject.toBean(jsonArray.getJSONObject(0), Map.class));
			} catch (java.lang.ClassCastException cce) {	// not a JSONArray
				// maybe a JSONObject
				JSONObject jsonObject = (JSONObject) JSONSerializer.toJSON( sResponse );  
				_systemLogger.log( Level.FINEST, MODULE, sMethod, "received message parsed to JSONObject:" + jsonObject.toString() );
				htReturn = new HashMap((Map<String, Object>) JSONObject.toBean(jsonObject, Map.class));
				
				
			}
			_systemLogger.log( Level.FINEST, MODULE, sMethod, "created HashMap:" + htReturn );
		}
		
		return htReturn;
	}

	/* (non-Javadoc)
	 * @see org.aselect.system.communication.client.IClientCommunicator#sendStringMessage(java.lang.String, java.lang.String)
	 */
	public String sendStringMessage(String sMessage, String sTarget)
	throws ASelectCommunicationException
	{
		
		String sResponse = null;
		String sMethod = "sendStringMessage";

		try {  // Send the message
			if ( getUser() != null ) _systemLogger.log(Level.WARNING, MODULE, sMethod, "Authentication not implemented for DataCommunicator (yet)");
			sResponse = DataCommunicator.dataComSend(_systemLogger, sMessage, sTarget);
		}
		catch (java.net.MalformedURLException eMU) {
			StringBuffer sbBuffer = new StringBuffer("Invalid URL: ");
			sbBuffer.append(eMU.getMessage()).append(" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString(), eMU);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		//_systemLogger.log(Level.INFO, MODULE, sMethod, "Response=" + sResponse);
		return sResponse;
	}

	/**
	 * Send the request to the target url. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Executes the following steps:
	 * <ul>
	 * <li>Builds a URL with request parameters</li>
	 * <li>Opens a connection to the server</li>
	 * <li>Receives response from the server</li>
	 * </ul>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <ul>
	 * <li><code>sUrl</code> is a valid URL
	 * <li><code>sParams</code> is a non empty <code>String</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The return <code>String</code> contains the server response. <br>
	 * 
	 * @param sUrl
	 *            The URL of a server.
	 * @param sParams
	 *            The parameters to be send as CGIMessage.
	 * @return The response from the A-Select server.
	 * @throws ASelectCommunicationException
	 *             If communication with <code>sUrl</code> fails.
	 */
	private String sendRequestToAnotherServer(String sUrl, String sParams)
	throws ASelectCommunicationException
	{
		String sMethod = "sendRequestToAnotherServer";
		String sInputLine = "";
		URL urlSomeServer = null;
		BufferedReader brInput = null;
		StringBuffer sbBuffer = new StringBuffer();

//		sbBuffer = new StringBuffer(sUrl).append("?").append(sParams);	// RH, 20151001, o
		// RH, 20151001, sn
		sbBuffer = new StringBuffer(sUrl);
		if ( sParams != null && sParams.length() > 0 && !sParams.startsWith("?")) {
			sbBuffer = sbBuffer.append("?").append(sParams);
		}


		_systemLogger.log(Level.FINEST, MODULE, sMethod, "URL=" + sbBuffer.toString());
		try {
			
			if ( user != null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Using Basic Authentication");
				Authenticator.setDefault(new Authenticator() {
				    protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(getUser(), (getPw() != null) ? getPw().toCharArray() : "".toCharArray());
				    }
				});
			}
			// RH, 20151001, en
			
			
			
			
			urlSomeServer = new URL(sbBuffer.toString());
			brInput = new BufferedReader(new InputStreamReader(urlSomeServer.openStream()), 16000);
			String s = null;
			while ( (s = brInput.readLine()) != null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Input from the other server=" +s);
				sInputLine += s;
			}
			brInput.close();

			if (sInputLine != null)
				sInputLine = sInputLine.trim();
			return sInputLine;
		}
		catch (MalformedURLException eMU) // Invalid URL
		{
			sbBuffer = new StringBuffer("Invalid URL: \"").append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR, eMU);
		}
		catch (IOException eIO) // Error communicating with A-Select Server
		{
			sbBuffer = new StringBuffer("Error communicating with server at: \"").append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_IO);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, eIO);
		}
		// RH, 20151001, sn
		finally {
			if ( getUser() != null)	Authenticator.setDefault(null);
			if (brInput != null)
				try {
					brInput.close();
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Couldn't close inputstream, continuing");
				}
		}
		// RH, 20151001, en
	}

	public String getUser()
	{
		return user;
	}

	public void setUser(String user)
	{
		this.user = user;
	}

	public String getPw()
	{
		return pw;
	}

	public void setPw(String pw)
	{
		this.pw = pw;
	}

	

}

