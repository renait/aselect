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
package org.aselect.lbsensor.handler;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.logging.Level;

import org.aselect.system.communication.server.Communicator;
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.communication.server.IOutputMessage;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.lbsensor.ISensorHandler;
import org.aselect.lbsensor.LbSensorConfigManager;
import org.aselect.lbsensor.LbSensorSystemLogger;


public class BasicSensorHandler implements ISensorHandler
{
	public final static String MODULE = "BasicSensorHandler";

	protected LbSensorConfigManager _oConfigManager = LbSensorConfigManager.getHandle();
	protected LbSensorSystemLogger _oLbSensorLogger = LbSensorSystemLogger.getHandle();
	protected SensorStore _myStore = null; // Storage to calculate the running average data
	protected String _sMyId = null;
	protected String _myIP = "";
	protected int _myPort = 0;
	protected String _myHost = "";

	private ServerSocket _oServiceSocket = null;
	private boolean _bActive = true;
	
	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.ISensorHandler#initialize(java.lang.Object, java.lang.String)
	 */
	public void initialize(Object oConfigHandler, String sId)
	throws ASelectException
	{
		String sMethod = "initialize";
		int iPort = -1;
		int iIntCount, iIntLength;
		InetAddress inetAddress = null;

		_sMyId = sId;

		iPort = _oConfigManager.getSimpleIntParam(oConfigHandler, "listen_port", true);
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Port=" + iPort);

		String sInetAddress = _oConfigManager.getSimpleParam(oConfigHandler, "listen_host", false);
		if ( sInetAddress != null && sInetAddress.length() > 0 ) {
			try {
				inetAddress = InetAddress.getByName(sInetAddress);
			}
			catch (UnknownHostException e) {
				_oLbSensorLogger.log(Level.SEVERE, MODULE, sMethod, "Invalid 'listen_host' provided, Host=" + sInetAddress);
				throw new ASelectConfigException("Invalid 'listen_host' provided,", e);
			}
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Host=" + inetAddress.getHostAddress());
		}
		
		// try to allocate the listening ports on localhost.
		// Bauke, 20090707: Listen on all addresses
		try {
//			_oServiceSocket = new ServerSocket(iPort, 50, null/* InetAddress.getByName("localhost") */);
			_oServiceSocket = new ServerSocket(iPort, 50, inetAddress);
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Socket=" + _oServiceSocket);
		}
		catch (Exception e) {
			_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "Cannot create serversocket on port " + iPort);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		iIntCount = _oConfigManager.getSimpleIntParam(oConfigHandler, "nr_of_intervals", false);
		if (iIntCount < 0)
			iIntCount = 8; // intervals
		iIntLength = _oConfigManager.getSimpleIntParam(oConfigHandler, "interval_length", false);
		if (iIntLength < 0)
			iIntLength = 30; // seconds
		_myStore = new SensorStore(_sMyId, iIntCount, iIntLength);
		
		try {
			InetAddress ownIP = InetAddress.getLocalHost();
			_myIP = ownIP.getHostAddress();
			_myPort = _oServiceSocket.getLocalPort();
			_myHost = ownIP.getHostName();
			DataCollectStore.getHandle().set_myIP(_myIP);
			DataCollectStore.getHandle().set_myPort(_myPort);
		}
		catch (UnknownHostException e) {
		}
	}

	/* (non-Javadoc)
	 * @see org.aselect.lbsensor.ISensorHandler#getMyStore()
	 */
	public SensorStore getMyStore()
	{
		return _myStore;
	}

	
	class BasicSensorSocketRunner extends Thread {
		
		Socket oSocket = null;
		BufferedReader oInReader = null;
		BufferedWriter oOutWriter = null;
		LbSensorSystemLogger _oLbSensorLogger = null;
		StringBuffer sRequestLine = new StringBuffer();
		int n = -1;

		
		public BasicSensorSocketRunner(Socket oSocket , LbSensorSystemLogger _oLbSensorLogger ) {
			this.oSocket = oSocket;
			this._oLbSensorLogger = _oLbSensorLogger;
		};
		
		public void run() {
			String sMethod = "BasicSensorSocketRunner.run:" + Thread.currentThread().getName();

			long now = System.currentTimeMillis();
			long stamp = now % 1000000;

			int port = oSocket.getPort();
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() +
					" "+stamp + " port="+port +", t="+Thread.currentThread().getId());

			String s = null;
			Boolean isPOST = null;	// We don't know yet, so null
			
			try {
//				oSocket.setSoTimeout(40);
				oSocket.setSoTimeout(0);	// disable
			InputStream isInput = oSocket.getInputStream();
			OutputStream osOutput = oSocket.getOutputStream();
			oInReader = new BufferedReader(new InputStreamReader(isInput, "UTF-8"));
			oOutWriter = new BufferedWriter(new OutputStreamWriter(osOutput, "UTF-8"));

			processStart(oOutWriter, _sMyId);
			
			do {	// This is an http like socket so we can use readline 
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Trying to read stream T=" + System.currentTimeMillis() +
						" t="+Thread.currentThread().getId() + ", from remote =" + oSocket.toString());
				s = oInReader.readLine();
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted in first loop T=" + System.currentTimeMillis() +
						" t="+Thread.currentThread().getId() + ", lineLength (without eol) =" + s.length() + ", line  read =" + s);
				if (isPOST == null ) {	// only true for fist line
					if ( s != null && s.toUpperCase().startsWith("POST")) { // first line should not be null, but in case of
						isPOST = true;
						_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted in first loop T=" + System.currentTimeMillis() +
								" t="+Thread.currentThread().getId() + ", it's a POST");
					} else {
						isPOST = false;
					}
				}
				oOutWriter.write(s + "\r\n");
					try {
						processLine(oOutWriter, s, _sMyId);
					}
					catch (Exception e) { // continue anyway
						_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "exception occurred in processLine()", e);
					}
			}while (s != null && !"".equals(s) && oInReader.ready()) ;
			if ( isPOST.booleanValue() == true) {	// read the POST data
				do {	// we assume there is a eol after the post data. this is trictly not true, we should read content-length
					s = oInReader.readLine();
					_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted in second loop T=" + System.currentTimeMillis() +
							" t="+Thread.currentThread().getId() + ", lineLength (without eol) =" + s.length() + ", line  read =" + s);
					oOutWriter.write(s + "\r\n");
				
				try {
					processLine(oOutWriter, s, _sMyId);
				}
				catch (Exception e) { // continue anyway
					_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "exception occurred in processLine()", e);
				}
				}while (s != null && !"".equals(s) && oInReader.ready()) ;	// POST data processed
				
			} // else it's a GET and we're done
			
			
			}
			catch (SocketTimeoutException e0) {
				// see if there were some characters left over 
				_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, "SocketTimeoutException occurred:" + e0.getMessage());
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Accepted T=" + System.currentTimeMillis() +
						" t="+Thread.currentThread().getId() + " last s) read =" + s);
				if (s != null && s.length() > 0) {
				try {
					_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, "Handling left-over line(s)");
					processLine(oOutWriter, s, _sMyId);
				}
				catch (IOException e1) {
					_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "IOException occurred in left-over processLine()", e1);
				}
				}

			}
			catch (SocketException e) {
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "SocketException occurred: "+ e.getMessage());
			}
			catch (IOException e) {
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "IOException occurred: "+ e.getMessage());
			}
			finally {
				try {
					processFinish(oOutWriter, _sMyId);
					if (oOutWriter != null)
						oOutWriter.close(); // flushes the output to the client
					if (oSocket != null) {
						oSocket.close();
					}
				}
				catch (Exception e) {
				}
			}
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, " t="+Thread.currentThread().getId() +", Ready");
			
		}
	}

	
	
	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	public void run()
	{
		String sMethod = "run";
		Socket oSocket = null;

		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " ip="+_myIP+" port="	+ _myPort+" host="+_myHost);
		while (_bActive) {
			try {
				long now = System.currentTimeMillis();
				long stamp = now % 1000000;
				_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Waiting. T=" + now + " " +
						stamp+", thread="+Thread.currentThread().getId());
				oSocket = _oServiceSocket.accept();
				
				BasicSensorSocketRunner socketrunner = new BasicSensorSocketRunner(oSocket, _oLbSensorLogger);
				socketrunner.start();


			} catch (IOException e) {
				_oLbSensorLogger.log(Level.WARNING, MODULE, sMethod, "I/O exception occurred in _oServiceSocket", e);
			}
		}
		_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, MODULE + " stopped");
	}

	// Allow this thread to be stopped
	/**
	 * Stop thread.
	 */
	public void stopThread()
	{
		_bActive = false;
	}

	/**
	 * Process line. This is the default supplied, may be overridden
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param line
	 *            the line
	 * @param sId
	 *            the handler id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processLine(BufferedWriter oOutWriter, String line, String sId)
	throws IOException
	{
		String sMethod = "processLine";

		_oLbSensorLogger.log(Level.FINEST, MODULE, sMethod, sId + " [" + line + "]");
	}

	/**
	 * Called before processing.
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param sId
	 *            the s id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processStart(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		oOutWriter.write("---- Received data:\n\n");  // first \n somehow gets eaten by the browser
	}
	
	/**
	 * Called after processing.
	 * 
	 * @param oOutWriter
	 *            the o out writer
	 * @param sId
	 *            the handler id
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void processFinish(BufferedWriter oOutWriter, String sId)
	throws IOException
	{
		oOutWriter.write("---- End of data\n");
	}

	// Override if no echoing is needed
	/**
	 * Echo char to stream.
	 * 
	 * @param oOutWriter
	 *            the out writer
	 * @param c
	 *            the char to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	protected void echoCharToStream(BufferedWriter oOutWriter, char c)
	throws IOException
	{
		//if (c=='\r') oOutWriter.write(c+"<R>");
		//else if (c=='\n') oOutWriter.write(c+"<N>");
		//else
		oOutWriter.write(c);
	}

	/**
	 * Process request.
	 * 
	 * @param xCommunicator
	 *            the x communicator
	 * @param port
	 *            the port
	 */
	protected void processRequest(Communicator xCommunicator, int port)
	{
		String sMethod = "processRequest";
		IInputMessage oInputMessage = xCommunicator.getInputMessage();
		IOutputMessage oOutputMessage = xCommunicator.getOutputMessage();

		String sRequest = null;
		try {
			sRequest = oInputMessage.getParam("request");
			_oLbSensorLogger.log(Level.INFO, MODULE, sMethod, "Request=" + sRequest);
			oOutputMessage.setParam("result_code", Errors.ERROR_ASELECT_SUCCESS);
		}
		catch (Exception eX) {
		}
	}
}
