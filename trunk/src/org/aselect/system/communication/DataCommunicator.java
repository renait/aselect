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
package org.aselect.system.communication;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Tools;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * The Class DataCommunicator contains communication utility methods.
 */
public class DataCommunicator
{
	private static final String MODULE = "DataCommunicator";
	private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
	
/*	Form POST:
    POST / HTTP/1.1
	Host: localhost:1805
	User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,..*;q=0.8
	Accept-Language: nl,en;q=0.7,en-us;q=0.3
	Accept-Encoding: gzip, deflate
	Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
	DNT: 1
	Connection: keep-alive
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 106

	RelayState=aWRwPWh0dHBzOi8vc2lhbVjdHNlcnZZXJ2ZXI%3D&SAMLRequest=data&language=nl
*/
	// RH, 20200323, so
	/*
	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl)
	throws MalformedURLException, ASelectCommunicationException
	{
		return dataComSend(systemLogger, sMessage, sUrl, null);
	}

	// RH, 20190618, sn
	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl, Map<String, String> requestProprties)
	throws MalformedURLException, ASelectCommunicationException
	{
		return dataComSend(systemLogger, sMessage, sUrl, requestProprties, null);
	}
	// RH, 20190618, sn
	*/
	// RH, 20200323, eo
	
	/**
	 * Send data using a HTTP POST connection
	 * <br>
	 * <b>Description: </b> <br>
	 * Sends the suplied message to the suplied URL using an <code>HttpURLConnection</code>.<br>
	 * <br>
	 * 
	 * @param sMessage
	 *            A <code>String</code> containing the message that has to be sent.
	 * @param sUrl
	 *            The URL to send the message to.
	 * @return A <CODE>String</CODE> containing the response message.
	 * @throws MalformedURLException
	 *             If suplied URL is invalid.
	 * @throws ASelectCommunicationException
	 *             If communication with the server fails.
	 */
//	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl)
//	throws MalformedURLException, ASelectCommunicationException
//	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl, Map<String, String> requestProprties)	// RH, 20190618, o
//	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl, Map<String, String> requestProprties, String reqMethod)	// RH, 20190618, o	// RH, 20200323, o
	public static String dataComSend(SystemLogger systemLogger, String sMessage, String sUrl, Map<String, String> requestProprties, String reqMethod, SSLSocketFactory sslSocketFactory)	// RH, 20190618, o 	// RH, 20200323, n
	throws MalformedURLException, ASelectCommunicationException
	{
		String sMethod = "dataComSend";
		StringBuffer sbBuf = new StringBuffer();
		StringBuffer sbBuffer;
		HttpURLConnection connection = null;
		HttpsURLConnection  sslconnection = null;	// RH, 20200323, n

		PrintStream osOutput = null;
		URL url = new URL(sUrl);

		systemLogger.log(Level.FINEST, MODULE, sMethod, "Sending headers/RequestProperties: "+Auxiliary.obfuscate(requestProprties));
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Sending message: "+Auxiliary.obfuscate(sMessage));
		systemLogger.log(Level.FINEST, MODULE, sMethod, "Using  RequestMethod: "+reqMethod);
		systemLogger.log(Level.INFO, MODULE, sMethod, "Sending "+sMessage.length()+" [bytes] to: "+sUrl);
		try {
			// open HTTP connection to URL
			connection = (HttpURLConnection) url.openConnection();
			
			// open HTTP connection to URL
//			connection = (HttpURLConnection) url.openConnection();
			if ( sslSocketFactory != null ) {
				systemLogger.log(Level.FINEST, MODULE, sMethod, "Setting sslFactory =" + sslSocketFactory);
				sslconnection = (HttpsURLConnection) url.openConnection();
				sslconnection.setSSLSocketFactory(sslSocketFactory);
				connection = sslconnection;
			} else {
				connection = (HttpURLConnection) url.openConnection();
			}
			
			// enable sending to connection
			connection.setDoOutput(true);
			// RH, 20190618, sn
			if (reqMethod != null && reqMethod.length() > 0) {
				if ("PATCH".equalsIgnoreCase(reqMethod)) {	// patch for java
					allowMethods("PATCH");
				}
//				connection.setRequestMethod(reqMethod);	// RH, 20200528, o
				// RH, 20200528, sn
				if ("POST-JSON".equalsIgnoreCase(reqMethod)) {
					connection.setRequestMethod("POST");
				} else {
					connection.setRequestMethod(reqMethod);
				}
				// RH, 20200528, en
			}
			// RH, 20190618, sn
			// set mime headers
			if (requestProprties != null) {
				Set<String> keySet = requestProprties.keySet();
				for (String key : keySet) {
					connection.setRequestProperty(key, requestProprties.get(key));
				}
			} else {	// backwards compatibility
				connection.setRequestProperty("Content-Type", CONTENT_TYPE);
				connection.setRequestProperty("Accept", CONTENT_TYPE);
			}
			// write message to output
			osOutput = new PrintStream(connection.getOutputStream());
			osOutput.println(sMessage);
			osOutput.println("");  // is already <CR><NL> combination

			int xRetCode = connection.getResponseCode();
			systemLogger.log(Level.INFO, MODULE, sMethod, "Message send, response code: " + xRetCode);
			switch (xRetCode) { // switch on HTTP response code
			case 200: // ok
				sbBuf = new StringBuffer(Tools.stream2string(connection.getInputStream(), true));
				break;
			case 204: // ok but no content
				sbBuf = new StringBuffer(Tools.stream2string(connection.getInputStream(), true));
				break;
			case 400: // Bad request
				systemLogger.log(Level.INFO, MODULE, sMethod, "Bad request: "+connection.getHeaderField(0));
				break;
			case 500: // Internal server error
				sbBuffer = new StringBuffer("Internal server error at target host. errorcode: ");
				sbBuffer.append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			default: // unknown error
//				sbBuffer = new StringBuffer("Invalid response from target host: \"");
				sbBuffer = new StringBuffer("Unexpected response from target host: \"");
				sbBuffer.append(connection.getHeaderField(0));
				sbBuffer.append(" \". errorcode: ").append(Errors.ERROR_ASELECT_INTERNAL_ERROR);
				systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
				break;
			}
		}
		catch (java.net.UnknownHostException eUH) {  // target host unknown
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception: " + eUH.getMessage());
			sbBuffer = new StringBuffer("Target host unknown: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_USE_ERROR);
			systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_USE_ERROR);
		}
		catch (java.io.IOException eIO) {  // error while connecting,writing or reading
			systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception: " + eIO.getMessage());
			sbBuffer = new StringBuffer("Could not open connection to host: \"");
			sbBuffer.append(sUrl);
			sbBuffer.append("\" errorcode: ").append(Errors.ERROR_ASELECT_IO);
			systemLogger.log(Level.WARNING, MODULE, sMethod, sbBuffer.toString());
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO);
		}
		finally {
			systemLogger.log(Level.FINEST, MODULE, sMethod, "Close osOutput="+osOutput+" conn="+connection);
			if (osOutput != null)
				osOutput.close();
			if (connection != null)
				connection.disconnect();
		}
		return sbBuf.toString();
	}
	
	// Temporary workaround by okutane
//    private static void allowMethods(String... methods) {	// RH, 20200323, o
    private synchronized static void allowMethods(String... methods) {	// RH, 20200323, n
        try {
            Field methodsField = HttpURLConnection.class.getDeclaredField("methods");

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(methodsField, methodsField.getModifiers() & ~Modifier.FINAL);

            methodsField.setAccessible(true);

            String[] oldMethods = (String[]) methodsField.get(null);
            Set<String> methodsSet = new LinkedHashSet<>(Arrays.asList(oldMethods));
            methodsSet.addAll(Arrays.asList(methods));
            String[] newMethods = methodsSet.toArray(new String[0]);

            methodsField.set(null/*static field*/, newMethods);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

}
