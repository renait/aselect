/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.authspserver.authsp.sms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;

import org.aselect.authspserver.log.AuthSPSystemLogger;
import org.aselect.system.utils.Utils;

/**
 * Sends request for sms to the CM sms gateway
 * @author Bauke Hiemstra
 * 
 */
public class CmHttpSmsSender extends GenericSmsSender
{
	private static final String sModule = "CM";
	//private static final String SEPCHAR = "=";

	private String sCustomerId = null;
	private String sProductToken = null;
	private String sAppKey = null;
	
	final String CUSTOMER_LOCATION = "_CUSTOMER_IS_HERE_";
	final String PRODUCTTOKEN_LOCATION = "_PRODUCTTOKEN_IS_HERE_";
	final String LOGIN_DATA_LOCATION = "_LOGIN_DATA_IS_HERE_";
	final String APPKEY_LOCATION = "_APPKEY_IS_HERE_";

	final String xmlCustomer = "<CUSTOMER ID=\"[CUSTOMER]\"/>\n";
	final String xmlProductToken = "<AUTHENTICATION>\n<PRODUCTTOKEN>[PRODUCTTOKEN]</PRODUCTTOKEN>\n</AUTHENTICATION>\n";
	final String xmlLoginData = "<USER LOGIN=\"[USER]\" PASSWORD=\"[PASSWORD]\"/>\n";
	final String xmlAppKey = "<APPKEY>[APPKEY]</APPKEY>";

	private String xmlSmsMessage =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<MESSAGES>\n" +
		CUSTOMER_LOCATION + PRODUCTTOKEN_LOCATION + LOGIN_DATA_LOCATION +
		"<MSG>\n" +
			"<FROM>[SENDER]</FROM>\n" +
			"<BODY>[MESSAGE]</BODY>\n" + 
			"<TO>[NUMBER]</TO>\n" + APPKEY_LOCATION + "\n" +
			//"<ALLOWEDCHANNELS>SMS</ALLOWEDCHANNELS>\n" +
		"</MSG>\n" +
		"</MESSAGES>\n";
	
	final String CONTENT_TYPE = "text/xml; charset=utf-8";
	
	// Override the default from GenericSmsSender
	public String getContentType()
	{
		return CONTENT_TYPE;
	}

	/**
	 * Instantiates a new CM http sms sender.
	 * 
	 * @param url
	 *            the sms gateway provider url
	 * @param user
	 *            the account user
	 * @param password
	 *            the account password
	 * @param gateway
	 *            the (optional) priority gateway if supported by the sms
	 *            gateway provider
	 * @param usePost
	 *            use POST instead of GET
	 */
	public CmHttpSmsSender(String url, String customer, String user, String password, String producttoken,
			String appkey, String gateway, boolean usePost)
	{
		super(url, user, password, gateway, usePost);
		sCustomerId = customer;
		sProductToken = producttoken;
		sAppKey = appkey;
	}
	
	/**
	 * Assemble the sms message.
	 * This XML document should be encoded in UTF-8.
	 * The values within the document elements should be XML encoded
	 * 
	 * @param sTemplate
	 *            the template
	 * @param sSecret
	 *            the secret code
	 * @param from
	 *            the sender
	 * @param recipients
	 *            the recipients
	 * @param sbResult
	 *            the data to be sent
	 * @return - 0 = ok
	 * @throws UnsupportedEncodingException
	 */
	protected int assembleSmsMessage(String sTemplate, String sSecret, String from, String recipients, StringBuffer sbResult)
	throws UnsupportedEncodingException
	{
		String sMethod = "assembleSmsMessage";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();
		_systemLogger.log(Level.INFO, sModule, sMethod, "url=" + providerUrl);
		
		String sMessage = applySmsTemplate(sTemplate, sSecret, false);
//		_systemLogger.log(Level.FINEST, sModule, sMethod, "msg="+escapeXmlString(sMessage)+" cust="+sCustomerId+
//				" user="+this.user+" password="+this.password+" from="+from+" rcp="+recipients);
		String sData = xmlSmsMessage.replaceAll("\\[MESSAGE\\]", escapeXmlString(sMessage));

		if (Utils.hasValue(sCustomerId)) {
			String sValue = xmlCustomer.replaceAll("\\[CUSTOMER\\]", sCustomerId);
			sData = sData.replaceAll(CUSTOMER_LOCATION, sValue);
		}
		else {
			sData = sData.replaceAll(CUSTOMER_LOCATION, "");
		}
		
		if (Utils.hasValue(sProductToken)) {
			String sValue = xmlProductToken.replaceAll("\\[PRODUCTTOKEN\\]", escapeXmlString(this.sProductToken));
			sData = sData.replaceAll(PRODUCTTOKEN_LOCATION, sValue);
		}
		else {
			sData = sData.replaceAll(PRODUCTTOKEN_LOCATION, "");
		}
		if (Utils.hasValue(this.user) && Utils.hasValue(this.password)) {
			String sValue = xmlLoginData.replaceAll("\\[USER\\]", escapeXmlString(this.user));
			sValue = sValue.replaceAll("\\[PASSWORD\\]", escapeXmlString(this.password));
			sData = sData.replaceAll(LOGIN_DATA_LOCATION, sValue);
		}
		else {
			sData = sData.replaceAll(LOGIN_DATA_LOCATION, "");
		}
		
		sData = sData.replaceAll("\\[SENDER\\]", escapeXmlString(from));
		sData = sData.replaceAll("\\[NUMBER\\]", recipients);  // a single phone number
		
		if (Utils.hasValue(sAppKey)) {
			String sValue = xmlAppKey.replaceAll("\\[APPKEY\\]", escapeXmlString(this.sAppKey));
			sData = sData.replaceAll(APPKEY_LOCATION, sValue);
		}
		else {
			sData = sData.replaceAll(APPKEY_LOCATION, "");
		}
		
		// gateway has no value
		if (Utils.hasValue(this.gateway)) {
			_systemLogger.log(Level.WARNING, sModule, sMethod, "Alternate gateway supplied, but not supported");
		}
		sbResult.append(sData);
		return 0;
	}
	
	/**
	 * Returns the string where all non-ascii and <, &, > are encoded as numeric
	 * entities. The result is safe to include anywhere in a text field in an
	 * XML-string. If no characters were escaped, the original string is
	 * returned.
	 * 
	 * @param unescapedString
	 *            the unescaped string
	 * @return the result
	 */
	public static String escapeXmlString(String unescapedString)
	{
	    boolean anyCharactersEscaped = false;

	    if (unescapedString == null)
	        return null;
	    
	    StringBuffer stringBuffer = new StringBuffer();
	    for (int i = 0; i < unescapedString.length(); i++) {
	        char ch = unescapedString.charAt(i);

	        if (ch < 32 || ch > 126 || ch == '<' || ch == '&' || ch == '>') {
	            stringBuffer.append("&#" + (int)ch + ";");
	            anyCharactersEscaped = true;
	        }
	        else {
	            stringBuffer.append(ch);
	        }
	    }
	    return (anyCharactersEscaped)? stringBuffer.toString(): unescapedString;
	}
	
	/**
	 * Every request will get an HTTP response with status 200 (OK), even if the request is malformed.
	 * If the request was correct, the response will be empty.
	 * If the request was malformed, the response will start with �ERROR�.
	 * @param rd - the Reader for the result
	 * @return - 0 = ok
	 */
	protected int analyzeSmsResult(BufferedReader rd)
	throws IOException, DataSendException
	{
		String sMethod = "analyzeSmsResult";
		AuthSPSystemLogger _systemLogger = AuthSPSystemLogger.getHandle();

		String line;
		String sResult = "";
		while ((line = rd.readLine()) != null) {	// there should be only one significant line, ignore extra lines
			_systemLogger.log(Level.FINEST, sModule, sMethod, "line" + line);
			sResult += line;
			//if ("".equals(sResult) && !"".equals(line))
			//	sResult = line;	// get first non-empty line
		}
		_systemLogger.log(Level.FINEST, sModule, sMethod, "result:" + sResult);

		// Analyse the result
		if (sResult.contains("Error:") || sResult.contains("ERROR")) {
			throw new DataSendException("SMS provider could not send sms, error=" + sResult);
		}
		return 0;  // ok
	}
}
