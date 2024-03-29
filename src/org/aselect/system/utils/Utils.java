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
 * $Id: Utils.java,v 1.10 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: Utils.java,v $
 * Revision 1.10  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.9  2006/04/12 13:20:41  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.8.4.2  2006/04/04 11:05:54  erwin
 * Removed warnings.
 *
 * Revision 1.8.4.1  2006/03/21 07:32:49  leon
 * hashtable2CGIMessage added
 *
 * Revision 1.8  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.7  2005/08/30 14:20:05  erwin
 * Fixed bug in wildcard match
 *
 * Revision 1.6  2005/05/20 13:10:38  erwin
 * Fixed some minor bugs in Javadoc
 *
 * Revision 1.5  2005/04/07 08:32:52  remco
 * base64 decoder couldn't handle empty strings
 *
 * Revision 1.4  2005/03/24 13:24:22  erwin
 * Removed toLowerCase() for parameters.
 *
 * Revision 1.3  2005/03/16 13:29:19  remco
 * added wildcard matching method
 *
 * Revision 1.2  2005/03/04 08:26:43  erwin
 * Applied import manager
 *
 * Revision 1.1  2005/02/22 12:03:29  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.2  2005/01/28 10:09:44  ali
 * Javadoc toegevoegd en kleine code cleanup acties.
 *
 */

package org.aselect.system.utils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

//import org.aselect.server.log.ASelectSystemLogger;	// RH, 20190926, o
import org.aselect.system.communication.server.IInputMessage;
import org.aselect.system.configmanager.ConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.ISystemLogger;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.crypto.Auxiliary;

import net.sf.json.JSONObject;

/**
 * Static class that implements generic, widely used utility methods. <br>
 * <br>
 * <b>Description: </b> <br>
 * The Utils class implements convenient static methods used widely by A-Select components. <br>
 * <br>
 * <b>Concurrency issues: </b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class Utils
{
	private static final String OPERATOR_URLDECODE = "URLDECODE";

	private static final String OPERATORPREFIX_URLDECODE = "=urldecode:";

	/**
	 * Static char array for quickly converting bytes to hex-strings.
	 */
	private static final char[] _hexChars = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	/** "[]" braces UTF-8 encoded. */
	private static final String ENCODED_BRACES = "%5B%5D";

	private static final String MODULE = "Utils";
	
	private static SystemLogger _oSysLog = null;
	public static void setSysLog(SystemLogger sysLog)
	{
		_oSysLog = sysLog;
	}
	
	/**
	 * Returns an int from 0 to 15 corresponding to the specified hex digit. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * For input 'A' this method returns 10 etc. Input is <u>case-insensitive </u>. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * Only hexadecimal characters [0..f] or [0..F] are processed. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param ch
	 *            Input hexadecimal character.
	 * @return int representing ch.
	 * @throws IllegalArgumentException
	 *             on non-hexadecimal characters.
	 */
	public static int fromDigit(char ch)
	{
		if (ch >= '0' && ch <= '9')
			return ch - '0';
		if (ch >= 'A' && ch <= 'F')
			return ch - 'A' + 10;
		if (ch >= 'a' && ch <= 'f')
			return ch - 'a' + 10;

		throw new IllegalArgumentException("invalid hex digit '" + ch + "'");
	}

	/**
	 * Outputs a hex-string respresentation of a byte array. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This method returns the hexadecimal String representation of a byte array. <br>
	 * <br>
	 * Example: <br>
	 * For input <code>[0x13, 0x2f, 0x98, 0x76]</code>, this method returns a String object containing
	 * <code>"132F9876"</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xBytes
	 *            Source byte array.
	 * @return a String object respresenting <code>xBytes</code> in hexadecimal format.
	 */
	public static String byteArrayToHexString(byte[] xBytes)
	{
		int xLength = xBytes.length;
		char[] xBuffer = new char[xLength * 2];

		for (int i = 0, j = 0, k; i < xLength;) {
			k = xBytes[i++];
			xBuffer[j++] = _hexChars[(k >>> 4) & 0x0F];
			xBuffer[j++] = _hexChars[k & 0x0F];
		}
		return new String(xBuffer);
	}

	/**
	 * Returns a byte array corresponding to a hexadecimal String. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Example: <br>
	 * For input <code>"132F9876"</code>, this method returns an array containing <code>[0x13, 0x2f, 0x98, 0x76]</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * The <code>xHexString</code> must be a hexadecimal String. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xHexString
	 *            String containing a hexadecimal string.
	 * @return a byte array containing the converted hexadecimal values.
	 * @throws IllegalArgumentException
	 *             on non-hexadecimal characters.
	 */
	public static byte[] hexStringToByteArray(String xHexString)
	{
		int len = xHexString.length();

		byte[] buf = new byte[((len + 1) / 2)];

		int i = 0, j = 0;
		if ((len % 2) == 1)
			buf[j++] = (byte) fromDigit(xHexString.charAt(i++));

		while (i < len) {
			buf[j++] = (byte) ((fromDigit(xHexString.charAt(i++)) << 4) | fromDigit(xHexString.charAt(i++)));
		}
		return buf;
	}

	/**
	 * Prefixes a String with another String until a specified length is reached. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Example: <br>
	 * <br>
	 * <code>
	 * String xVar = "873";<br>
	 * xVar = prefixString("0", xVar, 5);<br>
	 * System.out.println(xVar);<br><br>
	 * </code> This will print <br>
	 * <br>
	 * <code>
	 * 00873
	 * </code><br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>xPrefix</code> may not be null. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xPrefix
	 *            character to prefix xString with.
	 * @param xString
	 *            input String.
	 * @param xEndlength
	 *            length of desired output String.
	 * @return String containing the output String.
	 */
	public static String prefixString(String xPrefix, String xString, int xEndlength)
	{
		String xResult;

		xResult = xString;
		while (xResult.length() < xEndlength) {
			xResult = xPrefix + xResult;
		}
		return xResult;
	}

	/**
	 * Replaces all occurrences of a string in a source string. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Trivial. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * None. <br>
	 * 
	 * @param xSrc
	 *            The source string.
	 * @param xString
	 *            The string that is to be replaced.
	 * @param xReplaceString
	 *            The string that replaces xString.
	 * @return A String containing all occurrences of xString replaced by xReplaceString.
	 */
	public static String replaceString(String xSrc, String xString, String xReplaceString)
	{
		StringBuffer xBuffer = new StringBuffer(xSrc);
		int xStart, xEnd;

		if (xReplaceString == null)
			return xSrc;
		while (xBuffer.indexOf(xString) != -1) {
			xStart = xBuffer.indexOf(xString);
			xEnd = xStart + xString.length();
			xBuffer = xBuffer.delete(xStart, xEnd);
			xBuffer = xBuffer.insert(xStart, xReplaceString);
		}
		return xBuffer.toString();
	}

	/**
	 * Gets the aselect_specials value from RelayState or app_url.
	 * 
	 * @param htSessionContext
	 *            the session context
	 * @return the specials found or null
	 */
	public static String getAselectSpecials(HashMap htSessionContext, boolean decode, ISystemLogger logger)
	{
		String sMethod = "getAselectSpecials";
		String sSpecials = null;
		
		String sRelay = (String)htSessionContext.get("RelayState");
		if (Utils.hasValue(sRelay) && !sRelay.startsWith("idp=")) {  // try RelayState passed from SP
			// Found a base64 encoded RelayState
			sRelay = new String(Base64Codec.decode(sRelay));
			sSpecials = Utils.getParameterValueFromUrl(sRelay, "aselect_specials");
			logger.log(Level.FINER, MODULE, sMethod, "sRelay="+sRelay+" sSpecials="+sSpecials);
		}
		if (sSpecials == null) {
			sSpecials = (String)htSessionContext.get("aselect_specials");
			logger.log(Level.FINER, MODULE, sMethod, "aselect_specials="+sSpecials);
		}
		if (sSpecials == null) {  // try application url
			String sAppUrl = (String)htSessionContext.get("app_url");
			sSpecials = Utils.getParameterValueFromUrl(sAppUrl, "aselect_specials");					
			logger.log(Level.INFO, MODULE, sMethod, "sAppUrl="+sAppUrl+" sSpecials="+sSpecials);
		}
		if (decode && Utils.hasValue(sSpecials)) {
			sSpecials = new String(Base64Codec.decode(sSpecials));
			logger.log(Level.FINER, MODULE, sMethod, "sSpecials="+sSpecials);
		}
		return sSpecials;
	}
	
	/**
	 * Sets the session status.
	 * 
	 * @param htSessionContext
	 *            the session context
	 * @param sStatus
	 *            the status to be set
	 * @param logger
	 *            the logger, can be null
	 */
	public static void setSessionStatus(HashMap htSessionContext, String sStatus, ISystemLogger logger)
	{
		String sMethod = "setSessionStatus";
		if (htSessionContext == null)
			return;
		if (logger != null)
			logger.log(Level.FINER, MODULE, sMethod, "Set status="+sStatus);
		if ("del".equals(sStatus))
			htSessionContext.put("status", sStatus);
		else {
			String sOld = (String)htSessionContext.get("status");
			if (!"del".equals(sOld))
				htSessionContext.put("status", sStatus);
			else if (logger != null)
				logger.log(Level.FINER, MODULE, sMethod, "Skip status, already="+sOld);
		}
	}

	/**
	 * Retrieve parameter value from the given URL.
	 * 
	 * @param sUrl
	 *            the URL (null allowed)
	 * @param sParamName
	 *            the parameter name
	 * @return the parameter value or null if not found
	 */
	// Example: sAppUrl=https://appl.anoigo.nl/?aselect_specials=aWZfY29uZD1vcmdfbG9naW4mc2V0X2ZvcmNlZF91aWQ=
	public static String getParameterValueFromUrl(String sUrl, String sParamName)
	{
		if (sUrl == null)
			return null;

		String sParCond = null;
		int iArgs = sUrl.indexOf('?');
		if (iArgs >= 0)
			sUrl = sUrl.substring(iArgs+1);
		
		// sUrl now starts with the arguments
		int iCond = sUrl.indexOf(sParamName+"=");
		if (iCond >= 0 && (iCond == 0 || sUrl.charAt(iCond-1)=='&')) {
			iCond += sParamName.length()+1;
			int iAmp = sUrl.indexOf('&', iCond);
			sParCond = (iAmp<0)? sUrl.substring(iCond): sUrl.substring(iCond, iAmp);
		}
		return sParCond;
	}

	/**
	 * Handle all conditional keywords in a HTML form.
	 * 
	 * @param sText
	 *            the HTML text to examine
	 * @param bErrCond
	 *            is if_err true?
	 * @param sSpecials
	 *             the specials to look for
	 * @param logger
	 *            any logger
	 * @return the modified HTML text
	 */
	public static String handleAllConditionals(String sText, boolean bErrCond, String sSpecials, ISystemLogger logger)
	{
		final String sMethod = "handleAllConditionals";

		logger.log(Level.FINER, MODULE, sMethod, "error="+bErrCond+" specials="+sSpecials);
		sText = Utils.replaceConditional(sText, "[if_error,", ",", "]", bErrCond, logger);
		
		// 20131028, Bauke: added multiple conditions
		if (sSpecials != null) {
			String sParCond = getParameterValueFromUrl(sSpecials, "if_cond");
			// Can take the form: if_cond=condition1,condition2,...
			logger.log(Level.FINER, MODULE, sMethod, "parCond="+sParCond);
			if (sParCond != null) {
				// Replace true conditions
				String[] saCond = sParCond.split(",");
				for (int i = 0; i < saCond.length; i++) {
					// sText example: ...[if_cond,user_change,class="row",class="do_not_display"]...
					// First handle: if_cond,user_change
					logger.log(Level.FINER, MODULE, sMethod, "saCond["+i+"]="+saCond[i]);
					sText = Utils.replaceConditional(sText, "[if_cond,"+saCond[i]+",", ",", "]", true, logger);
					sText = Utils.replaceConditional(sText, "#if_cond,"+saCond[i]+"#", "#else_cond,"+saCond[i]+"#", "#end_cond,"+saCond[i]+"#", true, logger);
				}
			}
		}
		
		// Other conditions are false
		sText = Utils.removeAllConditionals(sText, "[if_cond,", ",", "]", logger);
		sText = Utils.removeAllConditionals(sText, "#if_cond,", "#else_cond,", "#end_cond,", logger);
		return sText;
	}

	/**
	 * Replace text based on a condition. Syntax:
	 * [&lt;keyword&gt;,&lt;true_branch&gt;,&lt;false_branch&gt;] Currently no
	 * escape mechanism for the comma and right bracket.
	 * 
	 * @param sText
	 *            The source text.
	 * @param sKeyword
	 *            The keyword used to look for the conditional replacement.
	 * @param sMidSep
	 *            the mid separator
	 * @param sFinal
	 *            the final string
	 * @param bCondition
	 *            Use the true branch of the condition?
	 * @param logger
	 *            the logger
	 * @return result with replacements applied
	 */
	public static String replaceConditional(String sText, String sKeyword, String sMidSep, String sFinal, boolean bCondition, ISystemLogger logger)
	{
		String sMethod = "replaceConditional";
		String sSearch = sKeyword; // "[" + sKeyword + ",";
		int idx, len = sSearch.length();
		String sResult = "";
		
		// 20131030, Bauke: added sMidSep and sFinal parameters
		// Replace constructions like: [if_cond,org_login,password,user_id]
		//                             ^idx...............        ^mid    ^fin
		// And: #if_cond,ui_mobile#<true_part>#else_cond,ui_mobile#<false_part>#end_cond,ui_mobile#\n...
		//      ^idx...............<true_part>^mid.................<false_part>^fin................
		//
		if (sText == null)
			return sText;

		// RH, 20100622, use of ASelectLogger causes cyclic dependency server<->system
		if (logger!=null) logger.log(Level.FINER, MODULE, sMethod, "Search="+sSearch);
		while (true) {
			idx = sText.indexOf(sSearch);
			if (idx < 0)
				break;
			//if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "Text="+Utils.firstPartOf(sText.substring(idx), 15)+" idx="+idx);
			int iMid = sText.indexOf(sMidSep/*","*/, idx + len);
			int iFinal = sText.indexOf(sFinal/*"]"*/, (iMid >= 0) ? iMid+1 : idx + len);
			//if (logger!=null) logger.log(Level.INFO, MODULE, sMethod, "comma="+iComma+" right="+iRight);
			if (iFinal < 0) {
				sResult += sText.substring(0, idx + len);
				sText = sText.substring(idx + len);
				continue;
			}
			if (iMid < 0) {
				sResult += sText.substring(0, iFinal+1);
				sText = sText.substring(iFinal+1);
				continue;
			}
			// sMid and sFinal found
			if (bCondition) {  // Use the true part
				sResult += sText.substring(0, idx) + sText.substring(idx + len, iMid);
			}
			else {  // Use the false part
				sResult += sText.substring(0, idx) + sText.substring(iMid+sMidSep.length(), iFinal);
			}
			sText = sText.substring(iFinal+sFinal.length());
		}
		return sResult + sText;
	}
	
	/**
	 * Replace all unused or false conditions. Syntax:
	 * [&lt;keyword&gt;,&lt;true_branch&gt;,&lt;false_branch&gt;].
	 * Currently no escape mechanism for the comma and right bracket.
	 * 
	 * @param sText
	 * 			The source text.
	 * @param sKeyword
	 *            The keyword used to look for the conditional replacement.
	 * @return result with replacements applied
	 */
	public static String removeAllConditionals(String sText, String sKeyword, String sMidSep, String sFinal, ISystemLogger logger)
	{
		String sMethod = "removeAllConditionals";
		String sSearch = sKeyword;  // "[" + sKeyword + ",";
		int idx, len = sSearch.length();
		String sResult = "";
		
		// 20131030, Bauke: added sMidSep and sFinal
		// Remove constructions like: [if_cond,org_login,password,user_id]
		//                            ^idx.....org_login^mid     ^next   ^fin
		//		  sKeyword contains: "[if_cond,"
		// And: #if_cond,ui_mobile#<true_part>#else_cond,ui_mobile#<false_part>#end_cond,ui_mobile#...
		//      ^idx.....         ^idx2       ^mid.......                      ^fin......
		//
		if (sText == null)
			return sText;
		if (logger!=null) logger.log(Level.FINER, MODULE, sMethod, "Search="+sSearch);
		
		while (true) {
			//logger.log(Level.INFO, MODULE, sMethod, "Text="+Utils.firstPartOf(sText, 45));
			idx = sText.indexOf(sSearch);
			if (idx < 0)
				break;
			int len2 = 0;
			String sFullMid = sMidSep, sFullFin = sFinal;
			if (sText.charAt(idx) == '#') {  // need to skip "ui_mobile#" too!
				int idx2 = sText.indexOf("#", idx+len);
				if (idx2 >= 0) {
					// Add condition part to allow nested conditions
					len2 = ((idx2+1)-idx)-len;
					String sCond = sText.substring(idx+len, idx2+1);
					sFullMid = sMidSep + sCond; 
					sFullFin = sFinal + sCond;
					//logger.log(Level.FINER, MODULE, sMethod, "sCond="+sCond);
				}
			}
			//logger.log(Level.FINER, MODULE, sMethod, "idx="+idx+" Cond="+Utils.firstPartOf(sText.substring(idx), 60));
			int iMidSep = sText.indexOf(sFullMid/*","*/, idx+len+len2);
			// Only one mid separator for the #if_cond construction, so don't set iNextMid
			int iNextMid = (sText.charAt(idx)=='#' || iMidSep < 0) ? -1: sText.indexOf(sFullMid/*","*/, iMidSep+sFullMid.length());
			if (sText.charAt(idx) == '#') {
				iNextMid = iMidSep;
			}
			int iFinal = (iNextMid < 0) ? -1: sText.indexOf(sFullFin/*"]"*/, iNextMid+sFullMid.length());
			//logger.log(Level.FINER, MODULE, sMethod, "mid="+iMidSep+" next="+iNextMid+" final="+iFinal);
			if (iFinal < 0) {  // skip keyword
				sResult += sText.substring(0, idx+len+len2);
				sText = sText.substring(idx+len+len2);
				//logger.log(Level.FINER, MODULE, sMethod, "SkipFinal="+Utils.firstPartOf(sText, 80));
				continue;
			}
			if (iMidSep < 0) {  // iNextMid can be -1
			//if (iNextMid < 0 || iMidSep < 0) {  // skip till end
				sResult += sText.substring(0, iFinal+sFullFin.length());
				sText = sText.substring(iFinal+sFullFin.length());
				//logger.log(Level.FINER, MODULE, sMethod, "SkipMid="+Utils.firstPartOf(sText, 80));
				continue;
			}
			// sMidSep and sFinal found, find and use the false part
			sResult += sText.substring(0, idx) + sText.substring(iNextMid+sFullMid.length(), iFinal);
			sText = sText.substring(iFinal+sFullFin.length());
			//logger.log(Level.FINER, MODULE, sMethod, "Continue="+Utils.firstPartOf(sText, 80));
		}
		return sResult + sText;
	}

	
	public static HashMap convertCGIMessage(String xMessage, boolean doUrlDecode)
	{
		return convertCGIMessage(xMessage, doUrlDecode, "&");
	}
	/**
	 * Converts a CGI-based String to a hashtable. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * This methods converts a CGI-based String containing
	 * <code>key=value&key=value</code> to a hashtable containing the keys and
	 * corresponding values. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * CGI-based input String (<code>xMessage</code>).<br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * All keys in the returned hashtable are converted to lowercase. <br>
	 * 
	 * @param xMessage
	 *            CGI-based input String.
	 * @param doUrlDecode
	 *            run URL decode on the parsed values
	 * @return HashMap containg the keys and corresponding values.
	 */
//	public static HashMap convertCGIMessage(String xMessage, boolean doUrlDecode)	// RH, 20201008, o
	public static HashMap convertCGIMessage(String xMessage, boolean doUrlDecode, String delimiters)	// RH, 20201008, n
	{
		String xToken, xKey, xValue;
		StringTokenizer xST = null;
		int iPos;
		HashMap<String, String> xResponse = new HashMap<String, String>();

		if (xMessage == null)
			return xResponse;

//		xST = new StringTokenizer(xMessage, "&");	// RH, 20201008, o
		xST = new StringTokenizer(xMessage, delimiters);	// RH, 20201008, n
		while (xST.hasMoreElements()) {
			xToken = (String) xST.nextElement();
			if (!xToken.trim().equals("")) {
				iPos = xToken.indexOf('=');
				if (iPos != -1) {
					xKey = xToken.substring(0, iPos);

					try {
						xValue = xToken.substring(iPos + 1);
					}
					catch (Exception e) {
						xValue = "";
					}

					if (xKey != null && xValue != null) {
						// 20120106, Bauke: added URL decode option
						if (doUrlDecode) {	// RH, 20120202, n, fix on option doUrlDecode
							try {
								xValue = URLDecoder.decode(xValue, "UTF-8");
							}
							catch (UnsupportedEncodingException e) {								
							}
						}	// RH, 20120202, n, fix on option doUrlDecode
						xResponse.put(xKey, xValue);
					}
				}
			}
		}
		return xResponse;
	}

	/**
	 * Convert <code>HashMap</code> to CGI message string. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Creates a CGI syntax message from the key/value pairs in the input <code>HashMap</code>.<br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * The used {@link java.util.HashMap}objects are synchronized. <br>
	 * <br>
	 * <b>Preconditions: </b> <br>
	 * <code>htInput</code> should be a HashMap containing valid parameters. <br>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * The return <code>String</code> contains the parameters in CGI syntax. <br>
	 * 
	 * @param htInput
	 *            The <code>HashMap</code> to be converted.
	 * @return CGI message containg all parameters in <code>htInput</code>.
	 * @throws UnsupportedEncodingException
	 *             If URL encoding fails.
	 */
	public static String hashtable2CGIMessage(HashMap htInput)
	throws UnsupportedEncodingException
	{
		StringBuffer sbBuffer = new StringBuffer();
		Set keys = htInput.keySet();
		for (Object s : keys) {
			String sKey = (String) s;
			// Enumeration enumKeys = htInput.keys();
			// boolean bStop = !enumKeys.hasMoreElements(); //more elements?
			// while (!bStop)
			// {
			// String sKey = (String)enumKeys.nextElement();
			Object oValue = htInput.get(sKey);
			if (oValue instanceof String) {
				sbBuffer.append(sKey);
				sbBuffer.append("=");
				// URL encode value
				String sValue = URLEncoder.encode((String) oValue, "UTF-8");
				sbBuffer.append(sValue);
			}
			else if (oValue instanceof String[]) {
				String[] strArr = (String[]) oValue;
				for (int i = 0; i < strArr.length; i++) {
					sbBuffer.append(sKey).append(ENCODED_BRACES);
					sbBuffer.append("=");
					String sValue = URLEncoder.encode(strArr[i], "UTF-8");
					sbBuffer.append(sValue);
					if (i < strArr.length - 1)
						sbBuffer.append("&");
				}
			}
			else if (oValue instanceof List) {	// Should be List of Strings
				List<String> l = (List<String>) oValue;
				ArrayList<String> aList = new ArrayList<String>(l);
				String[] strArr = {};
				strArr = 	aList.toArray(strArr);
				for (int i = 0; i < strArr.length; i++) {
					sbBuffer.append(sKey).append(ENCODED_BRACES);
					sbBuffer.append("=");
					String sValue = URLEncoder.encode(strArr[i], "UTF-8");
					sbBuffer.append(sValue);
					if (i < strArr.length - 1)
						sbBuffer.append("&");
				}
			}
			
			// if (enumKeys.hasMoreElements()) {
			// Append extra '&' after every parameter.
			sbBuffer.append("&");
			// }
		}
		int len = sbBuffer.length();
		return sbBuffer.substring(0, (len > 0) ? len - 1 : len);
	}

	/**
	 * Compare a string against another string that may contain wildcards. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Compares string <code>s</code> against <code>sMask</code>, where <code>sMask</code> may contain wildcards (* and
	 * ?). <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None <br>
	 * <br>
	 * 
	 * @param s
	 *            The string to compare against <code>sMask</code>.
	 * @param sMask
	 *            The mask to compare against. May contain wildcards.
	 * @return <code>true</code> if they match, <code>false</code> otherwise
	 */
	public static boolean matchWildcardMask(String s, String sMask)
	{
		// check empty string
		if (s.length() == 0) {
			if (sMask.length() == 0 || sMask.equals("*") || sMask.equals("?"))
				return true;
			return false;
		}

		char ch;
		int i = 0;
		StringCharacterIterator iter = new StringCharacterIterator(sMask);

		for (ch = iter.first(); ch != CharacterIterator.DONE && i < s.length(); ch = iter.next()) {
			if (ch == '?')
				i++;
			else if (ch == '*') {
				int j = iter.getIndex() + 1;
				if (j >= sMask.length())
					return true;
				String xSubFilter = sMask.substring(j);
				while (i < s.length()) {
					if (matchWildcardMask(s.substring(i), xSubFilter))
						return true;
					i++;
				}
				return false;
			}
			else if (ch == s.charAt(i)) {
				i++;
			}
			else
				return false;
		}

		return (i == s.length());
	}

	/**
	 * Does the string have a decent value (not null and length > 0).
	 * 
	 * @param sText
	 *        the string
	 * @return true, if successful
	 */
	public static boolean hasValue(String sText)
	{
		return (sText != null && sText.length() > 0);  // can use !isEmpty() in Java 1.6
	}
	
	/**
	 * First part of.
	 * 
	 * @param sValue
	 *            the s value
	 * @param max
	 *            the max
	 * @return the string
	 */
	public static String firstPartOf(String sValue, int max)
	{
		if (sValue == null)
			return "null";
		int len = sValue.length();
		return (len <= max) ? sValue : sValue.substring(0, max) + "...";
	}

	/**
	 * Copy hashmap value.
	 * 
	 * @param sName
	 *            the s name
	 * @param hmTo
	 *            the hm to
	 * @param hmFrom
	 *            the hm from
	 * @return the object
	 */
	public static Object copyHashmapValue(String sName, HashMap<String, Object> hmTo, HashMap<String, Object> hmFrom)
	{
		if (hmFrom == null || hmTo == null)
			return null;
		Object oValue = hmFrom.get(sName);
		if (oValue != null)
			hmTo.put(sName, oValue);
		return oValue;
	}

	/**
	 * Copy msg value to hashmap.
	 * 
	 * @param sName
	 *            the parameter name
	 * @param hmTo
	 *            the HashMap to copy to
	 * @param imFrom
	 *            the Input message to copy from
	 * @return the string
	 */
	public static String copyMsgValueToHashmap(String sName, HashMap<String, String> hmTo, IInputMessage imFrom)
	{
		String sValue = null;
		if (imFrom == null || hmTo == null)
			return null;
		try {
			sValue = imFrom.getParam(sName);
			if (sValue != null)
				hmTo.put(sName, sValue);
		}
		catch (Exception e) {
		}
		return sValue;
	}

	// Get 'sParam' within the 'oConfig' section
	// This can be the value of an attribute or the contents of a 'sParam' tag
	// Examples:
	// Get attribute value: (oApplication, "id", true)
	// Get tag value (need not be present): (oApplication, "friendly_name", false)
	//
	/**
	 * Gets the simple param.
	 * 
	 * @param oConfMgr
	 *            the config mgr
	 * @param oSysLog
	 *            the systemlogger
	 * @param oConfig
	 *            the config section
	 * @param sParam
	 *            the param to retrieve
	 * @param bMandatory
	 *            mandatory?
	 * @return the param value
	 * @throws ASelectException
	 */
	public static String getSimpleParam(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sParam,
			boolean bMandatory)
	throws ASelectException
	{
		final String sMethod = "getSimpleParam";
		try {
			return oConfMgr.getParam(oConfig, sParam); // is not null
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Config item '" + sParam + "' not found", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Gets a simple integer parameter from the configuration.
	 * 
	 * @param oConfMgr
	 *            the config mgr
	 * @param oSysLog
	 *            the systemlogger
	 * @param oConfig
	 *            the config section
	 * @param sParam
	 *            the param to retrieve
	 * @param bMandatory
	 *            mandatory?
	 * @return the param value as an integer
	 * @throws ASelectException
	 */
	public static int getSimpleIntParam(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sParam,
			boolean bMandatory)
	throws ASelectException
	{
		final String sMethod = "getSimpleIntParam";
		String sValue = getSimpleParam(oConfMgr, oSysLog, oConfig, sParam, bMandatory);

		try {
			if (sValue != null)
				return Integer.parseInt(sValue);
			if (!bMandatory)
				return -1;
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
		catch (NumberFormatException e) {
			if (!bMandatory)
				return -1;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Value of <" + sParam + "> is not an integer");
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	// Find the 'sParam' section within the 'oConfig' section
	// 'oConfig' can be null to get one of the top level sections
	// Example: (null, "aselect");
	/**
	 * Gets the simple section.
	 * 
	 * @param oConfMgr
	 *            the conf mgr
	 * @param oSysLog
	 *            the sys log
	 * @param oConfig
	 *            the config
	 * @param sSection
	 *            the section we're looking for
	 * @param bMandatory
	 *            the mandatory
	 * @return the simple section
	 * @throws ASelectConfigException
	 *             the aselect config exception
	 */
	public static Object getSimpleSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig, String sSection, boolean bMandatory)
	throws ASelectConfigException
	{
		final String sMethod = "getSimpleSection";
		Object oSection = null;

		oSysLog.log(Level.FINEST, MODULE, sMethod, "Param=" + sSection + " cfg=" + oConfMgr);
		try {
			oSection = oConfMgr.getSection(oConfig, sSection);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
//			oSysLog.log(Level.SEVERE, MODULE, sMethod, "Cannot find " + sSection + " section in config file", e);	// RH, 20150618, o
			// , we caanot be sure this is SEVERE yet
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Cannot find " + sSection + " section in config file", e);	// RH, 20150618, n
			throw e;
		}
		return oSection;
	}

	// Get 'sParam' within a node of the 'oConfig' section.
	// The name of the node must match the 'sSection' given.
	// If oConfig is null the global section is used.
	// Examples:
	// Get attribute value: (oConfig, "application", "id")
	// Get tag value: (null, "aselect", "redirect_url")
	//
	/**
	 * Gets the param from section.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sSection
	 *            the s section
	 * @param sParam
	 *            the s param
	 * @param bMandatory
	 *            the b mandatory
	 * @return the param from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static String getParamFromSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig,
			String sSection, String sParam, boolean bMandatory)
	throws ASelectConfigException
	{
		final String sMethod = "getParamFromSection";
		try {
			Object oSection = oConfMgr.getSection(oConfig, sSection);
			return oConfMgr.getParam(oSection, sParam);
		}
		catch (ASelectConfigException e) {
			if (!bMandatory)
				return null;
			oSysLog.log(Level.WARNING, MODULE, sMethod, "Could not retrieve '" + sParam + "' parameter in '" + sSection
					+ "' section", e);
			throw e;
		}
	}

	// Find section with given attribute name and value.
	// If oConfig is null the global section is used.
	// Example: (oConfig, "logging", "id=system")
	/**
	 * Gets the section from section.
	 * 
	 * @param oConfMgr
	 *            the o conf mgr
	 * @param oSysLog
	 *            the o sys log
	 * @param oConfig
	 *            the o config
	 * @param sParam
	 *            the s param
	 * @param sValue
	 *            the s value
	 * @param bMandatory
	 *            the b mandatory
	 * @return the section from section
	 * @throws ASelectConfigException
	 *             the a select config exception
	 */
	public static Object getSectionFromSection(ConfigManager oConfMgr, SystemLogger oSysLog, Object oConfig,
			String sParam, String sValue, boolean bMandatory)
	throws ASelectConfigException
	{
		final String sMethod = "getSectionFromSection";
		Object oLogSection = null;

		try {
			oLogSection = oConfMgr.getSection(oConfig, sParam, sValue);
		}
		catch (Exception e) {
			if (!bMandatory)
				return null;
//			oSysLog.log(Level.SEVERE, MODULE, sMethod, "No valid " + sParam + " section with " + sValue + " found", e);	// RH, 20150618, o
			// , we caanot be sure this is SEVERE yet
			oSysLog.log(Level.WARNING, MODULE, sMethod, "No valid " + sParam + " section with " + sValue + " found", e);	// RH, 20150618, n
			throw new ASelectConfigException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		return oLogSection;
	}

	// Localization
	// If no language/country is present in 'htSessionContext',
	// store the given values in it.
	/**
	 * Transfer localization.
	 * 
	 * @param htSessionContext
	 *            the session context
	 * @param sUserLanguage
	 *            the user language
	 * @param sUserCountry
	 *            the user country
	 */
	public static void transferLocalization(HashMap<String, Object> htSessionContext, String sUserLanguage,
			String sUserCountry)
	{
		if (htSessionContext == null)
			return;
		String sloc = (String) htSessionContext.get("language");
		if ((sloc == null || sloc.equals("")) && sUserLanguage != null && !sUserLanguage.equals("")) {
			htSessionContext.put("language", sUserLanguage);
			Utils.setSessionStatus(htSessionContext, "upd", null/*log*/);
		}
		sloc = (String) htSessionContext.get("country");
		if ((sloc == null || sloc.equals("")) && sUserCountry != null && !sUserCountry.equals("")) {
			htSessionContext.put("country", sUserCountry);
			Utils.setSessionStatus(htSessionContext, "upd", null/*log*/);
		}
	}

	// No organization gathering specified: no org_id in TGT
	// Organization gathering specified but no organization found or choice not made yet: org_id="" in TGT
	// Choice made by the user: org_id has a value
	// As long as org_id is present and empty no gathering will take place at all
	//
	public static boolean handleOrganizationChoice(HashMap<String, Object> htTGTContext, HashMap<String, String> hUserOrganizations)
	{
		String sOrgId = "";
		if (hUserOrganizations == null || hUserOrganizations.size() == 0)
			return false;  // no organizations, no choice
	
		if (hUserOrganizations.size() == 1) {
			Set<String> keySet = hUserOrganizations.keySet();
			Iterator<String> it = keySet.iterator();
			sOrgId = it.next();  // no choice needed
		}
		htTGTContext.put("org_id", sOrgId);  // empty or filled with the chosen org
		return (sOrgId != null && sOrgId.equals(""));
	}

	
	/**
	 * Serialize attributes contained in a HashMap. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method serializes attributes contained in a HashMap:
	 * <ul>
	 * <li>They are formatted as attr1=value1&attr2=value2;...
	 * <li>If a "&amp;" or a "=" appears in either the attribute name or value, they are transformed to %26 or %3d
	 * respectively.
	 * <li>The end result is base64 encoded.
	 * </ul>
	 * <br>
	 * 
	 * @param htAttributes - HashMap containing all attributes
	 * @return Serialized representation of the attributes
	 * @throws ASelectException - If serialization fails.
	 */
//	public static String serializeAttributes(Map htAttributes)	// RH, 20200612, o
	public static String serializeAttributes(Map htAttributes,  ISystemLogger logger)	// RH, 20200612, n
	throws ASelectException
	{
		final String sMethod = "serializeAttributes";
		try {
			if (htAttributes == null || htAttributes.isEmpty())
				return null;
			StringBuffer sb = new StringBuffer();
	
			Set keys = htAttributes.keySet();
			for (Object s : keys) {
				String sKey = (String) s;
				// for (Enumeration e = htAttributes.keys(); e.hasMoreElements(); ) {
				// String sKey = (String)e.nextElement();
				Object oValue = htAttributes.get(sKey);
	
				if (oValue instanceof Iterable) {// it's a multivalue attribute
					Iterable vValue = (Iterable) oValue;
	
					sKey = URLEncoder.encode(sKey + "[]", "UTF-8");
//					Enumeration eEnum = vValue.elements();
					Iterator itr =  vValue.iterator();
					// RH, 20200612, so
//					while (itr.hasNext()) {
//						String sValue = (String) itr.next();
//	
//						// add: key[]=value
//						sb.append(sKey).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
//						if (itr.hasNext())
//							sb.append("&");
//					}
					// RH, 20200612, eo
					// RH, 20200612, sn
					sb.append(sKey).append("=");
					while (itr.hasNext()) {	// fix, this did not allow empty valued elements
//						String sValue = (String) itr.next();	// RH, 20201203, o
						// RH, 20201203, sn
						String sValue = "";
						Object oSubValue = itr.next();
						if (oSubValue instanceof JSONObject) {
							sValue = ((JSONObject)oSubValue).toString(0);
							sb.append(URLEncoder.encode(sValue, "UTF-8"));
							if (itr.hasNext())
								sb.append("&").append(sKey).append("=");
						} else if (oSubValue instanceof String) {
							sValue = (String) oSubValue;
						// RH, 20201203, en
							// add: key[]=value
							sb.append(URLEncoder.encode(sValue, "UTF-8"));
							if (itr.hasNext())
								sb.append("&").append(sKey).append("=");
						// RH, 20201203, sn	
						} else {
							if (logger != null) {
								logger.log(Level.WARNING, MODULE, sMethod, "Unknown type of  attribute" + sKey);	// RH, 20190926, n	// RH, 20200612, o
							}
						}
						// RH, 20201203, en
					}
					// RH, 20200612, en
				}
				else if (oValue instanceof String) {// it's a single value attribute
					String sValue = (String) oValue;
					sb.append(URLEncoder.encode(sKey, "UTF-8")).append("=").append(URLEncoder.encode(sValue, "UTF-8"));
				}
	
				// if (e.hasMoreElements())
				sb.append("&");
			}
			int len = sb.length();
			String result = sb.substring(0, len - 1);
			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(result.getBytes("UTF-8"));
		}
		catch (Exception e) {
			// RH, 20190926, so
//			ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
//			logger.log(Level.WARNING, MODULE, sMethod, "Could not serialize attributes", e);
			// RH, 20190926, eo
			// RH, 20200612, sn
//			_oSysLog.log(Level.WARNING, MODULE, sMethod, "Could not serialize attributes", e);	// RH, 20190926, n	// RH, 20200612, o
			// RH, 20200612, sn
			if (logger != null) {
				logger.log(Level.WARNING, MODULE, sMethod, "Could not serialize attributes", e);	// RH, 20190926, n	// RH, 20200612, o
			}
			// RH, 20200612, en
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Deserialize attributes and convertion to a <code>HashMap</code>. <br/>
	 * Conatins support for multivalue attributes, with name of type <code>
	 * String</code> and value of type <code>Vector</code>.
	 * 
	 * @param sSerializedAttributes
	 *            the serialized attributes.
	 * @return The deserialized attributes (key,value in <code>HashMap</code>)
	 * @throws ASelectException
	 *             If URLDecode fails
	 */
//	public static HashMap deserializeAttributes(String sSerializedAttributes)	// RH, 20200612, o
	public static HashMap deserializeAttributes(String sSerializedAttributes, ISystemLogger logger)	// RH, 20200612, n
	throws ASelectException
	{
		String sMethod = "deSerializeAttributes";
		HashMap htAttributes = new HashMap();
		if (sSerializedAttributes != null) {  // Attributes available
			try {  // base64 decode
				BASE64Decoder base64Decoder = new BASE64Decoder();
				String sDecodedUserAttrs = new String(base64Decoder.decodeBuffer(sSerializedAttributes));
	
				// decode & and = chars
				String[] saAttrs = sDecodedUserAttrs.split("&");
				for (int i = 0; i < saAttrs.length; i++) {
					int iEqualChar = saAttrs[i].indexOf("=");
					String sKey = "";
					String sValue = "";
					Vector vVector = null;
	
					if (iEqualChar > 0) {
						sKey = URLDecoder.decode(saAttrs[i].substring(0, iEqualChar), "UTF-8");
						sValue = URLDecoder.decode(saAttrs[i].substring(iEqualChar + 1), "UTF-8");
	
						if (sKey.endsWith("[]")) { // it's a multi-valued attribute
							// Strip [] from sKey
							sKey = sKey.substring(0, sKey.length() - 2);
							if ((vVector = (Vector) htAttributes.get(sKey)) == null)
								vVector = new Vector();
							vVector.add(sValue);
						}
					}
					else
						sKey = URLDecoder.decode(saAttrs[i], "UTF-8");
	
					if (vVector != null)  // store multivalue attribute
						htAttributes.put(sKey, vVector);
					else  // store singlevalue attribute
						htAttributes.put(sKey, sValue);
				}
			}
			catch (Exception e) {
				// RH, 20190926, so
//				ASelectSystemLogger logger = ASelectSystemLogger.getHandle();
//				logger.log(Level.WARNING, Utils.MODULE, sMethod, "Error during deserialization of attributes", e);
				// RH, 20190926, eo
//				_oSysLog.log(Level.WARNING, Utils.MODULE, sMethod, "Error during deserialization of attributes", e);	// RH, 20190926, n	// RH, 20200612, o
				// RH, 20200612, sn
				if (logger != null) {
					logger.log(Level.WARNING, Utils.MODULE, sMethod, "Error during deserialization of attributes", e);	// RH, 20190926, n
				}
				// RH, 20200612, en
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}
		return htAttributes;
	}
	
	public static boolean bsnCheck(String bsnNumber)
	{
		final int bsnModuloNumber = 11;
		final int bsnLength = 9;

		boolean testOK = false;
		int len = bsnNumber.length();
		int weightedSum = 0;
		boolean isNumberOK = (bsnLength == len);
		for (int i=0;isNumberOK && i<len-1;i++) {
			if (Character.isDigit(bsnNumber.charAt(i))) {
				weightedSum += (len-i)*Character.getNumericValue(bsnNumber.charAt(i));
			} else {
				isNumberOK = false;
			}
		}
		if (isNumberOK && (weightedSum % bsnModuloNumber == Character.getNumericValue(bsnNumber.charAt(len-1))) ) {
			testOK = true;
		}
		return testOK;
	}
	
	/**
	 * Load properties from file.
	 * 
	 * @param oSysLog
	 *            the system logger
	 * @param sWorkingDir
	 *            The working directory
	 * @param sSubDir
	 *            the authsp subdirectory
	 * @param sFileName
	 *            the name of the template that must be loaded (can be without .html)
	 * @param sLanguage
	 *            the language version
	 * @return the properties
	 * @throws ASelectException
	 */
	public static Properties loadPropertiesFromFile(SystemLogger oSysLog, String sWorkingDir, String sSubDir,
					String sFileName, String sLanguage)
	throws ASelectException
	{
		String sErrorsConf = Utils.loadTemplateFromFile(oSysLog, sWorkingDir, sSubDir,
				sFileName, sLanguage, null, null);
		
		Properties propErrorMessages = new Properties();
		try {
			propErrorMessages.load(new StringReader(sErrorsConf));
		}
		catch (IOException e) {
			throw new ASelectException(Errors.ERROR_ASELECT_PARSE_ERROR);
		}
		return propErrorMessages;
	}

	/**
	 * Loads a html template from harddisk.
	 * For example:
	 *	 aselectserver/conf/html/directlogin_nl.html
	 *	 authspserver/conf/sms/html/authenticate.html
	 * 
	 * @param oSysLog
	 *            the system logger
	 * @param sWorkingDir
	 *            The working directory
	 * @param sSubDir
	 *            the authsp subdirectory
	 * @param sFileName
	 *            the name of the template that must be loaded (can be without .html)
	 * @param sLanguage
	 *            the language version
	 * @param sFriendlyName
	 *            the friendly name
	 * @param sVersion
	 *            the version
	 * @return The loaded HTML template.
	 * @throws ASelectException
	 *             if loading fails.
	 */
	// 20141119, Bauke: Merge from aselectserver and authspserver versions
	public static String loadTemplateFromFile(SystemLogger oSysLog, String sWorkingDir, String sSubDir,
					String sFileName, String sLanguage, String sFriendlyName, String sVersion)
	throws ASelectException
	{
		String sMethod = "loadTemplateFromFile";
		String sTemplate = "";
		String sExtension = ".html";
		String sExtSubDir = "html";

		// Support these example file paths:
		//   aselectserver/conf/html/directlogin_nl.html  (sSubDir = null)
		//   authspserver/conf/sms/html/authenticate.html (sLanguage = null)
		// Error files:
		//   authspserver/conf/ldap/errors/errors.conf (sFileName ends with .conf and subdir is set)
		//   aselectserver/conf/errors/errors_nl.conf (sFileName ends with .conf)
		
		String sLangExt = (Utils.hasValue(sLanguage))? "_" + sLanguage.toLowerCase(): "";
		if (sFileName.endsWith(".conf")) {
			sExtension = ".conf";  // errors.conf file detected
			sExtSubDir = "errors";
			sFileName = sFileName.substring(0, sFileName.length()-5);
		}
		else if (sFileName.endsWith(".html")) {
			sExtension = ".html";
			sExtSubDir = "html";
			sFileName = sFileName.substring(0, sFileName.length()-5);
		}
		// else html file without extension
		
		for (;;) {
			StringBuffer sbFilePath = new StringBuffer(sWorkingDir).append(File.separator).append("conf");
			if (Utils.hasValue(sSubDir))
				sbFilePath = sbFilePath.append(File.separator).append(sSubDir);
			sbFilePath = sbFilePath.append(File.separator).append(sExtSubDir).
					append(File.separator).append(sFileName).append(sLangExt).append(sExtension);
			String sFilePath = sbFilePath.toString();
			
			// get file
			sTemplate = FileCache.getFile(sFilePath, oSysLog);
			if (Utils.hasValue(sTemplate))
				break;
			
			if (sLangExt.equals("")) { // already tried the default
				oSysLog.log(Level.WARNING, MODULE, sMethod, "Required template not found: "+sFilePath);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}
			sLangExt = ""; // try the default file
		}
		if (Utils.hasValue(sVersion))
			sTemplate = Utils.replaceString(sTemplate, "[version]", sVersion);  // 20141118 old: Version.getVersion());
		if (Utils.hasValue(sFriendlyName))
			sTemplate = Utils.replaceString(sTemplate, "[organization_friendly]", sFriendlyName);
							// 20141118 old: getParam(_oASelectConfigSection, "organization_friendly_name"));
		return sTemplate;
	}

	/**
	 * Prepare for html output.
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @return the newly created PrintWriter
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrintWriter prepareForHtmlOutput(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
	throws IOException
	{
		return prepareForHtmlOutput(servletRequest, servletResponse, null);
	}

	/**
	 * Prepare for html output. Content type can be specified
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param sContentType
	 *            the content type
	 * @return the newly created PrintWriter
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrintWriter prepareForHtmlOutput(HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sContentType)
	throws IOException
	{
		String sMethod = "prepareForHtmlOutput";
		
		// NOTE: Content type must be set before getwriter()
		prepareForHttpResponse(servletRequest, servletResponse, sContentType);		
		if (_oSysLog != null)
			_oSysLog.log(Level.FINEST, MODULE, sMethod, "Create PrintWriter "+servletResponse.toString());
		PrintWriter pwOut = servletResponse.getWriter();
		return pwOut;
	}	

	/**
	 * Prepare for other (non html) output or redirection. UTF-8 and no cacheing will be set too.
	 * Specify your own content-type in the arguments (no need for "utf-8" part).
	 * 
	 * @param servletRequest
	 *            the servlet request
	 * @param servletResponse
	 *            the servlet response
	 * @param sContentType
	 *            the content type
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void prepareForHttpResponse(HttpServletRequest servletRequest,
			HttpServletResponse servletResponse, String sContentType)
	throws IOException
	{
		String sMethod = "prepareForHttpResponse";
		
		if (!Utils.hasValue(sContentType))
			sContentType = "text/html";
		if (_oSysLog != null)
			_oSysLog.log(Level.FINEST, MODULE, sMethod, "HTTP headers: no-cache utf-8 "+sContentType);
		servletResponse.setContentType(sContentType);
		servletResponse.setCharacterEncoding("utf-8");
		setDisableCachingHttpHeaders(servletRequest, servletResponse);
	}

	/**
	 * Set HTTP headers that disable browser caching. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Sets HTTP 1.0 or HTTP 1.1 disable caching headers depending on the request. <br>
	 * <br>
	 * <b>Preconditions: </b>
	 * <ul>
	 * <li><code>oRequest != null</code></li>
	 * <li><code>oResponse != null</code></li>
	 * </ul>
	 * <br>
	 * <b>Postconditions: </b> <br>
	 * <code>oResponse</code> contains caching disable headers. <br>
	 * 
	 * @param oRequest
	 *            The HTTP request.
	 * @param oResponse
	 *            The HTTP response.
	 */
	public static void setDisableCachingHttpHeaders(HttpServletRequest oRequest, HttpServletResponse oResponse)
	{
		// turn off caching
		if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.0")) {
			oResponse.setHeader("Pragma", "no-cache");
		}
		else if (oRequest.getProtocol().equalsIgnoreCase("HTTP/1.1")) {
			oResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		}
		// turn off caching by proxies
		oResponse.setHeader("Expires", "-1");
	}

	/**
	 * Escape a search value for Ldap search().
	 * 
	 * @param sEscapedUid
	 *     the uid to be escaped
	 *
	 * @param sLdapEscapes
	 *     the ldap escape instructions to be applied, the first character serves as <instr_sep>, the second as <assign_sep>
	 *     Format of a single instruction: <string_to_be_repaced><assign_sep><replacement_string>
	 *     format: <instr_sep><assign_sep><instr_sep><replacement_instruction><instr_sep><replacement_instruction><instr_sep>...
	 *
	 * @return the escaped value
	 */
	public static String ldapEscape(String sEscapedUid, String sLdapEscapes, SystemLogger oSysLog)
	{
		String sMethod = "ldapEscape";
		
		if (Utils.hasValue(sLdapEscapes) && sLdapEscapes.length() > 2) {
			//  <ldap_escapes>_=_,=\,_*=\\2a_\=\\5c_(=\\28_)=\\29</ldap_escapes>
			oSysLog.log(Level.FINER, MODULE, sMethod, "ldap_escapes="+sLdapEscapes);
			String sGroupSep = sLdapEscapes.substring(0, 1);
			String sReplSep = sLdapEscapes.substring(1, 2);
			String[] aSplit = sLdapEscapes.split(sGroupSep);
			for (int i=2; i<aSplit.length; i++) {
				// *=\\2a
				String[] aRepl = aSplit[i].split(sReplSep);
				if (aRepl.length > 1) {
					sEscapedUid = sEscapedUid.replace(aRepl[0], aRepl[1]);
				}
				oSysLog.log(Level.FINEST, MODULE, sMethod, "i="+i+" instr:"+aSplit[i]+" esc="+sEscapedUid);
			}			
		}
		return sEscapedUid;
	}
	
	/**
	 * @return
	 * @throws ASelectException 
	 */
	public static DocumentBuilderFactory createDocumentBuilderFactory(SystemLogger oSysLog) throws ASelectCommunicationException
	{
		String sMethod = "createDocumentBuilderFactory";
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setExpandEntityReferences(false);
		dbFactory.setIgnoringComments(true);	// RH, 20210930, n
		// RH, 20210318, sn
//		dbFactory.setXIncludeAware(false);	// defaults to false
		// RH, 20210318, en
		
		try {
			// RH, 20210318, sn
			dbFactory.setAttribute(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			dbFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			// In future versions we might want to assign a schema but for now disallow
			dbFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
			// RH, 20210318, en
			dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", 
		                   true);
//			dbFactory.setFeature("http://apache.org/xml/features/external-general-entities", 
//	                   false);
//			dbFactory.setFeature("http://apache.org/xml/features/external-parameter-entities", 
//	                   false);
			dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", 
	                   false);
		} 
		catch (ParserConfigurationException e) {
			if (oSysLog != null) {
				oSysLog.log(Level.SEVERE, MODULE, sMethod, "Cannot set required parser feature", e);
			}
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

		return dbFactory;
	}

	/**
	 * 
	 * @param sHandle
	 * 
	 * @return
	 * Returns UUID format of input. 		8-4-4-4-12[:8-4-4-4-12]*
	 */
	public static String format2quasiuuid(String sHandle) {
		String template = "00000000000000000000000000000000";
		StringBuffer buffer = new StringBuffer();
		int chunks = ( (sHandle.length() - 1) / template.length() ) + 1;
		for (int i = 0; i <chunks; i++) {
			if (i>0) {
				buffer.append(":");
			}
			buffer.append(template);
			String part = sHandle.substring(i*template.length(), Math.min( (i+1)*template.length(), sHandle.length() ));
			buffer.replace( buffer.length() - part.length(), buffer.length() , part);
			// some hanky-panky for the dashes
			buffer.insert( (i*(template.length()+5))+20, "-").insert((i*(template.length()+5))+16, "-").insert((i*(template.length()+5))+12, "-").insert((i*(template.length()+5))+8, "-");
		}
		return buffer.toString();
	}

	// RH, 20190211, sn
	public static String parseSessionVariable(Map session, String sToParse, String leftParenthesis, String rightParenthesis, SystemLogger oSysLog)
	{
		String sMethod = "parseConfigSessionVariable";
		if (sToParse != null && leftParenthesis != null && rightParenthesis != null && sToParse.contains(leftParenthesis) && sToParse.contains(rightParenthesis)) {
			StringBuffer sb = new StringBuffer(sToParse);
			int len = sb.length();
			int li = sb.indexOf(leftParenthesis);
			String sesvalue = "";
			while (li > -1 && len > li) {
				int ri = sb.indexOf(rightParenthesis, li);
				if ( ri > li ) {
					oSysLog.log(Level.FINEST, MODULE, sMethod, "li:" + li + ", ri:" + ri);
					String var = sb.substring(li+1, ri);	// cut off parenthesis as well
					oSysLog.log(Level.FINEST, MODULE, sMethod, "Parsing variable:" + var);
					String operation = null;
					if (var != null && var.startsWith(OPERATORPREFIX_URLDECODE)) {	// Maybe parameterize this
						operation = OPERATOR_URLDECODE;
						var = var.substring(OPERATORPREFIX_URLDECODE.length());
					}
					if (session != null && (sesvalue = (String)session.get(var)) != null) {
						oSysLog.log(Level.FINEST, MODULE, sMethod, "Found session variable value:" + Auxiliary.obfuscate(sesvalue));
					} else {
						sesvalue= "";	// clear possible null value
					}
					if (operation != null) {
						if (OPERATOR_URLDECODE.equals(operation)) {	// allows for other operators
							try {
								sesvalue = URLDecoder.decode(sesvalue, "UTF-8");
							} catch (UnsupportedEncodingException | IllegalArgumentException e) {
								sesvalue = "";	// a bit arbitrary but decided to not include any data
								oSysLog.log(Level.WARNING, MODULE, sMethod, "Could not urldecode:" + e.getMessage());
							}
						}
					}
					sb.replace(li, ri+1, sesvalue);	
					li += sesvalue.length();
				} else {
					oSysLog.log(Level.WARNING, MODULE, sMethod, "No variable or no matching Right parenthesis found for Left parenthesis on position: " + li);
					li++;	// skip single left parenthesis
				}
				li = sb.indexOf(leftParenthesis, li);	// resets to -1 if not found
			}
			oSysLog.log(Level.FINEST, MODULE, sMethod, "Parsing finished");
			sToParse = sb.toString();
		} else {
			oSysLog.log(Level.FINEST, MODULE, sMethod, "No parsable parameters passed to method, returning unmodified value");
		}
		return sToParse;
	}
	// RH, 20190211, en

}