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
 * $Id: OpaqueAttributeRequestor.java,v 1.7 2006/05/03 09:32:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: OpaqueAttributeRequestor.java,v $
 * Revision 1.7  2006/05/03 09:32:06  tom
 * Removed Javadoc version
 *
 * Revision 1.6  2005/03/30 14:25:58  martijn
 * the getAttributes() method needs an TGT context instead of the A-Select user id
 *
 * Revision 1.5  2005/03/29 08:58:05  tom
 * Fixed javadoc
 *
 * Revision 1.4  2005/03/17 15:19:59  martijn
 * removed unused imports
 *
 * Revision 1.3  2005/03/17 14:08:48  remco
 * changed attribute functionality
 *
 * Revision 1.2  2005/03/17 10:12:34  martijn
 * interface changes: getAttributes() will now throw an ASelectAttributesException
 *
 * Revision 1.1  2005/03/17 10:06:58  erwin
 * renamed and made compatible with new interface.
 *
 * Revision 1.1  2005/03/16 13:12:11  remco
 * added attributes (initial version)
 *
 */
package org.aselect.server.attributes.requestors.opaque;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.UUID;
import java.util.Vector;
import java.util.logging.Level;

import org.apache.commons.codec.binary.Base64;
import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BaseMultiEncDec;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;


/**
 * Generate an "opaque handle" attribute from the user id <br>
 * <br>
 * <b>Description:</b><br>
 * Generates the SHA1 of the user id and returns this as an attribute. The name of the attribute must be configured in
 * the configuration section of this attribute requestor. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class OpaqueAttributeRequestor extends GenericAttributeRequestor
{
	final private String MODULE = "OpaqueAttributeRequestor";
	final private int MAXRANDOMBYTESDECIMALWIDTH = 5;	// RH, 20190716, n, We will not allow ridiculous large bytearrays, max 99999 bytes
	
	private String _format = null;
	private String _algorithm = null;
	private String _precoding = null;	// RH, 20180601, n

	private boolean _silent = false;	// RH, 20180628, n
	private boolean _urlsafe = false;	// RH, 20180628, n


	/**
	 * Retrieve attributes from opaquehandler. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param vAttributes
	 *            the v attributes
	 * @return the attributes
	 * @throws ASelectAttributesException
	 *             the a select attributes exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(java.util.HashMap,
	 *      java.util.Vector)
	 */
	// RH, 20180601, sn
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		final String sMethod = "getAttributes";

		try {
			String sUID = (String)(_bFromTgt? htTGTContext: hmAttributes).get(_sUseKey);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "vAttr="+vAttributes+" hmAttr="+Auxiliary.obfuscate(hmAttributes)+" "+_sUseKey+"="+Auxiliary.obfuscate(sUID)+" fromTgt="+_bFromTgt);
			if (!Utils.hasValue(sUID)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute '"+_sUseKey+"' not found, from_tgt="+_bFromTgt);
				return null;
			}

			if (vAttributes == null)
				return null;

			// Calculate opaque handle
			byte[] digest_input;
			if ("BASE64DECODE".equalsIgnoreCase(_precoding) || "BASE64".equalsIgnoreCase(_precoding)) {
				digest_input = Base64.decodeBase64(sUID);
			} else if ("GUID".equalsIgnoreCase(_precoding)) {
				digest_input = uuidToBytes(sUID);
			} else if ("MSIMMUTABLEID".equalsIgnoreCase(_precoding)) {
				digest_input = Base64.decodeBase64(sUID);	// looks good. supports URL safe base64
				digest_input = SwapMSImmutable(digest_input);
			} else if ("VKBASE85DECODE".equalsIgnoreCase(_precoding)) { // BW, 20210927, n
				digest_input = BaseMultiEncDec.decodeVeryKreative85(sUID);
			} else if ("FROMHEX".equalsIgnoreCase(_precoding) || "FROMHEXSTRING".equalsIgnoreCase(_precoding)) {	// RH, 20210906, sn
				digest_input = Utils.hexStringToByteArray(sUID);
			} else { 	// RH, 20210906, en
				digest_input = sUID.getBytes("UTF-8");
			}
			
			byte[] digested;
			if ("NONE".equalsIgnoreCase(_algorithm)) {
				digested = digest_input;
			// RH, 20190716, sn
			} else if (_algorithm != null && _algorithm.startsWith("RANDOM")) {		// Already uppercase from init()
				String sByteLen = _algorithm.substring(6);	// Length of literal "RANDOM", take what is behind it
				if (sByteLen.length() > MAXRANDOMBYTESDECIMALWIDTH) {
					throw new Exception("Requested byte array too large, max number of digits = " + MAXRANDOMBYTESDECIMALWIDTH);
				}
				int byteLen = 0;
				try {
					byteLen = Integer.parseInt(sByteLen);
				} catch (NumberFormatException nfe) {
					throw new Exception(nfe);
				}
				digested = new byte[byteLen];
				SecureRandom.getInstance("SHA1PRNG").nextBytes(digested);
			// RH, 20190716, en
			} else if (_algorithm != null && _algorithm.startsWith("ENCRYPT")) {	// RH, 20210906, sn
				// for future extension we'll use startsWith()
				CryptoEngine cEngine = CryptoEngine.getHandle();
				String encrypted = cEngine.encryptTGT(digest_input);
				// We need a byte[] to continue
				digested = encrypted.getBytes("UTF-8");
			} else {	// RH, 20210906, en
				MessageDigest md = MessageDigest.getInstance(_algorithm);
				md.update(digest_input);
				digested = md.digest();
			}
			String sHandle = null;
			if ("UUID".equalsIgnoreCase(_format)) {
				sHandle = Utils.format2quasiuuid(Utils.byteArrayToHexString(digested));
			} else if ("BASE64ENCODE".equalsIgnoreCase(_format) || "BASE64".equalsIgnoreCase(_format)) {
				if (_urlsafe) {
					sHandle = Base64.encodeBase64URLSafeString(digested);
				} else {
					sHandle = Base64.encodeBase64String(digested);
				}
			} else if ("GUID".equalsIgnoreCase(_format)) {
			    sHandle = uuidFromBytes(digested);
			} else if ("MSIMMUTABLEID".equalsIgnoreCase(_format)) {
				digested = SwapMSImmutable(digested);
				if (_urlsafe) {
					sHandle = Base64.encodeBase64URLSafeString(digested);
				} else {
					sHandle = Base64.encodeBase64String(digested);
				}
			} else if ("VKBASE85ENCODE".equalsIgnoreCase(_format)) { // BW, 20210927, n
				sHandle = BaseMultiEncDec.encodeVeryKreative85(digested);
			} else if ("PLAIN".equalsIgnoreCase(_format)) {
				sHandle = new String(digested, "UTF-8");
			} else {
				sHandle = Utils.byteArrayToHexString(digested);
			}
			
			// Return result in a HashMap
			HashMap htAttrs = new HashMap();
			for (Enumeration e = vAttributes.elements(); e.hasMoreElements();) {
				htAttrs.put(e.nextElement(), sHandle);
			}
			return htAttrs;
		}
		catch (Exception e) {
			// RH, 20180628, sn
			if (_silent) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Silently ignoring exception opaque handle ", e);
				return null;
				// RH, 20180628, en
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to generate opaque handle", e);
//				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);		// RH, 20190716, o
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);		// RH, 20190716, n
			}
		}
	}
	// RH, 20180601, en

	
	/**
	 * Initialize the <code>OpaqueAttributeRequestor</code>. <br>
	 * <br>
	 * 
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#init(java.lang.Object)
	 */
	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		super.init(oConfig);

		_format = ASelectConfigManager.getSimpleParam(oConfig, "format", false);
		if (_format != null ) {
			_format = _format.toUpperCase();
		}
		_algorithm = ASelectConfigManager.getSimpleParam(oConfig, "algorithm", false);
		if (_algorithm == null || _algorithm.length() == 0) {
			_algorithm = "SHA1";	// Backwards compatibility
		} else {
			_algorithm = _algorithm.toUpperCase();
		}
		// RH, 20180601, sn
		_precoding = ASelectConfigManager.getSimpleParam(oConfig, "precoding", false);
		if (_precoding != null ) {
			_precoding = _precoding.toUpperCase();
		}
		// RH, 20180601, en
		// RH, 20180628, sn
		String sSilent = ASelectConfigManager.getSimpleParam(oConfig, "silent", false);
		if (sSilent != null ) {
			_silent = Boolean.parseBoolean(sSilent);
		}
		// RH, 20180628, en
		// RH, 20180628, sn
		String sURLSafe = ASelectConfigManager.getSimpleParam(oConfig, "urlsafe", false);
		if (sURLSafe != null ) {
			_urlsafe = Boolean.parseBoolean(sURLSafe);
		}
		// RH, 20180628, en

	}

	/**
	 * Destroys the <code>OpaqueAttributeRequestor</code>. <br>
	 * <br>
	 * 
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#destroy()
	 */
	public void destroy()
	{
		// Does nothing
	}

	private static String uuidFromBytes(byte[] highlow) {
	    ByteBuffer bb = ByteBuffer.wrap(highlow);
	    UUID uuid = new UUID(bb.getLong(), bb.getLong());
	    return uuid.toString();
	}

	private static byte[] uuidToBytes(String str) {
	    UUID uuid = UUID.fromString(str);
	    ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
	    bb.putLong(uuid.getMostSignificantBits());
	    bb.putLong(uuid.getLeastSignificantBits());
	    return bb.array();
	}

	// Only for 128 bits ( 16 bytes) byte[] )
	public static byte[] SwapMSImmutable(byte[] bytes) {
        
    	byte[] swappedBytes = new byte[16];
    	
    	//	MS typical marshalling-unmarshalling
    	//	last part no suprises
    	for (int i = 8 ; i < 16 ; i++) {	// lsb (last part) the same
    		swappedBytes[i] = bytes[i];
    	}

    	// now the MS specifics
    	swappedBytes[0] = bytes[3];
    	swappedBytes[1] = bytes[2];
    	swappedBytes[2] = bytes[1];
    	swappedBytes[3] = bytes[0];

    	swappedBytes[4] = bytes[5];
    	swappedBytes[5] = bytes[4];

    	swappedBytes[6] = bytes[7];
    	swappedBytes[7] = bytes[6];
    	//
    	return swappedBytes;
	}
	
}
