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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.logging.Level;

import org.aselect.server.attributes.requestors.GenericAttributeRequestor;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectException;
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
	
	private String _format = null;
	private String _algorithm = null;


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
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		final String sMethod = "getAttributes";

		try {
			String sUID = (String)(_bFromTgt? htTGTContext: hmAttributes).get(_sUseKey);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "vAttr="+vAttributes+" hmAttr="+hmAttributes+" "+_sUseKey+"="+Auxiliary.obfuscate(sUID)+" fromTgt="+_bFromTgt);

			if (!Utils.hasValue(sUID)) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Attribute '"+_sUseKey+"' not found, from_tgt="+_bFromTgt);
				return null;
			}

			if (vAttributes == null)
				return null;

			HashMap htAttrs = new HashMap();
			for (Enumeration e = vAttributes.elements(); e.hasMoreElements();) {
				// Calculate opaque handle
//				MessageDigest md = MessageDigest.getInstance("SHA1");	// RH, 20171106, o
				MessageDigest md = MessageDigest.getInstance(_algorithm);	// RH, 20171106, n
				md.update(sUID.getBytes("UTF-8"));
				String sHandle = Utils.byteArrayToHexString(md.digest());
				//  RH, 20171106, sn
				if ("UUID".equals(_format)) {
					sHandle = Utils.format2quasiuuid(sHandle);
				}
				//  RH, 20171106, en

				// Return result in a HashMap
				htAttrs.put(e.nextElement(), sHandle);
			}
			return htAttrs;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to generate opaque handle", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

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
	
	public static void main(String[] args)	// for testing
	{
//		String sUID = "12345dfk;sf;sf;sldfj;sldf;slfj;l;leer;ewr;re;lf;ladf;ldsf;lerfje;lfj;dlf;sldf;sdlf;lwef;f;lf;sdlf;sdf;sdf;sdfj;sfj;sdfj;sldf;sldf;lsdf;lsdf";
//		String sUID = "12345";
		String sUID = "";
		MessageDigest md;
		try {
//			md = MessageDigest.getInstance("MD5");
//			md = MessageDigest.getInstance("SHA-1");
			md = MessageDigest.getInstance("SHA1");
//			md = MessageDigest.getInstance("SHA-224");
//			md = MessageDigest.getInstance("SHA-256");
//			md = MessageDigest.getInstance("SHA-384");
//			md = MessageDigest.getInstance("SHA-512");
//			md = MessageDigest.getInstance("SHA3-256");
			md.update(sUID.getBytes("UTF-8"));
			String sHandle = Utils.byteArrayToHexString(md.digest());
			System.out.println("Hex:" + sHandle + ", length (chars):" + sHandle.length());
			String hash = Utils.format2quasiuuid(sHandle);
			
			System.out.println("Hex representation:" + hash + ", length (chars):" + hash.length());
		}
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
