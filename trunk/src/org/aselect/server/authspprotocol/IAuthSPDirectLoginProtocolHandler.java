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
 * $Id: IAuthSPDirectLoginProtocolHandler.java,v 1.3 2006/04/26 12:16:36 tom Exp $ 
 * 
 * Changelog:
 * $Log: IAuthSPDirectLoginProtocolHandler.java,v $
 * Revision 1.3  2006/04/26 12:16:36  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.2  2006/04/12 13:18:38  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.1.2.3  2006/04/07 09:51:52  leon
 * added javadoc
 *
 * Revision 1.1.2.2  2006/04/03 12:57:45  erwin
 * - Fixed error handling during initialization.
 * - Removed some warnings
 *
 * Revision 1.1.2.1  2006/03/20 10:10:56  leon
 * New interface for direct authsp handling
 *
 */

package org.aselect.server.authspprotocol;

import java.io.PrintWriter;
import java.util.HashMap;

import javax.servlet.http.HttpServletResponse;

import org.aselect.system.exception.ASelectAuthSPException;
import org.aselect.system.exception.ASelectException;

// TODO: Auto-generated Javadoc
/**
 * Interface that all AuthSP API protocol handlers should implement. <br>
 * <br>
 * <b>Description:</b><br>
 * Interface that all AuthSP API protocol handlers should implement. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * - <br>
 * 
 * @author Alfa & Ariss
 */
public interface IAuthSPDirectLoginProtocolHandler
{

	/**
	 * Initializes the AuthSP direct login protocol handler. <br>
	 * <br>
	 * <b>Description: </b> <br>
	 * Initializes the AuthSP protocol direct login handler with AuthSP handler specific configuration and resources. <br>
	 * <br>
	 * <b>Concurrency issues: </b> <br>
	 * - <br>
	 * <b>Preconditions: </b> <br>
	 * - <br>
	 * <b>Postconditions: </b> <br>
	 * -
	 * 
	 * @param sAuthSPId
	 *            <code>String</code> containing the AuthSP Id.
	 * @throws ASelectAuthSPException
	 *             If initialization fails.
	 */
	public void init(String sAuthSPId)
		throws ASelectAuthSPException;

	/**
	 * Handles the direct_login requests <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Handles the direct_login requests <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * .
	 * 
	 * @param htServiceRequest
	 *            the ht service request
	 * @param servletResponse
	 *            the servlet response
	 * @param pwOut
	 *            the pw out
	 * @param sServerId
	 *            the s server id
	 * @param sLanguage
	 *            the s language
	 * @param sCountry
	 *            the s country
	 * @throws ASelectException
	 *             the a select exception
	 */
	public void handleDirectLoginRequest(HashMap htServiceRequest, HttpServletResponse servletResponse,
			PrintWriter pwOut, String sServerId, String sLanguage, String sCountry)
		throws ASelectException;

}
