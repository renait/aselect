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
package org.aselect.server.request.handler.oauth2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.aselect.server.request.RequestState;
import org.aselect.server.request.handler.ProtoRequestHandler;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * OAUTH2 Resource RequestHandler. <br>
 * <br>
 * <b>Description:</b><br>
 * This class serves as a resource server for oauth2 requests
 *  It handles requests with a (valid) access_token and returns attributes from verify_credentials
 * <br>
 * <b>Concurrency issues:</b> <br>
 * 
 * @author RH
 */
public class ResourceHandler extends ProtoRequestHandler
{
	private final static String MODULE = "ResourceHandler";
	private final static String AUTH_CODE_PREFIX = "AUTH_CODE";
	
	private String _sMyServerID = null;
	private String sharedSecret = null;
	private String aselectServerURL = null;
	

	/* @param oServletConfig
	 *            the o servlet config
	 * @param oConfig
	 *            the o config
	 * @throws ASelectException
	 *             the a select exception
	 * @see org.aselect.server.request.handler.AbstractRequestHandler#init(javax.servlet.ServletConfig, java.lang.Object)
	 */
	@Override
	public void init(ServletConfig oServletConfig, Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";

		try {
			super.init(oServletConfig, oConfig);
			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find 'aselect' config section in config file", e);
				throw e;
			}

			try {
				_sMyServerID = _configManager.getParam(oASelect, "server_id");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'aselect' config section", e);
				throw e;
			}
			try {
				aselectServerURL = _configManager.getParam(oASelect, "redirect_url");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not retrieve 'server_id' config parameter in 'redirect_url' config section", e);
				throw e;
			}

			try {
				sharedSecret = _configManager.getParam(oConfig, "shared_secret");
			}
			catch (ASelectConfigException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "No config item 'shared_secret' found", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}

			
			
		}
		catch (ASelectException e) {
			throw e;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
	}

	/**
	 * Process incoming request.<br>
	 * 
	 * @param servletRequest
	 *            HttpServletRequest.
	 * @param servletResponse
	 *            HttpServletResponse.
	 * @return the request state
	 * @throws ASelectException
	 *             If processing of data request fails.
	 */
	public RequestState process(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
		throws ASelectException
	{
		String sMethod = "process";

		// rfc6750 says nothing about support GET or POST
		// token "bearer" must be in header ( we only support Authorization: bearer in http-header

		String auth_header = servletRequest.getHeader("Authorization");

		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found HTTP 'Authorization' header: " + auth_header);
		PrintWriter outwriter = null;
		try {
			outwriter = Utils.prepareForHtmlOutput(servletRequest, servletResponse, "application/json");
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Prepared output for application/json");
			int return_status = 400; // default
			HashMap<String, String> return_parameters = new HashMap<String, String>();

			if (auth_header != null) {
				StringTokenizer tkn = new StringTokenizer(auth_header);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "StringTokenizer created: " + tkn);
				if (tkn.countTokens() >= 2) {
					String bearer = tkn.nextToken();

					if ("bearer".equalsIgnoreCase(bearer)) {
						String access_token = tkn.nextToken();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Start verify credentials with access_token: "
								+ Auxiliary.obfuscate(access_token));
						try {
							BASE64Decoder b64dec = new BASE64Decoder();
							byte[] bytes_access_token = b64dec.decodeBuffer(access_token);
							String string_access_token = new String(bytes_access_token, "UTF-8");
							String sTGT = org.aselect.server.utils.Utils.decodeCredentials(string_access_token,
									_systemLogger);
							HashMap tgt = TGTManager.getHandle().getTGT(sTGT);
							if (tgt != null) {

								String rid = (String) tgt.get("rid");
								if (rid == null) { // should not happen
									_systemLogger.log(Level.SEVERE, MODULE, sMethod,
											"Could not retrieve RID from TGT, this should not happen!");
									return_parameters.put("error", "invalid_token");
									return_status = 401; // default
								}
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "Retrieved RID from TGT: " + rid);
								// do verify_credentials for latest attributes
								String finalResult = verify_credentials(servletRequest, string_access_token, rid);
								_systemLogger.log(Level.FINEST, MODULE, sMethod,
										"finalResult after verify_credentials: " + Auxiliary.obfuscate(finalResult));

								String extractedAttributes = finalResult.replaceFirst(".*attributes=([^&]*).*$", "$1");
								String extractedResultCode = finalResult.replaceFirst(".*result_code=([^&]*).*$", "$1");
								_systemLogger.log(Level.FINEST, MODULE, sMethod,
										"extractedResultCode after verify_credentials: " + extractedResultCode);
								_systemLogger.log(
										Level.FINEST,
										MODULE,
										sMethod,
										"extractedAttributes after verify_credentials: "
												+ Auxiliary.obfuscate(extractedAttributes));

								Boolean authenticatedAndApproved = false;
								try {
									authenticatedAndApproved = Boolean
											.valueOf(Integer.parseInt(extractedResultCode) == 0);
									if (authenticatedAndApproved) {

										String urlDecodedAttributes = null;
										try {
											urlDecodedAttributes = URLDecoder.decode(extractedAttributes, "UTF-8");
											if (urlDecodedAttributes != null) {
												return_parameters = org.aselect.server.utils.Utils
														.deserializeAttributes(urlDecodedAttributes);
											}
											_systemLogger.log(
													Level.FINEST,
													MODULE,
													sMethod,
													"Decoded attribute from aselectserver: "
															+ Auxiliary.obfuscate(return_parameters));
											return_status = 200; // OK, even when empty
										}
										catch (UnsupportedEncodingException e2) {
											_systemLogger.log(Level.SEVERE, MODULE, sMethod,
													"Could not URLDecode from UTF-8, this should not happen!");
											return_parameters.put("error", "invalid_token");
											return_status = 401; 

										}

									}
									else { // only happy flow implemented
										_systemLogger.log(Level.WARNING, MODULE, sMethod,
												"Could not verify credentials, failed with resultcode: "
														+ extractedResultCode);
										return_parameters.put("error", "invalid_token");
										return_status = 401;
									}
								}
								catch (NumberFormatException nfe) {
									_systemLogger.log(Level.WARNING, MODULE, sMethod,
											"Resultcode from aselectserver was non-numeric: " + extractedResultCode);
									return_parameters.put("error", "invalid_request");
									return_status = 400; // default
								}
							}
							else {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "TGT not found");
								return_parameters.put("error", "invalid_request");
								return_status = 400; // default
							}
						}
						catch (ASelectException as) {
							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot decrypt TGT: " + as.getMessage());
							return_parameters.put("error", "invalid_request");
							return_status = 400; // default
						}
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Authorization header not Bearer");
						return_parameters.put("error", "invalid_request");
						return_status = 400; // default
					}
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Invalid Authorization header received");
					return_parameters.put("error", "invalid_request");
					return_status = 400; // default

				}
			}
			else {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "No or empty Authorization header received");

				return_parameters.put("error", "invalid_request");
				return_status = 400; // default
			}
			if (return_status != 200) {
				servletResponse.setHeader("WWW-Authenticate", "Bearer realm=\"" + _sMyServerID + "\"" + " , " + "error=" + "\"" + return_parameters.get("error") + "\"");
			}
			servletResponse.setStatus(return_status);
			// return all JSON
			String out = ((JSONObject) JSONSerializer.toJSON(return_parameters)).toString(0);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Writing to client: " + out);
			outwriter.println(out);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Problem writing to client: " + e.getMessage());
		}
		finally {
			if (outwriter != null) {
				outwriter.close();
			}
		}
		return null;
	}

	/**
	 * @param request
	 * @param extracted_credentials
	 * @param sMethod
	 * @param extractedAselect_credentials
	 * @return 
	 * @throws ASelectCommunicationException
	 */
	private String verify_credentials(HttpServletRequest request, String extracted_credentials, String extractedRid)
	throws ASelectCommunicationException
	{
		String sMethod = "verify_credentials";
		String finalReqURL = aselectServerURL;
		String finalReqSharedSecret = sharedSecret;
		String finalReqAselectServer = _sMyServerID;
		String finalReqrequest= "verify_credentials";
		
		//Construct request data
		String finalRequestURL = null;
		try {
			finalRequestURL = finalReqURL + "?" + "shared_secret=" + URLEncoder.encode(finalReqSharedSecret, "UTF-8") +
					"&a-select-server=" + URLEncoder.encode(finalReqAselectServer, "UTF-8") +
					"&request=" + URLEncoder.encode(finalReqrequest, "UTF-8") +
					"&aselect_credentials=" + extracted_credentials +
//								"&check-signature=" + URLEncoder.encode(ridCheckSignature, "UTF-8") +
					"&rid=" + extractedRid;
		}
		catch (UnsupportedEncodingException e3) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not URLEncode to UTF-8, this should not happen!");
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e3);
		}
		String finalResult = "";

		//Send data
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving attributes through: " + finalRequestURL);

		BufferedReader in = null;
		try { 
			URL url = new URL(finalRequestURL); 
			
			in = new BufferedReader(
					new InputStreamReader(
							url.openStream()));

			String inputLine = null;
			while ((inputLine = in.readLine()) != null) {
				finalResult += inputLine;
			}
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Retrieved attributes in: " + finalResult);

		} catch (Exception e) { 	
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not retrieve attributes from aselectserver: " + finalReqAselectServer);
			throw new ASelectCommunicationException(Errors.ERROR_ASELECT_IO, e);
		} finally {
			if (in != null)
				try {
					in.close();
				}
				catch (IOException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not close stream to aselectserver : " + finalReqAselectServer);
				}
		}
		return finalResult;
	}


	public void destroy()
	{
	}


}
