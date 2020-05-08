package org.aselect.server.attributes.requestors.api;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import org.apache.commons.beanutils.DynaBean;
import org.apache.commons.beanutils.DynaClass;
import org.apache.commons.beanutils.DynaProperty;
import org.aselect.server.utils.AttributeSetter;
import org.aselect.system.communication.client.json.JSONCommunicator;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectSAMException;
import org.aselect.system.utils.crypto.Auxiliary;

public class RESTAPIAttributeRequestor extends APIAttributeRequestor {

	/** The module name. */
	private final String MODULE = "RESTAPIAttributeRequestor";

	
	public void init(Object oConfig)
	throws ASelectException
	{
		String sMethod = "init";
		super.init(oConfig);
		
		try {
			// Get main configuration
			Object oMainConfiguration = null;
			try {
				oMainConfiguration = _configManager.getSection(oConfig, "main");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve 'main' configuration section",
						eAC);
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR, eAC);
			}

			// Get communicator
			String sProtocol = null;
			String method = null;	// RH, 20190614, n
			try {
				sProtocol = _configManager.getParam(oMainConfiguration, "transferprotocol");
				method = _configManager.getSimpleParam(oMainConfiguration, "method", false);	// RH, 20190614, n
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not find config item 'transferprotocol', using Raw communication", eAC);
				sProtocol = "raw";
			}
			if (sProtocol == null)
				sProtocol = "";

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator="+sProtocol);
			if (sProtocol.equalsIgnoreCase("json")) {
//				retrieveSOAPMethodFromConfig(oMainConfiguration);	// Maybe provide for POST here
				// RH, 20190614, so
//				_communicator = new JSONCommunicator(_systemLogger);
				// RH, 20190614, eo
				// RH, 20190614, sn
				if (method != null) {
					_communicator = new JSONCommunicator(_systemLogger, method);
				} else {
					_communicator = new JSONCommunicator(_systemLogger);
				}
				// RH, 20190614, en
				// RH, 20200326, sn
				if (get_sslSocketFactory() != null) {
					_communicator.set_sslSocketFactory(get_sslSocketFactory());
				}
				// RH, 20200326, en
				
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "communicator= 'json' loaded");

			} else {
				// raw communication is specified or something unreadable
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "only 'json' supported");
				throw new ASelectAttributesException(Errors.ERROR_ASELECT_INIT_ERROR);
			}


		}
		catch (ASelectException eAS) {
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error initializing due to internal error", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
	
	
	/**
	 * Retrieve all, or the specified attributes. <br>
	 * <br>
	 * 
	 * @param htTGTContext
	 *            the ht tgt context
	 * @param vAttributes
	 *            the v attributes
	 * @return the attributes
	 * @throws ASelectAttributesException
	 *             the a select attributes exception
	 * @see org.aselect.server.attributes.requestors.IAttributeRequestor#getAttributes(HashMap, Vector)
	 */
	public HashMap getAttributes(HashMap htTGTContext, Vector vAttributes, HashMap hmAttributes)
	throws ASelectAttributesException
	{
		final String sMethod = "getAttributes";
		String sURL = null;

		String requestURL = null ;
		
		HashMap htAttributes = new HashMap();
		try {
			if (!vAttributes.isEmpty()) {  // Attributes should be gathered.
				// get connection
				try {
					sURL = getConnection();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved url from resources:" + sURL);
					requestURL = sURL + _sAttributesName;
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "request url before parsing:" + requestURL);
				}
				catch (ASelectSAMException eSAM) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not retrieve connection from sam", eSAM);
					throw new ASelectAttributesException(eSAM.getMessage());
				}
				// create request/response
				HashMap htRequest = new HashMap();
				//////////////////////////////
				htRequest.putAll(_htConfigParameters);	// RH, 20190614, n
				////////////////////////////////
//				HashMap htRequestpairs = new HashMap();
				HashMap htResponse = new HashMap();
				// set TGT parameters
				Enumeration e = _vTGTParameters.elements();
				while (e.hasMoreElements()) {
					String sName = (String) e.nextElement();
					String sValue = (String) htTGTContext.get(sName);
					if (sValue == null) {
						StringBuffer sbError = new StringBuffer("Error retrieving '");
						sbError.append(sName);
						sbError.append("' parameter from session context.");
						_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
						throw new ASelectAttributesException(Errors.ERROR_ASELECT_CONFIG_ERROR);
					}
					requestURL = requestURL.replaceAll("\\{" + sName + "\\}", sValue);
					// RH, 20190717, sn
					if (vAttributes.contains(sName)) {
						htRequest.put(sName, sValue);	// Selected as (json) request parameter
					}
					// RH, 20190717, en
				}
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "request url after parsing:" + Auxiliary.obfuscate(requestURL));

				
				// do Authentication if needed
				_communicator.setUser(getUser());
				_communicator.setPw(getPw());
				
				// RH, 20170731, sn
				if (_htRequestHeaders != null && !_htRequestHeaders.isEmpty()) {
					_communicator.setCommunicatorRequestProperties(_htRequestHeaders);
				}
				// RH, 20170731, sn
				
				if (get_bearerToken_attribute() != null) {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Looking for  bearer_token in TGT attribute: " + get_bearerToken_attribute());
					String bearer_token =  (String)htTGTContext.get(get_bearerToken_attribute());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Located  bearer_token in TGT: " + bearer_token);
					if (bearer_token != null) {
						_communicator.setBearerToken(bearer_token);
						// RH, 20170731, sn
						Map<String, String> reqProps = _communicator.getCommunicatorRequestProperties();
						if (reqProps == null) {
							reqProps = new HashMap<String, String>();
							_communicator.setCommunicatorRequestProperties(reqProps);
						}
						reqProps.put("Accept", "application/json");
						// RH, 20170731, en
					}
				}
				
				// send message
				htResponse = _communicator.sendMessage(htRequest, requestURL);
				HashMap newAttr = new HashMap();

				if (attributeSetters != null && !attributeSetters.isEmpty()) {
				Set<String> keys = htResponse.keySet();
				for (String key : keys) {
//				Object oNested = htResponse.get("value");
//					_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved claim key= " + key );
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved claim value= " + htResponse.get(key) );
//				if (oNested instanceof net.sf.ezmorph.bean.MorphDynaBean[]) {
					if ( htResponse.get(key) != null) {
//						Object[] oNested = (Object[]) htResponse.get("value");
					if ( htResponse.get(key)  instanceof ArrayList) {
						
						
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found nested attributes");
					ArrayList val = (ArrayList)htResponse.get(key);
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found ArrayList: " +val );
					Iterator iter = val.iterator();
					while ( iter.hasNext()) {
						DynaBean bean = (DynaBean) iter.next();
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found next bean: " +bean );
						DynaClass properties = bean.getDynaClass();
						DynaProperty[] pdprops = properties.getDynaProperties();
						if (pdprops != null) {
							HashMap retrievedClaims = new HashMap();
							for (int i= 0 ; i <pdprops.length ; i++ ){
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found DynaProperty for  Name: " +pdprops[i].getName() );
//						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found next value: " +bean.get(pdprops[i].getName()) );
						// pdprops[i].getName() should not be null, value might just be
						if (pdprops[i].getName() != null && bean.get(pdprops[i].getName()) != null) {	// beware of null pointer
							String membervalue = (bean.get(pdprops[i].getName())).toString();	// see it as a String, 
							retrievedClaims.put(pdprops[i].getName(), membervalue);
							}
						
							}
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Start processing claims: " +retrievedClaims );
							HashMap processedClaims = AttributeSetter.attributeProcessing(new HashMap(), retrievedClaims, attributeSetters, _systemLogger);
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "Processed claims: " +processedClaims );
							if (processedClaims != null && !processedClaims.isEmpty()) {
								// add processed claims to htAttributes
								Set<String> claimsKeys = processedClaims.keySet();
								for (String claimsKey : claimsKeys) {
									String oldValue = (String)newAttr.get(claimsKey);
									newAttr.put(claimsKey, oldValue == null ? ("" + processedClaims.get(claimsKey)) : oldValue + processedClaims.get(claimsKey)  );
									_systemLogger.log(Level.FINEST, MODULE, sMethod, "htAttributes so far: " +newAttr );
								}
							}
						} else {
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "no DynaProperty[] "  );
						}
					}
					} else {	// single claim
//						htAttributes = htResponse; // like we used to
						// RH, 20170411, sn
						HashMap retrievedClaims = new HashMap();
						retrievedClaims.put(key, htResponse.get(key));
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Start processing claims: " +retrievedClaims );
						HashMap processedClaims = AttributeSetter.attributeProcessing(new HashMap(), retrievedClaims, attributeSetters, _systemLogger);
						_systemLogger.log(Level.FINEST, MODULE, sMethod, "Processed claims: " +processedClaims );
						if (processedClaims != null && !processedClaims.isEmpty()) {
							// add processed claims to htAttributes
							Set<String> claimsKeys = processedClaims.keySet();
							for (String claimsKey : claimsKeys) {
								String oldValue = (String)newAttr.get(claimsKey);
								newAttr.put(claimsKey, oldValue == null ? ("" + processedClaims.get(claimsKey)) : oldValue + processedClaims.get(claimsKey)  );
								_systemLogger.log(Level.FINEST, MODULE, sMethod, "htAttributes so far: " +newAttr );
							}
						}
						// RH, 20170411, en

					}
				} else { // skip
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Null attribute found");
				}
				} // end for
					htAttributes = newAttr;
				} else {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "No attributes found to be processed, continuing");
					// Do not change anything
					htAttributes = htResponse;
				}
				// retrieve response and forward 1-on-1
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved attributes:" + htAttributes);
			}
		}
		catch (ASelectCommunicationException eAC) {
			StringBuffer sbError = new StringBuffer("Error communicating with host: ");
			sbError.append(sURL);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, sbError.toString(), eAC);
			throw new ASelectAttributesException(eAC.getMessage());
		}
		catch (ASelectAttributesException eAA) {
			// allready logged
			throw eAA;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Error retrieving attributes due to internal error", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htAttributes;
	}
	
}
