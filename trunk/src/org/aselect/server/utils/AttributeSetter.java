package org.aselect.server.utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectAttributesException;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/*
 * @author Bauke Hiemstra
 * 
 * Save Attribute setter data from configuration files
 */
public class AttributeSetter
{
	private static final String MODULE = "AttributeSetter";

	String sDest = null;
	String sSrc = null;
	String sSep = null;
	String sName = null;
	int iIndex = -1;
	boolean bDestTgt = false;
	boolean bSrcTgt = false;

	Pattern pMatchingPattern = null;
	String sReplacementString = null;
	String sOperator = null;

	public String getDest() { return sDest; }
	public String getSrc() { return sSrc; }
	public String getSep() { return sSep; }
	public String getName() { return sName; }
	public int getIndex() { return iIndex; }
	public boolean isDestTgt() { return bDestTgt; }
	public boolean isSrcTgt() { return bSrcTgt; }

	public Pattern getMatchingPattern() { return pMatchingPattern; }
	public String getReplacementString() { return sReplacementString; }
	public String getOperator() { return sOperator; }


	// Creator
	public AttributeSetter(String sDest, String sSrc, String sSep, String sName, int iIndex, boolean bDestTgt, boolean bSrcTgt)
	{
//		this(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt, null, null);
		this(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt, null, null, null);
	}
	// Creator
//	public AttributeSetter(String sDest, String sSrc, String sSep, String sName, int iIndex, boolean bDestTgt, boolean bSrcTgt, Pattern pMatchingPattern, String sReplacementString )
	public AttributeSetter(String sDest, String sSrc, String sSep, String sName, int iIndex, boolean bDestTgt, boolean bSrcTgt, 
			Pattern pMatchingPattern, String sReplacementString, String sOperator )
	{
		this.sDest = sDest;
		this.sSrc = sSrc;
		this.sSep = sSep;
		this.sName = sName;
		this.iIndex = iIndex;
		this.bDestTgt = bDestTgt;
		this.bSrcTgt = bSrcTgt;

		this.pMatchingPattern = pMatchingPattern;
		this.sReplacementString = sReplacementString;
		this.sOperator = sOperator;
	}

	/**
	 * Read attributes config.
	 * 
	 * @param oConfigManager
	 *            the config manager
	 * @param oConfig
	 *            the config
	 * @param attributeSetters
	 *            the attribute setter rules
	 * @param sysLogger
	 *            the system logger
	 * @throws ASelectException
	 */
	public static void initAttributesConfig(ASelectConfigManager oConfigManager, Object oConfig,
					LinkedList<AttributeSetter> attributeSetters, ASelectSystemLogger sysLogger)
	throws ASelectException
	{
		String sMethod = "initAttributesConfig";
		
		Object oAttributes = ASelectConfigManager.getSimpleSection(oConfig, "attributes", false);
		sysLogger.log(Level.FINEST, MODULE, sMethod, "oAttributes="+oAttributes);
		if (oAttributes == null)
			return;
		Object oSetAttr = ASelectConfigManager.getSimpleSection(oAttributes, "set_attr", false);
		if (oSetAttr == null)
			return;

		while (oSetAttr != null) {
			boolean bDestTgt = false, bSrcTgt = false;
			String sDest = ASelectConfigManager.getSimpleParam(oSetAttr, "dest", false);
			sysLogger.log(Level.FINEST, MODULE, sMethod, "dest="+sDest);
			if (!Utils.hasValue(sDest)) {
				sDest = ASelectConfigManager.getSimpleParam(oSetAttr, "tgt_dest", true);
				bDestTgt = true;
			}
			String sSrc = ASelectConfigManager.getSimpleParam(oSetAttr, "src", false);
			if (!Utils.hasValue(sSrc)) {
				sSrc = ASelectConfigManager.getSimpleParam(oSetAttr, "tgt_src", true);
				bSrcTgt = true;
			}
			String sSep = ASelectConfigManager.getSimpleParam(oSetAttr, "sep", false);
			String sName = ASelectConfigManager.getSimpleParam(oSetAttr, "name", false);
			String sIndex = ASelectConfigManager.getSimpleParam(oSetAttr, "index", false);
			
			// RH, 20160229, sn
			Pattern pMatchingPattern = null;
			String sReplacementString = null;
			String  sMatchingPattern = ASelectConfigManager.getSimpleParam(oSetAttr, "matchingpattern", false);
			if ( sMatchingPattern != null ) {
				try {
					pMatchingPattern = Pattern.compile(sMatchingPattern);
					sReplacementString = ASelectConfigManager.getSimpleParam(oSetAttr, "replacementstring", false);
					sysLogger.log(Level.FINEST, MODULE, sMethod, "Compiled matchingpattern: " + pMatchingPattern.pattern());
					sysLogger.log(Level.FINEST, MODULE, sMethod, "Found replacementstring: " + sReplacementString);
				} catch ( PatternSyntaxException pex) {
					sysLogger.log(Level.SEVERE, MODULE, sMethod, "Error in pattern: " + sMatchingPattern);
					throw new ASelectConfigException(pex.getMessage(), pex);
				}
			} else {
				sysLogger.log(Level.FINEST, MODULE, sMethod, "No matchingpattern found, skipping replacementstring");
			}
			// RH, 20160229, en

			// RH, 20190208, sn
			String sOperator = ASelectConfigManager.getSimpleParam(oSetAttr, "operator", false);
			// RH, 20190208, en

			int iIndex = -1;
			try {
				iIndex = Integer.valueOf(sIndex);
			} catch (Exception e) { }
			sysLogger.log(Level.INFO, MODULE, sMethod, (bDestTgt?"tgt_":"")+"dest="+sDest+" "+(bSrcTgt?"tgt_":"")+"src="+sSrc+" name="+sName+" sep="+sSep+" index="+sIndex);
//			attributeSetters.add(new AttributeSetter(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt));
//			attributeSetters.add(new AttributeSetter(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt, pMatchingPattern, sReplacementString));
			attributeSetters.add(new AttributeSetter(sDest, sSrc, sSep, sName, iIndex, bDestTgt, bSrcTgt, pMatchingPattern, sReplacementString, sOperator));
			
			// Obtain handle to the next requestor
			try {
				oSetAttr = oConfigManager.getNextSection(oSetAttr);
			}
			catch (ASelectConfigException e) {
				oSetAttr = null;
			}
		}
	}

	/**
	 * Attribute processing.
	 * 
	 * @param htTGTContext
	 *            the tgt context
	 * @param hmAttributes
	 *            the collected attributes so far
	 * @param attributeSetters
	 *            the attribute setter specifications
	 * @return the resulting hash map
	 * @throws ASelectAttributesException
	 */
	public static HashMap attributeProcessing(HashMap htTGTContext, HashMap hmAttributes,
			LinkedList<AttributeSetter> attributeSetters, ASelectSystemLogger sysLog)
	throws ASelectAttributesException
	{
		final String sMethod = "attributeProcessing";
		HashMap htNewAttrs = new HashMap();

		try {
			String sValue = null;
			
			for (int idx = 0; idx < attributeSetters.size(); idx++) {
				AttributeSetter setter = attributeSetters.get(idx);
				String sDest = setter.getDest();
				if (!Utils.hasValue(sDest))
					continue;
				
				String sSrc = setter.getSrc();
				if (!Utils.hasValue(sSrc))
					continue;
				sysLog.log(Level.FINER, MODULE, sMethod, (setter.isSrcTgt()?"tgt_":"")+"src="+sSrc+(setter.isDestTgt()?" tgt_":" ")+"dest="+sDest+
						" sep="+setter.getSep()+" index="+setter.getIndex()+" name="+setter.getName());
				
				// Take from source, multi valued (Vector) attributes will be converted to a string
				Object oValue = (setter.isSrcTgt())? htTGTContext.get(sSrc): hmAttributes.get(sSrc);
				//sysLog.log(Level.FINEST, MODULE, sMethod, "oValue="+oValue);
				if (oValue == null)
					continue;
				sValue = oValue.toString();
				// Some day we'll want to allow empty strings
				if (!Utils.hasValue(sValue))
					continue;
				
				// Split the value using sSep
				String sSep = setter.getSep();
				if (Utils.hasValue(sSep)) {
					String sNewValue = null;
					String[] fields = sValue.split(sSep+" *");  // eat white space too
					
					// Get field i or get a named field
					int iIndex = setter.getIndex();
					String sName = setter.getName();
					if (iIndex != -1) {
						if (iIndex >= 1 && iIndex <= fields.length)
							sNewValue = fields[iIndex-1];
						// index and name combined?
						if (Utils.hasValue(sName) && Utils.hasValue(sNewValue)) {
							if (sNewValue.startsWith(sName+"="))
								sNewValue = sNewValue.substring(sName.length()+1);
						}
					}
					else {
						if (Utils.hasValue(sName)) {
							for (int i=0; i<fields.length; i++) {
								if (fields[i].startsWith(sName+"="))
									sNewValue = fields[i].substring(sName.length()+1);
							}
							// Last value found wins!
						}
					}
					if (Utils.hasValue(sNewValue))
						sValue = sNewValue;
				}
				sysLog.log(Level.FINEST, MODULE, sMethod, "Before matching and operation, value="+Auxiliary.obfuscate(sValue));
				
				// RH, 20160229, sn
				if (setter.getMatchingPattern() != null) {
					sysLog.log(Level.FINEST, MODULE, sMethod, "Using Pattern="+setter.getMatchingPattern() +" with Replacement="+setter.getReplacementString());
//					sValue = setter.getMatchinePattern().matcher(sValue).replaceAll(setter.getReplacementString());	// RH, 20170331, o
					// RH, 20170331, sn
					Matcher m = setter.getMatchingPattern().matcher(sValue);
					if (m.matches()) {
						sValue = m.replaceAll(setter.getReplacementString());
					} else {
						sysLog.log(Level.FINEST, MODULE, sMethod, "No match found, skipping");
						continue;
					}
					// RH, 20170331, en
					sysLog.log(Level.FINEST, MODULE, sMethod, "New value="+Auxiliary.obfuscate(sValue));
				}
				// RH, 20160229, en
				
				// RH, 20190208, sn
				if (setter.getOperator() != null) {
					String slValue = sValue;
					sysLog.log(Level.FINEST, MODULE, sMethod, "Using Operator="+setter.getOperator());
//					Object orValue = (setter.isDestTgt())? htTGTContext.get(sDest): hmAttributes.get(sDest);
//					if (orValue == null)
//						continue;
//					String srValue = orValue.toString();
//					if (!Utils.hasValue(srValue))
//						continue;
					if ("==".equals(setter.getOperator())) {
						Object orValue = (setter.isDestTgt())? htTGTContext.get(sDest): hmAttributes.get(sDest);
						if (orValue == null)
							continue;
						String srValue = orValue.toString();
						// Some day we'll want to allow empty strings
						if (!Utils.hasValue(srValue))
							continue;
						sValue = Boolean.toString(slValue.equals(srValue));
						sysLog.log(Level.FINEST, MODULE, sMethod, "Comparing:" + sSrc + " with:" + sDest + " results:" + Auxiliary.obfuscate(sValue));
					} 
					// RH, 20190927, sn
					else if ("DECRYPT".equalsIgnoreCase(setter.getOperator())) {
						ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
						PrivateKey secretKey = _configManager.getDefaultPrivateKey();
						sValue = Auxiliary.decryptRSAString(slValue, secretKey, sysLog);
					} else if ("ENCRYPT".equalsIgnoreCase(setter.getOperator())) {
						ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
						PublicKey pubKey = _configManager.getDefaultCertificate().getPublicKey();
						sValue = Auxiliary.encryptRSAString(slValue, pubKey, sysLog);
					}
					// RH, 20190927, en
					// RH, 20200713, sn
					else if ("+=".equalsIgnoreCase(setter.getOperator())) {
						Object orValue = (setter.isDestTgt())? htTGTContext.get(sDest): hmAttributes.get(sDest);
						String srValue = null;
						if (orValue == null) {
							srValue = "";
						} else {
							srValue = orValue.toString();
						}
						sValue = slValue + srValue;
						sysLog.log(Level.FINEST, MODULE, sMethod, "Concating:" + sSrc + " with:" + sDest + " results:" + Auxiliary.obfuscate(sValue));
					}
					else if ("++".equalsIgnoreCase(setter.getOperator())) {
						sValue = slValue.toUpperCase();
						sysLog.log(Level.FINEST, MODULE, sMethod, "toUpperCase:" + sSrc + " results:" + Auxiliary.obfuscate(sValue));
					}
					else if ("--".equalsIgnoreCase(setter.getOperator())) {
						sValue = slValue.toLowerCase();
						sysLog.log(Level.FINEST, MODULE, sMethod, "toLowerCase:" + sSrc + " results:" + Auxiliary.obfuscate(sValue));
					}
					// RH, 20200713, en
				}
				// RH, 20190208, en
				
				sysLog.log(Level.FINEST, MODULE, sMethod, "After matching and operation, value="+Auxiliary.obfuscate(sValue));
				
				if (setter.isDestTgt()) {
					sysLog.log(Level.FINEST, MODULE, sMethod, "Tgt: "+sDest+"="+Auxiliary.obfuscate(sValue));
					htTGTContext.put(sDest, sValue);
				}
				else {
					sysLog.log(Level.FINEST, MODULE, sMethod, "New: "+sDest+"="+Auxiliary.obfuscate(sValue));
					htNewAttrs.put(sDest, sValue);
				}
			}
		}
		catch (Exception e) {
			sysLog.log(Level.WARNING, MODULE, sMethod, "Attribute collection failed", e);
			throw new ASelectAttributesException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
		return htNewAttrs;
	}
}
