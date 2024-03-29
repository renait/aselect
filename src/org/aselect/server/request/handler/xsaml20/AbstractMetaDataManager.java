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
package org.aselect.server.request.handler.xsaml20;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.apache.commons.httpclient.HttpClient;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Utils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author bauke
 *
 */
public abstract class AbstractMetaDataManager
{
	// RH, 20090616
	// Forward proxy can now be enabled by setting java system properties "http.proxyPort" en "http.proxyPort"
	private static final String HTTP_PROXY_PORT = "http.proxyPort";
	private static final String HTTP_PROXY_HOST = "http.proxyHost";
	private static final String DEFAULT_PROXY_PORT = "8080"; // RH, 20090615, n
	protected final String MODULE = "AbstractMetaDataManager";
	protected String protocolSupportEnumeration = SAMLConstants.SAML20P_NS; // "urn:oasis:names:tc:SAML:2.0:protocol"
	protected ASelectConfigManager _configManager;
	protected SystemLogger _systemLogger;

	// All descriptors
//	protected ConcurrentHashMap<String, SSODescriptor> SSODescriptors = new ConcurrentHashMap<String, SSODescriptor>();	// RH, 20190322, o
	protected ConcurrentHashMap<Map.Entry<String, String>, SSODescriptor> SSODescriptors = new ConcurrentHashMap<Map.Entry<String, String>, SSODescriptor>();	// RH, 20190322, n
//	protected ConcurrentHashMap<String, String> metadataSPs = new ConcurrentHashMap<String, String>();
//	protected ConcurrentHashMap<String, String> sessionSyncSPs = new ConcurrentHashMap<String, String>();
	protected ConcurrentHashMap<String, java.security.cert.X509Certificate> trustedIssuers = new ConcurrentHashMap<String, java.security.cert.X509Certificate>();

//	public ConcurrentHashMap<String, PartnerData> storeAllIdPData = new ConcurrentHashMap<String, PartnerData>();	// RH, 20190321, o
	public ConcurrentHashMap<Map.Entry<String, String>, PartnerData> storeAllIdPData = new ConcurrentHashMap<Map.Entry<String, String>, PartnerData>();	// RH, 20190321, n

	private static String _sCheckCertificates = null;
	
	/**
	 * Override to specify the classes role
	 * 
	 * @return - the role, either "SP" or "IDP"
	 */
	protected abstract String getMyRole();
	
	/**
	 * Initialization method
	 * 
	 * @throws ASelectException
	 */
	protected void init()
	throws ASelectException
	{
		_configManager = ASelectConfigManager.getHandle();
		_systemLogger = ASelectSystemLogger.getHandle();
	}

	/**
	 * Initialize meta data handling.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void initializeMetaDataHandling()
	throws ASelectException
	{
		String sMethod = "initializeMetaData";

		// Initialize the opensaml library
		try {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Saml Bootstrap");
			DefaultBootstrap.bootstrap();
		}
		catch (ConfigurationException cfge) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not initialize bootstrap", cfge);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, cfge);
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "storeAllIdPData=" + storeAllIdPData);
	}

	/**
	 * File system provider.
	 * 
	 * @param myMetadataProvider
	 *            the my metadata provider
	 * @param sMethod
	 *            the s method
	 * @param ppMgr
	 *            the pp mgr
	 * @param metadataURL
	 *            the metadata url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void fileSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod,
			BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, MODULE, sMethod, "fileSystemProvider url="+metadataURL);
		File mdFile = new File(metadataURL);
		mdFile.toURI();
		FilesystemMetadataProvider fileProvider;
		try {
			fileProvider = new FilesystemMetadataProvider(mdFile);
			fileProvider.setParserPool(ppMgr);
			fileProvider.initialize();
			myMetadataProvider.addMetadataProvider(fileProvider);
		}
		catch (MetadataProviderException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"Could not read metadata xml file, check the pathname within aselect xml file: " + metadataURL, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * Url system provider.
	 * 
	 * @param myMetadataProvider
	 *            the my metadata provider
	 * @param sMethod
	 *            the s method
	 * @param ppMgr
	 *            the pp mgr
	 * @param metadataURL
	 *            the metadata url
	 * @throws ASelectException
	 *             the a select exception
	 */
	protected void urlSystemProvider(ChainingMetadataProvider myMetadataProvider, String sMethod,
			BasicParserPool ppMgr, String metadataURL)
	throws ASelectException
	{
		_systemLogger.log(Level.INFO, MODULE, sMethod, "urlSystemProvider url="+metadataURL);
		HTTPMetadataProvider urlProvider;
		try {
			// RH, 20090615, sn
			// opensaml2 does not (yet) support usage of proxy
			// use the wrapper class ProxyHTTPMetadataProvider if the SYstemproperty is set
			String proxyHost = System.getProperty(HTTP_PROXY_HOST);
			if (proxyHost != null) {
				String sPort = System.getProperty(HTTP_PROXY_PORT);
				if (sPort == null) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "No proxyPort defined, using default port");
					sPort = DEFAULT_PROXY_PORT;
				}
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Using proxy: " + proxyHost + " on port: " + sPort);
				int proxyPort = Integer.parseInt(sPort);
				urlProvider = new ProxyHTTPMetadataProvider(metadataURL, 1000 * 5, proxyHost, proxyPort);
			}
			else { // RH, 20090615, en
//				urlProvider = new HTTPMetadataProvider(metadataURL, 1000 * 5);
				urlProvider = new HTTPMetadataProvider(new Timer(), new HttpClient(), metadataURL);
				
			} // RH, 20090615, n

			urlProvider.setParserPool(ppMgr);
			urlProvider.initialize();
			myMetadataProvider.addMetadataProvider(urlProvider);
		}
		catch (MetadataProviderException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not read metadata, check your aselect.xml file: "
					+ metadataURL, e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
	}

	/**
	 * If a new partner (SP or IDP is making contact, we must be able to read it's metadata.
	 * Can be called any time, not necessarily at startup.
	 * Must be called before using SSODescriptors.
	 * 
	 * @param entityId
	 *            the entity id
	 * @throws ASelectException
	 *             the a select exception
	 */
//	protected void ensureMetadataPresence(String entityId)	// RH, 20190322, o
	protected void ensureMetadataPresence(String resourceGroup, String entityId)	// RH, 20190322, n
	throws ASelectException
	{
		String sMethod = "ensureMetadataPresence";
		String metadataURL = null;
		ChainingMetadataProvider myMetadataProvider = new ChainingMetadataProvider();

//		_systemLogger.log(Level.FINE, MODULE, sMethod, "myRole="+getMyRole()+" entityId="+entityId+" SSODescriptors="+SSODescriptors);
		_systemLogger.log(Level.FINE, MODULE, sMethod, "myRole="+getMyRole()+" resourceGroup="+resourceGroup+" entityId="+entityId+" SSODescriptors="+SSODescriptors);
		if (trustedIssuers.isEmpty() && getCheckCertificates() != null) {
			// Load trusted ca's (SP) or trusted SP's (IdP) from trusted_issuers.keystore
			loadTrustedIssuers();
		}
		if (entityId == null)
			return;
//		if (SSODescriptors.containsKey(makeEntityKey(entityId, null))) {	// RH, 20190322, o
		if (SSODescriptors.containsKey(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, null)))) {	// RH, 20190322, n
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " already in cache");
			_systemLogger.log(Level.INFO, MODULE, sMethod, "resourceGroup="+resourceGroup + " entityId=" + entityId + " already in cache");
			return;
		}

		// Read the new metadata
		_systemLogger.log(Level.INFO, MODULE, sMethod, "entityId=" + entityId + " not in cache yet");
//		metadataURL = getMetadataURL(entityId);	// RH, 20190322, o
		metadataURL = getMetadataURL(resourceGroup, entityId);	// RH, 20190322, n
		if (metadataURL == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity id: " + entityId + " is not Configured");
			return;
		}

		// Get parser pool manager
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);

		_systemLogger.log(Level.INFO, MODULE, sMethod, "READ url=" + metadataURL);
		if (metadataURL.toLowerCase().startsWith("http"))
			urlSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		else
			fileSystemProvider(myMetadataProvider, sMethod, ppMgr, metadataURL);
		// Result has been stored in myMetadataProvider

		// Add to the SSODescriptor
//		addMetadata(myMetadataProvider);	// RH, 20180829, n
		addMetadata(myMetadataProvider, resourceGroup);	// RH, 20180829, o
	}

	/**
	 * Load trusted issuers.
	 * 
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void loadTrustedIssuers()
	throws ASelectException
	{
		String sMethod = "loadTrustedIssuers";

		ASelectConfigManager _oASelectConfigManager = ASelectConfigManager.getHandle();
		StringBuffer sbKeystoreLocation = new StringBuffer(_oASelectConfigManager.getWorkingdir());
		_systemLogger.log(Level.FINE, MODULE, sMethod, "WorkingDir=" + sbKeystoreLocation);
		sbKeystoreLocation.append(File.separator).append("keystores").append(File.separator).append(
				"trusted_issuers.keystore").toString();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Load TrustedIssuers " + sbKeystoreLocation + " Prefix=ca_ Check="
				+ getCheckCertificates());
		try {
			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			Enumeration<String> enumAliases = ksASelect.aliases();
			while (enumAliases.hasMoreElements()) {
				String sAlias = enumAliases.nextElement().toLowerCase();
				java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
						.getCertificate(sAlias);
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Alias=" + sAlias);
				if (checkCertificate("ca_", x509Cert))
					trustedIssuers.put(sAlias, x509Cert);
				else
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Alias=" + sAlias + " not valid!");
			}
		}
		catch (NoSuchAlgorithmException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Algorithm exception, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (CertificateException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Certificate exception, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (FileNotFoundException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be found, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (IOException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore cannot be read, " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		catch (KeyStoreException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Keystore exception: " + e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
		}
		// Make size() > 0 so this method does not get called again
		if (trustedIssuers.size() == 0)
			trustedIssuers.put("loading_has_been_done", null);
	}

	// RH, 20190322, so
//	/**
//	 * Handle metadata provider.
//	 * List all entries or Remove an entity from the metadata storage
//	 * Produces output on stdout!
//	 * Can be called from the Operating System to cleanup the cache.
//	 * 
//	 * @param out
//	 *            the out
//	 * @param entityId
//	 *            the entity id
//	 * @param sList
//	 *            the s list
//	 */
//	public void handleMetadataProvider(PrintWriter out, String entityId, boolean sList)
//	{
//		String sMethod = "handleMetadataProvider";
//
//		if (sList) {
//			Set<String> SSOkeys = SSODescriptors.keySet();
//			for (String SSOkey : SSOkeys) {
//				out.println("EntityId=" + SSOkey);
//			}
//			return;
//		}
//		// Remove entries from SSODescriptors
//		SSODescriptor descriptorSP = SSODescriptors.remove(makeEntityKey(entityId, "SP"));
//		SSODescriptor descriptorIDP = SSODescriptors.remove(makeEntityKey(entityId, "IDP"));
//		if (descriptorSP == null && descriptorIDP == null) {
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity " + entityId + " not found");
//			out.println("Entity " + entityId + " not found");
//		}
//	}
	// RH, 20190322, eo

	// RH, 20190322, sn
	/**
	 * Handle metadata provider.
	 * List all entries or Remove an entity from the metadata storage
	 * Produces output on stdout!
	 * Can be called from the Operating System to cleanup the cache.
	 * 
	 * @param out
	 *            the out
	 * @param entityId
	 *            the entity id not null
	 * @param sList
	 *            the s list
	 */
	public void handleMetadataProvider(PrintWriter out, String resourceGroup, String entityId, boolean sList)
	{
		String sMethod = "handleMetadataProvider";

		if (sList) {
			Set<Map.Entry<String,String>> SSOkeys = SSODescriptors.keySet();
			for (Map.Entry<String,String> SSOkey : SSOkeys) {
				// This output is unfortunately not backward compatible, maybe handle this differently
				out.println("EntityId=" + SSOkey);
			}
			return;
		}
		// Remove entries from SSODescriptors
		if (resourceGroup == null) {	// remove enitityID form all groups
			Set<Map.Entry<String,String>> SSOkeys = SSODescriptors.keySet();
			for (Map.Entry<String,String> SSOkey : SSOkeys) {
				boolean removed = false;
				if ( SSOkey.getValue().equals(makeEntityKey(entityId, "SP")) ) {
					removed = SSOkeys.remove(SSOkey);
					// This output is unfortunately not backward compatible, maybe handle this differently
					out.println("EntityId=" + SSOkey + " removed:" + removed);
				}
				removed = false;
				if ( SSOkey.getValue().equals(makeEntityKey(entityId, "IDP")) ) {
					removed = SSOkeys.remove(SSOkey);
					// This output is unfortunately not backward compatible, maybe handle this differently
					out.println("EntityId=" + SSOkey + " removed:" + removed);
				}
			}
		} else {
			SSODescriptor descriptorSP = SSODescriptors.remove(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, "SP")));
			SSODescriptor descriptorIDP = SSODescriptors.remove(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, "IDP")));
			if (descriptorSP == null && descriptorIDP == null) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Entity " + entityId + " not found");
				out.println("Entity " + entityId + " not found");
			}
		}
	}
	// RH, 20190322, en


	// RH, 20180829, sn
//	protected void addMetadata(ChainingMetadataProvider myMetadataProvider)	// RH, 20190322, o
	protected void addMetadata(ChainingMetadataProvider myMetadataProvider, String resourceGroup)	// RH, 20190322, n
	throws ASelectException
	{
//		addMetadata(myMetadataProvider, null);	// RH, 20190322, o
		addMetadata(myMetadataProvider, resourceGroup, null);	// RH, 20190322, n
	}
	// RH, 20180829, en
	/**
	 * Get issuer(entityID) and metadata file location from application.
	 * Put these values in SSODescriptors.
	 * The key is the entityID and the value the Descriptors
	 * 
	 * @param myMetadataProvider
	 *            the Metadata provider
	 * @throws ASelectException
	 */
//	protected void addMetadata(ChainingMetadataProvider myMetadataProvider)	// RH, 20180829, o
//	protected void addMetadata(ChainingMetadataProvider myMetadataProvider, String entityId)	// RH, 20180829, n	// 20190322, o
	protected void addMetadata(ChainingMetadataProvider myMetadataProvider, String resourceGroup, String entityId)	// 20190322, n
	throws ASelectException
	{
		String sMethod = "addMetadata";

		ArrayList<MetadataProvider> metadataProviderArray = new ArrayList<MetadataProvider>();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "getProviders");
		metadataProviderArray.addAll(myMetadataProvider.getProviders());

		for (MetadataProvider metadataEntityId : metadataProviderArray) {
			try {
				
//				EntityDescriptor entityDescriptorValue = null;
//				if (entityId == null) {	// RH, 20180829, n, 	// RH, 20190809, o
				XMLObject domdoc = metadataEntityId.getMetadata();

				Element domDescriptor = marshallDescriptor(domdoc);
//				String entityId = domDescriptor.getAttribute("entityID");	// RH, 20180829, o
				if (entityId == null) {	// RH, 20190809, n
					entityId = domDescriptor.getAttribute("entityID");	// RH, 20180829, n
				}	// RH, 20180829, n
				// We will get and fill SSODescriptors
				// ((ChainingMetadataProvider)metadataEntityId).
				EntityDescriptor singleEntityDescriptorValue = metadataEntityId.getEntityDescriptor(entityId);

				// RH, 20180829, sn
				List<EntityDescriptor> entityDescriptors = new ArrayList<EntityDescriptor>();
				if (singleEntityDescriptorValue == null) {
					// if no single root EntityDescriptor, maybe embedded in EntitiesDescriptor
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "No single EntityDescriptor found, trying EntitiesDescriptor");
					_systemLogger.log(Level.FINEST, MODULE, sMethod, XMLHelper.prettyPrintXML(domdoc.getDOM()));
					
					if (!(domdoc instanceof EntitiesDescriptor)) {
					        throw new ASelectException("Unexpected body content.  Expected a SAML EntitiesDescriptor but recieved "
					                + domdoc.getElementQName());
				    }
					EntitiesDescriptor rootDescriptor = (EntitiesDescriptor)domdoc ;
					entityDescriptors = getEntityDescriptors(rootDescriptor, entityDescriptors);
				} else {
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Found single EntityDescriptor");
					entityDescriptors.add(singleEntityDescriptorValue);
				}
				// RH, 20180829, en
				for (EntityDescriptor entityDescriptorValue : entityDescriptors) {	// RH, 20190809, n
//				if (entityDescriptorValue != null) {	// RH, 20190809, o
					entityId = entityDescriptorValue.getEntityID();	// RH, 20190809, n
					_systemLogger.log(Level.INFO, MODULE, sMethod, "New Entity Descriptor: " + entityDescriptorValue
							+ " for " + entityId);
					// 20100501, Bauke: metadata can contain both Descriptor types, so check both of them!
					SSODescriptor descriptorValueIDP = entityDescriptorValue.getIDPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueIDP != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "IDP SSODescriptor found");
						if (!checkKeyDescriptorCertificate(descriptorValueIDP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
//						SSODescriptors.put(makeEntityKey(entityId, "IDP"), descriptorValueIDP);	// RH, 20190322, o
						SSODescriptors.put(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, "IDP")), descriptorValueIDP);	// RH, 20190322, n
					}
					SSODescriptor descriptorValueSP = entityDescriptorValue.getSPSSODescriptor(protocolSupportEnumeration);
					if (descriptorValueSP != null) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "SP SSODescriptor found");
						if (!checkKeyDescriptorCertificate(descriptorValueSP))
							throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
//						SSODescriptors.put(makeEntityKey(entityId, "SP"), descriptorValueSP);	// RH, 20190322, o
						SSODescriptors.put(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, "SP")), descriptorValueSP);	// RH, 20190322, n
					}
				}
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Marshalling failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Parser failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
			catch (MetadataProviderException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not read metadata xml file ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
	}

	// RH, 20190809, sn
	/**
	 * Recurse into EntitiesDescriptor and
	 * return flat list of EntityDescriptor
	 * @param rootDescriptor
	 *            the top level EntitiesDescriptor
	 * @param entityDescriptors
	 *            the (possibly empty or null) flat list of EntityDescriptor
	 */
	private List<EntityDescriptor> getEntityDescriptors(EntitiesDescriptor rootDescriptor, List<EntityDescriptor> entityDescriptors) {
		String sMethod = "getEntityDescriptors";

		if (entityDescriptors == null) { 
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Creating empty list entityDescriptors");
			entityDescriptors =  new ArrayList<EntityDescriptor>();
		}
		entityDescriptors.addAll(rootDescriptor.getEntityDescriptors());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "list of entityDescriptors so far:" + entityDescriptors);
		List<EntitiesDescriptor> entitiesDescriptors = rootDescriptor.getEntitiesDescriptors();
		if (entitiesDescriptors != null) {
			Iterator<EntitiesDescriptor> iter = entitiesDescriptors.iterator();
			while (iter.hasNext()) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Recursing into entitiesDescriptors");
				entityDescriptors = getEntityDescriptors(iter.next(), entityDescriptors);
			}
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "finally returning list entityDescriptors:" + entityDescriptors);
		return entityDescriptors;
	}
	// RH, 20190809, en
	
	
	/**
	 * Check validity of a metadata certificate. Called when the metadata is read in. Dates must be valid, and the
	 * certificate must be trusted by a ca stored in the trusted_issuers keystore.
	 * 
	 * @param descriptor
	 *            the descriptor
	 * @return true, if check key descriptor
	 */
	private boolean checkKeyDescriptorCertificate(SSODescriptor descriptor)
	{
		String sMethod = "checkKeyDescriptorCertificate";
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		int validCertsFound = 0;
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "CheckCerts=" + getCheckCertificates());
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
//			if (!useType.name().equalsIgnoreCase("SIGNING")) {
//			if (useType != UsageType.SIGNING) {
			if (useType != UsageType.SIGNING && useType != UsageType.UNSPECIFIED) {	// we'll allow UNSPECIFIED as SIGNING
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Invalid UsageType: " + useType + " , ignored");
				continue; // skip
			}

			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
//			X509Data x509Data = keyinfo.getX509Datas().get(0);
			List<X509Data> x509Datas = keyinfo.getX509Datas();
			if (x509Datas != null && !x509Datas.isEmpty()) {
				for (X509Data x509Data : x509Datas) {
					List<X509Certificate> certs = x509Data.getX509Certificates();
					if (certs != null && !certs.isEmpty()) {
						for (X509Certificate cert : certs) {
		//				X509Certificate cert = certs.get(0);
							try {
								java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert);
								if (javaCert != null) {
									if (checkCertificate("", javaCert)) {
										_systemLogger.log(Level.FINER, MODULE, sMethod, "OK "
												+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
												+ javaCert.getIssuerX500Principal().getName());
//										return true;
										validCertsFound++;
									} else {
										_systemLogger.log(Level.INFO, MODULE, sMethod, "NOT OK "
											+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
											+ javaCert.getIssuerX500Principal().getName());
									}
								}
							}
							catch (CertificateException e) {
//								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ",e);
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: " +
										e.getMessage() + ", continuing");
	//							return false;
								continue;
							}
						}
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Cannot retrieve X509Certificate from metadata, continuing next X509Data");
					}
				}
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Cannot retrieve X509Data from metadata, continuing next KeyDescriptor");
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Number of valid certs found: " + validCertsFound);
//		return false;
		return (validCertsFound > 0);
	}

	/**
	 * Check dates and/or issuer of the given certificate.
	 * 
	 * @param prefix
	 *            - can be "" or "ca_", the second version checks the ca-certificate as well
	 * @param javaCert
	 *            - the certificate to be checked
	 * @return - is certificate ok?
	 */
	private boolean checkCertificate(String prefix, java.security.cert.X509Certificate javaCert)
	{
		String sMethod = "checkCertificate";
		String sCheckCerts = getCheckCertificates();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Prefix="+prefix+" CheckCerts="+sCheckCerts);
		try {
			if (sCheckCerts != null && sCheckCerts.contains(prefix + "dates")) {
				javaCert.checkValidity();
				// _systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate dates are valid");
			}
			if (sCheckCerts != null && sCheckCerts.contains(prefix + "issuer")) {
				boolean isTrusted = isCertificateTrusted(javaCert);
				if (!isTrusted)
					_systemLogger.log(Level.INFO, MODULE, sMethod, "The certificate issuer is not valid");
				return isTrusted;
			}
			// RM_43_01
			return true;
		}
		catch (CertificateExpiredException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The certificate has expired");
			return false;
		}
		catch (CertificateNotYetValidException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "The certificate is not yet valid");
			return false;
		}
	}

	/**
	 * Checks if is certificate trusted.
	 * 
	 * @param clientCert
	 *            the client cert
	 * @return true, if is certificate trusted
	 */
	private boolean isCertificateTrusted(java.security.cert.X509Certificate clientCert)
	{
		String sMethod = "isCertificateTrusted";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "Check clientCert="
				+ clientCert.getSubjectX500Principal().getName() + " - Issued by "
				+ clientCert.getIssuerX500Principal().getName());
		Set<String> allIssuers = trustedIssuers.keySet();
		for (String ca : allIssuers) {
			java.security.cert.X509Certificate caCert = trustedIssuers.get(ca);
			if (caCert == null) // skip dummy entry
				continue;
			if (caCert.getSubjectX500Principal().equals(clientCert.getIssuerX500Principal())) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Trusted by '" + ca + "': "
						+ caCert.getSubjectX500Principal().getName());
				return true;
			}
		}
		return false;
	}

	/**
	 * Generate the key for the given 'entityId' in 'SSODescriptors'
	 * The key depends on the role of the actual class.
	 * If 'sRole' is null use the role of the partner.
	 * 
	 * @param entityId
	 * @return - the generated key
	 */
	private String makeEntityKey(String entityId, String sRole)
	{
		if (sRole != null)
			return sRole+"_"+entityId;
		
		if ("SP".equals(getMyRole()))
			return "IDP_"+entityId;
		else
			return "SP_"+entityId;
	}
	
	/**
	 * Retrieve the signing key for the given entity id from the metadata cache.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return PublicKey, is null on errors.
	 */
	/*
	public PublicKey getSigningKeyFromMetadata(String entityId)
	{
		String sMethod = "getSigningKeyFromMetadata";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
			ensureMetadataPresence(entityId);
		}
		catch (ASelectException e) {
			return null;
		}

		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors: "+SSODescriptors);
			return null;
		}
		
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
			if (!useType.name().equalsIgnoreCase("SIGNING")) {
//				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != SIGNING");	// RH, 20160512, o
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != SIGNING, trying next if present");	// RH, 20160512, n
//				return null;	// RH, 20160512, o
				continue;	// RH, 20160512, n
			}

			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
			X509Data x509Data = keyinfo.getX509Datas().get(0);

			List<X509Certificate> certs = x509Data.getX509Certificates();
			if (!certs.isEmpty()) {
				X509Certificate cert = certs.get(0);
				try {
					java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert);
					if (javaCert != null) {
						_systemLogger.log(Level.FINER, MODULE, sMethod, "Cert: "
								+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
								+ javaCert.getIssuerX500Principal().getName());
						return javaCert.getPublicKey();
					}
					else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Cannot retrieve the public key from metadata for entity id : " + entityId);
					}
				}
				catch (CertificateException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: ",e);
				}
			}
		}
		return null;
	}
	 */
	
	/**
	 * Retrieve a List of the signing keys from SSODescriptors for the given entity id from the metadata cache.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return List<PublicKey>, is null on errors.
	 */
//	public List<PublicKey> getSigningKeyFromMetadata(String entityId)	// RH, 20190322, o
	public List<PublicKey> getSigningKeyFromMetadata(String resourceGroup, String entityId)	// RH, 20190322, n
	{
		String sMethod = "getSigningKeyFromMetadata";
		List<PublicKey> pubKeys = new ArrayList<PublicKey>();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
//			ensureMetadataPresence(entityId);	// RH, 20190322, o
			ensureMetadataPresence(resourceGroup, entityId);	// RH, 20190322, n
		}
		catch (ASelectException e) {
			return null;
		}

//		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));	// RH, 20190322, o
		SSODescriptor descriptor = SSODescriptors.get(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, null)));	// RH, 20190322, n
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "ResourceGroup:" + resourceGroup + " Entity id:" + entityId + " not in SSODescriptors: "+SSODescriptors);
			return null;
		}
		
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
//			if (!useType.name().equalsIgnoreCase("SIGNING")) {
//			if (useType != UsageType.SIGNING) {
			if (useType != UsageType.SIGNING) {	// First try to find SIGNING

//				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != SIGNING");	// RH, 20160512, o
//				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != SIGNING, trying next if present");	// RH, 20160512, n	// RH, 20181120, o
//				_systemLogger.log(Level.FINE, MODULE, sMethod, "Use type: " + useType + " != " + UsageType.SIGNING + " , trying next if present");	// RH, 20160512, n	// 20181120, n
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid UsageType found: " + useType + ", ignored");	// RH, 20160512, n	// 20181120, n
				
//				return null;	// RH, 20160512, o
				continue;	// RH, 20160512, n
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Allowing keydescriptor with 'use': "  + useType);

//			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
//			X509Data x509Data = keyinfo.getX509Datas().get(0);
//			List<X509Data> x509Datas = keyinfo.getX509Datas();
//			pubKeys = addPubkey(entityId, pubKeys, keyinfo);
			pubKeys = addPubkey2List(entityId, pubKeys, keydescriptor);
		}
		if (pubKeys.size() == 0) {
			for (KeyDescriptor keydescriptor : keyDescriptors) {
				UsageType useType = keydescriptor.getUse();
				if (useType != UsageType.UNSPECIFIED) {	// we'll allow UNSPECIFIED as SIGNING as a fallback
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid UsageType found: " + useType + ", ignored");	// RH, 20160512, n	// 20181120, n
					continue;	// RH, 20160512, n
				}
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Allowing keydescriptor with 'use': "  + useType);
				pubKeys = addPubkey2List(entityId, pubKeys, keydescriptor);
			}
		}
//		return null;	// RH, 20181119, o
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Number of pubKeys found: "  + pubKeys.size());
		return pubKeys;	// RH, 20181119, n
	}

	// RH, 20210812, sn
	/**
	 * Retrieve a List of the signing keys from SSODescriptors for the given entity id from the metadata cache.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return List<PublicKey>, is null on errors.
	 */
	// We could/should combine this method with getSigningKeyFromMetadata() but that will require a huge refactor for the method name
	public List<PublicKey> getEncryptionKeyFromMetadata(String resourceGroup, String entityId)
	{
		String sMethod = "getEncryptionKeyFromMetadata";
		List<PublicKey> pubKeys = new ArrayList<PublicKey>();

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
			ensureMetadataPresence(resourceGroup, entityId);
		}
		catch (ASelectException e) {
			return null;
		}

		SSODescriptor descriptor = SSODescriptors.get(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, null)));
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "ResourceGroup:" + resourceGroup + " Entity id:" + entityId + " not in SSODescriptors: "+SSODescriptors);
			return null;
		}
		
		List<KeyDescriptor> keyDescriptors = descriptor.getKeyDescriptors();
		for (KeyDescriptor keydescriptor : keyDescriptors) {
			UsageType useType = keydescriptor.getUse();
			if (useType != UsageType.ENCRYPTION) {	// First try to find ENCRYPTION
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid UsageType found: " + useType + ", ignored");
				continue;
			}
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Allowing keydescriptor with 'use': "  + useType);

//			org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
//			pubKeys = addPubkey(entityId, pubKeys, keyinfo);
			pubKeys = addPubkey2List(entityId, pubKeys, keydescriptor);
		}
		if (pubKeys.size() == 0) {
			for (KeyDescriptor keydescriptor : keyDescriptors) {
				UsageType useType = keydescriptor.getUse();
				if (useType != UsageType.UNSPECIFIED) {	// we'll allow UNSPECIFIED as ENCRYPTION as a fallback
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Invalid UsageType found: " + useType + ", ignored");
					continue;
				}
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Allowing keydescriptor with 'use': "  + useType);
	
				pubKeys = addPubkey2List(entityId, pubKeys, keydescriptor);
			}
		}
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Number of pubKeys found: "  + pubKeys.size());
		return pubKeys;
	}

	
	
	/**
	 * @param entityId
	 * @param pubKeys, must NOT be null
	 * @param keyinfo, must NOT be null
	 */
//	protected List<PublicKey> addPubkey(String entityId, List<PublicKey> pubKeys, org.opensaml.xml.signature.KeyInfo keyinfo) {
	protected List<PublicKey> addPubkey2List(String entityId, List<PublicKey> pubKeys, KeyDescriptor keydescriptor) {
		
		String sMethod = "addPubkey";

		org.opensaml.xml.signature.KeyInfo keyinfo = keydescriptor.getKeyInfo();
		if (keyinfo != null) {
			List<X509Data> x509Datas = keyinfo.getX509Datas();
	
			if (x509Datas != null && !x509Datas.isEmpty()) {
				for (X509Data x509Data : x509Datas) {
	
					List<X509Certificate> certs = x509Data.getX509Certificates();
					if (certs != null && !certs.isEmpty()) {
						for (X509Certificate cert : certs) {
	//						X509Certificate cert = certs.get(0);
							try {
								java.security.cert.X509Certificate javaCert = SamlTools.getCertificate(cert);
								if (javaCert != null) {
									_systemLogger.log(Level.FINER, MODULE, sMethod, "Cert: "
											+ javaCert.getSubjectX500Principal().getName() + " - Issuer="
											+ javaCert.getIssuerX500Principal().getName());
	//									return javaCert.getPublicKey();
									pubKeys.add(javaCert.getPublicKey());
								}
								else {
									_systemLogger.log(Level.WARNING, MODULE, sMethod,
											"Cannot retrieve the public key one of X509Certificate from metadata for entity id : " 
													+ entityId + " , continuing nextX509Certificate ");
								}
							}
							catch (CertificateException e) {
								_systemLogger.log(Level.WARNING, MODULE, sMethod, "Cannot retrieve the public key from metadata: " 
										+ e.getMessage() + " , continuing next X509Certificate " );
							}
						}
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod,
								"Cannot retrieve X509Certificate from metadata for entity id : " + entityId + " , continuing next X509Data");
					}
				}
			} else {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Cannot retrieve X509Data from metadata for entity id : " + entityId + " , continuing next KeyDescriptor");
			}
		} else {
			_systemLogger.log(Level.WARNING, MODULE, sMethod,
					"KeyDescriptor without KeyInfo for entity id : " + entityId + " , continuing next KeyDescriptor");
		}
		return pubKeys;
	}
	// RH, 20210812, en

	
	
	// 20110406, Bauke: added
	/**
	 * Gets the attribute from metadata.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param sAttrName
	 *            the attribute name
	 * @return the attribute value
	 */
//	public String getAttributeFromMetadata(String entityId, String sAttrName)	// RH, 20190322, o
	public String getAttributeFromMetadata(String resourceGroup, String entityId, String sAttrName)	// RH, 20190322, n
	{
		String sMethod = "getAttributeFromMetadata";

		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId);
		try {
//			ensureMetadataPresence(entityId);	// RH, 20190322, o
			ensureMetadataPresence(resourceGroup, entityId);	// RH, 20190322, n
		}
		catch (ASelectException e) {
			return null;
		}

//		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));	// RH, 20190322, o
		SSODescriptor descriptor = SSODescriptors.get(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, null)));	// RH, 20190322, n
		if (descriptor == null) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Entity id: " + entityId + " not in SSODescriptors");
			return null;
		}

		String sAttrValue = descriptor.getDOM().getAttribute(sAttrName);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, sAttrName+"="+sAttrValue);
		return sAttrValue;
	}

	/**
	 * Gets the location.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 * <BR>
	 *            SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 * <BR>
	 *            SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return Location
	 * @throws ASelectException
	 *             the a select exception
	 */
//	public String getLocation(String entityId, String elementName, String bindingName)	// RH, 20190322, o
	public String getLocation(String resourceGroup, String entityId, String elementName, String bindingName)	// RH, 20190322, n
	throws ASelectException
	{
//		String locationValue = getAttrFromElementBinding(entityId, elementName, bindingName, "Location", null);	// RH, 20190322, o
		String locationValue = getAttrFromElementBinding(resourceGroup, entityId, elementName, bindingName, "Location", null);	// RH, 20190322, n
		return locationValue;
	}

	/**
	 * Gets the response location.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 * <BR>
	 *            SingleLogoutService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            SingleSignOnService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            ArtifactResolutionService.DEFAULT_ELEMENT_LOCAL_NAME <BR>
	 *            AssertionConsumerService.DEFAULT_ELEMENT_LOCAL_NAME
	 * @param bindingName
	 * <BR>
	 *            SAMLConstants.SAML2_SOAP11_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_REDIRECT_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_POST_BINDING_URI <BR>
	 *            SAMLConstants.SAML2_ARTIFACT_BINDING_URI
	 * @return ResponseLocation
	 * @throws ASelectException
	 *             the a select exception
	 */
//	public String getResponseLocation(String entityId, String elementName, String bindingName)	// RH, 20190322, o
	public String getResponseLocation(String resourceGroup, String entityId, String elementName, String bindingName)	// RH, 20190322, n
	throws ASelectException
	{
//		return getAttrFromElementBinding(entityId, elementName, bindingName, "ResponseLocation", null);	// RH, 20190322, o
		return getAttrFromElementBinding(resourceGroup, entityId, elementName, bindingName, "ResponseLocation", null);	// RH, 20190322, o
	}

	/**
	 * Gets the location and binding.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 *            the element name
	 * @param bindingName
	 *            the binding name
	 * @param whichLocation
	 *            the name of the requested location
	 * @param hmBinding
	 *            hash map for the binding found
	 * @return the location found
	 * @throws ASelectException
	 */
	// 20110323, Bauke added to pass back binding from metadata
//	public String getLocationAndBinding(String entityId, String elementName, String bindingName,	// RH, 20190322, o
	public String getLocationAndBinding(String resourceGroup, String entityId, String elementName, String bindingName,	// RH, 20190322, n
					String whichLocation, HashMap<String, String> hmBinding)
	throws ASelectException
	{
//		return getAttrFromElementBinding(entityId, elementName, bindingName, whichLocation, hmBinding);	// RH, 20190322, o
		return getAttrFromElementBinding(resourceGroup, entityId, elementName, bindingName, whichLocation, hmBinding);	// RH, 20190322, n
	}

	/**
	 * Retrieve the value for "attrName" within the entity 'entityId' looking
	 * for 'elementName' with binding 'bindingName'.
	 * 
	 * @param entityId
	 *            the entity id
	 * @param elementName
	 *            the element name
	 * @param requestedBinding
	 *            the binding name, can be empty meaning "pick any"
	 * @param attrName
	 *            the attribute name we're looking for
	 * @param hmBinding
	 *            the hashmap to receive the binding
	 * @return the requested attribute
	 * @throws ASelectException
	 */
//	protected String getAttrFromElementBinding(String entityId, String elementName, String requestedBinding,	// RH, 20190322, o
	protected String getAttrFromElementBinding(String resourceGroup, String entityId, String elementName, String requestedBinding,	// RH, 20190322, n
					String attrName, HashMap<String, String> hmBinding)
	throws ASelectException
	{
		String sMethod = "getAttrFromElementBinding " + Thread.currentThread().getId();
		String location = null;
//		String sDefaultLocation = null;	// RH, 20200203, o

//		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" entityId=" + entityId + " elementName=" + elementName
		_systemLogger.log(Level.INFO, MODULE, sMethod, "myRole="+getMyRole()+" resourceGroup=" + resourceGroup+" entityId=" + entityId + " elementName=" + elementName
				+ " binding=" + requestedBinding + " attr=" + attrName);
		if (entityId == null)
			return null;
//		ensureMetadataPresence(entityId);	// RH, 20190322, o
		ensureMetadataPresence(resourceGroup, entityId);	// RH, 20190322, n
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "Presence ensured for " + entityId);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Presence ensured for resourceGroup=" + resourceGroup+" entityId=" + entityId);
		
//		SSODescriptor descriptor = SSODescriptors.get(makeEntityKey(entityId, null));	// RH, 20190322, o
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "SSODescriptors:" + SSODescriptors);
		SSODescriptor descriptor = SSODescriptors.get(new AbstractMap.SimpleEntry<String, String>(resourceGroup, makeEntityKey(entityId, null)));	// RH, 20190322, n
		if (descriptor == null) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No SSODescriptor for " + entityId);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "No SSODescriptor for resourceGroup=" + resourceGroup+" entityId=" + entityId);
		}
		else {
			try {
				Element domDescriptor = marshallDescriptor(descriptor);
//				if (domDescriptor == null)	// RH, 20200203, o
//				_systemLogger.log(Level.WARNING, MODULE, sMethod, "marshallDescriptor failed");	// RH, 20200203, o
				if (domDescriptor != null) { 	// RH, 20200203, o
					NodeList nodeList = domDescriptor.getChildNodes();
	
					// RH, 20200127, so				
					/*
					// follow saml specs more precisely here, fix this
					//_systemLogger.log(Level.FINE, MODULE, sMethod, "Try "+nodeList.getLength()+" entries");
					for (int i = 0; i < nodeList.getLength(); i++) {
						Node childNode = nodeList.item(i);
						//_systemLogger.log(Level.FINE, MODULE, sMethod, "Node "+childNode.getLocalName());
						if (elementName.equals(childNode.getLocalName())) {
							NamedNodeMap nodeMap = childNode.getAttributes();
							String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
							Node nIsDefault = nodeMap.getNamedItem("isDefault");
							boolean isDefault = false;
							if (nIsDefault != null && "true".equals(nIsDefault.getNodeValue()))
								isDefault = true;
							_systemLogger.log(Level.FINE, MODULE, sMethod, "Try binding="+bindingMDValue+" isDefault="+isDefault);
							if ((!Utils.hasValue(requestedBinding) && isDefault) || bindingMDValue.equals(requestedBinding)) {
								Node node = nodeMap.getNamedItem(attrName);
								if (node != null) {
									location = node.getNodeValue();
									if (hmBinding != null)
										hmBinding.put("binding", bindingMDValue);
									_systemLogger.log(Level.FINER, MODULE, sMethod, "Found location for entityId="
											+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
											+ " attrName=" + attrName + " location=" + location+" binding="+bindingMDValue);
								}
								else {
									if (hmBinding != null)
										hmBinding.clear();
									_systemLogger.log(Level.FINER, MODULE, sMethod, "Did not find location for entityId="
											+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
											+ " attrName=" + attrName + " locatione=" + location);
								}
								break;  // ready
							}
						}
					}
					
					*/
					// RH, 20200127, eo				
	
					// RH, 20200127, sn				
					List<Node> entities = new ArrayList<Node>();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "nodeList.getLength():" + nodeList.getLength());
					for (int i = 0; i < nodeList.getLength(); i++) {	// only add Elements of interest
						if (elementName.equals(nodeList.item(i).getLocalName())) {
							entities.add( nodeList.item(i));
							_systemLogger.log(Level.FINEST, MODULE, sMethod, "added nodeList.item: " + i + " " + nodeList.item(i).getLocalName());
						}
					}
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Number of elements to compare:" + entities.size());
					
					if (!entities.isEmpty()) {
				        Collections.sort(entities, new Comparator<Node>() {
				            public int compare(Node node, Node node1) {
				            	// we will reverse order for convenience, so items of least interest are at the end
				            	// Binding is mandatory for the nodes we're interested in but we'll account for null anyway
								NamedNodeMap nodeMap = node.getAttributes();
								if (nodeMap == null) return 1;	// node is of less interest than node1
								String bindingMDValue = nodeMap.getNamedItem("Binding").getNodeValue();
								if (bindingMDValue == null) return 1;	// node is of less interest than node1
								Node nIsDefault = nodeMap.getNamedItem("isDefault");
								if ( nIsDefault != null && 
										!("true".equalsIgnoreCase(nIsDefault.getNodeValue()) || "false".equalsIgnoreCase(nIsDefault.getNodeValue())) ) {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Encountered illegal value for isDefault, ignored. Illegal value= " + nIsDefault.getNodeValue());
									nIsDefault = null;
								}
		
								NamedNodeMap nodeMap1 = node1.getAttributes();
								if (nodeMap1 == null) return -1;	// node is of more interest than node1
								String bindingMDValue1 = nodeMap1.getNamedItem("Binding").getNodeValue();
								if (bindingMDValue1 == null) return -1;	// node is of more interest than node1
								Node nIsDefault1 = nodeMap1.getNamedItem("isDefault");
								if ( nIsDefault1 != null && 
										!("true".equalsIgnoreCase(nIsDefault1.getNodeValue()) || "false".equalsIgnoreCase(nIsDefault1.getNodeValue())) ) {
									_systemLogger.log(Level.WARNING, MODULE, sMethod, "Encountered illegal value for isDefault, ignored. Illegal value= " + nIsDefault1.getNodeValue());
									nIsDefault1 = null;
								}
								
								// binding takes precedence
								if (bindingMDValue.equals(requestedBinding) && !bindingMDValue1.equals(requestedBinding)) {
									return -1;
				        	
								} else if (bindingMDValue1.equals(requestedBinding) && !bindingMDValue.equals(requestedBinding)) {
									return 1;
								}
								// max one should have isDefault=true but we'll allow for multiple 
								if (nIsDefault != null) {
									if ("true".equalsIgnoreCase(nIsDefault.getNodeValue())) {
										if (nIsDefault1 == null || !"false".equalsIgnoreCase(nIsDefault1.getNodeValue())) {
											return -1;
										}
									} else {	// nIsDefault == false
										if (nIsDefault1 == null || "true".equalsIgnoreCase(nIsDefault1.getNodeValue())) {
											return 1;
										}
									}
								} else {	//	nIsDefault == null
									if ( nIsDefault1 != null ) {
										if ("true".equalsIgnoreCase(nIsDefault1.getNodeValue())) {	// node is of less interest than node1
											return 1;
										} else {	// nIsDefault1 == false, // node is of more interest than node1
											return -1;
										}
									}
								}
								// This (java) sort is guaranteed to be stable. It means that equal elements will not be reordered as a result of the sort.
								// So to preserve order it should be sufficient to return zero
								return 0;
				            }
				        });
		
						Node preferredNode = entities.get(0);
						NamedNodeMap preferredMap = preferredNode.getAttributes();
						if ( requestedBinding == null || preferredMap.getNamedItem("Binding").getNodeValue().equals(requestedBinding) ) {
							Node node = preferredMap.getNamedItem(attrName);
							if (node != null) {
								location = node.getNodeValue();
								if (hmBinding != null)
									hmBinding.put("binding", preferredMap.getNamedItem("Binding").getNodeValue());
								_systemLogger.log(Level.FINER, MODULE, sMethod, "Found (response)location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
										+ " attrName=" + attrName + " (response)location=" + location+" binding="+preferredMap.getNamedItem("Binding").getNodeValue());
							}
							else {
								if (hmBinding != null)
									hmBinding.clear();
								_systemLogger.log(Level.FINER, MODULE, sMethod, "Did not find location for entityId="
										+ entityId + " elementName=" + elementName + " bindingName=" + requestedBinding
										+ " attrName=" + attrName + " (response)location=" + location);
							}
						}
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "No descriptors found for requested elementname: " + elementName);
					}
					// RH, 20200127, en
				} else { // RH, 20200203, sn
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "marshallDescriptor returned null");
				} // RH, 20200203, en
			}
			catch (MarshallingException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Marshalling failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);

			}
			catch (XMLParserException e) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Parser failed with the following error: ", e);
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
			}
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Returning (response)location: " + location);
		return location;
	}

	/**
	 * Marshall descriptor.
	 * 
	 * @param descriptor
	 *            the descriptor
	 * @return the element
	 * @throws MarshallingException
	 *             the marshalling exception
	 * @throws XMLParserException
	 *             the XML parser exception
	 */
	private synchronized Element marshallDescriptor(XMLObject descriptor)
	throws MarshallingException, XMLParserException
	{
		String sMethod = "marshallDescriptor";

		BasicParserPool parser = new BasicParserPool();
		parser.setNamespaceAware(true);
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(descriptor);

		_systemLogger.log(Level.FINER, MODULE, sMethod, "Marshall " + descriptor);
		//_systemLogger.log(Level.FINEST, MODULE, sMethod, XMLHelper.prettyPrintXML(descriptor.getDOM()));
		Element domDescriptor = marshaller.marshall(descriptor, parser.newDocument());
		return domDescriptor;
	}

	/**
	 * Gets the check certificates.
	 * 
	 * @return the check certificates
	 */
	public static String getCheckCertificates()
	{
		return _sCheckCertificates;
	}

	/**
	 * Sets the check certificates.
	 * 
	 * @param checkCertificates
	 *            the new check certificates
	 */
	public static void setCheckCertificates(String checkCertificates)
	{
		_sCheckCertificates = checkCertificates;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return The session sync URL, or null on errors.
	 */
//	public String getSessionSyncURL(String entityId)	// RH, 20190321, o
	public String getSessionSyncURL(String sResourceGroup, String entityId)	// RH, 20190321, n
	{
		String sMethod = "getSessionSyncURL";
		String sUrl = null;

//		PartnerData partnerData = getPartnerDataEntry(entityId);	// RH, 20190321, o		
		PartnerData partnerData = getPartnerDataEntry(sResourceGroup, entityId);	// RH, 20190321, n	
		if (partnerData != null)
			sUrl = partnerData.getSessionSyncUrl();
		if (sUrl == null) {
			_systemLogger.log(Level.INFO, MODULE, sMethod, "SessionSync not found for Entity id: "+entityId);
		}
		return sUrl;
	}

	/**
	 * Retrieve the session sync URL for the given entity id.
	 * 
	 * @param entityId
	 *            the entity id
	 * @return The session sync URL, or null on errors.
	 */
//	public String getMetadataURL(String entityId)
	public String getMetadataURL(String sResourceGroup, String entityId)	// RH, 20190321, o
	{
		String sMethod = "getMetadataURL";
		String sUrl = null;

//		PartnerData partnerData = getPartnerDataEntry(entityId);	// RH, 20190321, o
		PartnerData partnerData = getPartnerDataEntry(sResourceGroup, entityId);	// RH, 20190321, n
		if (partnerData != null)
			sUrl = partnerData.getMetadataUrl();
		
		if (sUrl == null)
			_systemLogger.log(Level.INFO, MODULE, sMethod, "Metadata not found for Entity id: "+entityId);
		return sUrl;
	}

	// RH, 20190321, so
//	/**
//	 * Get the PartnerData entry for the given entity id
//	 * 
//	 * @param entityId
//	 * @return - the entry
//	 */
//	public PartnerData getPartnerDataEntry(String entityId)
//	{
//		PartnerData partnerData = storeAllIdPData.get(entityId);
//		if (partnerData == null)
//			partnerData = storeAllIdPData.get("metadata");
//		return partnerData;
//	}
	// RH, 20190321, eo

	// RH, 20190321, sn
	/**
	 * Get the PartnerData entry for the given entity id
	 * 
	 * @param entityId
	 * @return - the entry
	 */
	public PartnerData getPartnerDataEntry(String _sResourceGroup, String entityId)
	{
		String sMethod = "getPartnerDataEntry";
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "storeAllIdPData:" + storeAllIdPData);

		PartnerData partnerData = null;
		if (_sResourceGroup != null) {
			partnerData = storeAllIdPData.get(new AbstractMap.SimpleEntry<String,String>(_sResourceGroup, entityId));
			if (partnerData != null) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Found partnerdata in _sResourceGroup / entityId:" + _sResourceGroup + " / " + entityId);
			}

		} else {
			partnerData = storeAllIdPData.get(new AbstractMap.SimpleEntry<String,String>("", "metadata"));
			if (partnerData != null) {
				_systemLogger.log(Level.FINER, MODULE, sMethod, "Found partnerdata in _sResourceGroup/entityId:" + "''" + " / " + "metadata");
			}
		}
		if (partnerData == null) {	// last resort
			_systemLogger.log(Level.FINER, MODULE, sMethod, "No partnerdata found, trying all resourcegroups");
			Set<Map.Entry<String,String>> keys = storeAllIdPData.keySet();
			boolean found = false;
			for (Map.Entry<String,String> key : keys) {
				
				if ( entityId.equals(key.getValue()) ) {
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Found partnerdata for entityId:" + entityId + " in resourcegroup:" + key.getKey());
					if (!found) {
						partnerData = storeAllIdPData.get(key);
						found = true;
					} else {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Found another partnerdata for entityId:" + entityId + " in resourcegroup:" + key.getKey());
					}
				}
			}
		}
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "Finally returning partnerData:" + partnerData);
		return partnerData;
	}
	// RH, 20190321, en

	
	/**
	 * Return the number of configured IdPs
	 * 
	 * @return the idp count
	 */
	public int getIdpCount()
	{
		// Does not return actual number of entries, but is never called
		// Should return total number of entries
		return storeAllIdPData.size();
	}

	// RH, 20190321, so
//	/**
//	 * Gets the default IdP.
//	 * 
//	 * @return the default IdP
//	 */
//	public String getDefaultIdP()
//	{
//		// Get the first one, useful when there's only one (the default)
//		Set<String> keys = storeAllIdPData.keySet();
//		for (Object s : keys) {
//			String sIdP = (String) s;
//			return (sIdP.equals("metadata")) ? _configManager.getFederationUrl() : sIdP;
//		}
//		return null;
//	}
	// RH, 20190321, eo
	
	// RH, 20190321, sn
	/**
	 * Gets the default IdP.
	 * 
	 * @return the default IdP
	 */
	public String getDefaultIdP()
	{
		// Get the first one, useful when there's only one (the default)
		Set<Map.Entry<String, String>> keys = storeAllIdPData.keySet();
		for (Map.Entry<String, String> s : keys) {
			Map.Entry<String, String> sIdP = s;
//			return (sIdP.equals("metadata")) ? _configManager.getFederationUrl() : sIdP;
			return ( "metadata".equals(sIdP.getValue()) ) ? _configManager.getFederationUrl() : sIdP.getValue();
		}
		return null;
	}
	// RH, 20190321, en
	
}
