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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.apache.commons.lang.builder.StandardToStringStyle;
import org.apache.commons.lang.builder.ToStringStyle;
import org.aselect.server.request.handler.xsaml20.SecurityLevel.SecurityLevelEntry;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.Utils;

/**
 * Store all data for an IdP or SP partner
 * @author bauke
 *
 */
public class PartnerData
{

	private String partnerID = null;
	private String metadataUrl = null;
	private String sessionSyncUrl = null;
	private String specialSettings = null;
	private String sRedirectSyncTime = null;
	private String sRedirectPostForm = null;

	private String localIssuer = null;
	private String destination = null;
	private String assertionconsumerserviceindex = null;
	private String attributeconsumerserviceindex = null;
	private String addkeyname = null;
	private String addcertificate = null;
	
	private String logoutSupport = "true";
	private String suppressscoping = null; // RH, 20180327, n
	private String suppresssforcedauthn = null; // RH, 20190412, n
	
	private String idpentryproviderid = null; // RH, 20181005, n

	private String federationurl = null;
	private SecurityLevelEntry[] securityLevels = null;
	private Metadata4Partner metadata4partner = null;
	private Testdata4Partner testdata4partner = null;
	private Extensionsdata4Partner extensionsdata4partner = null;

	private Crypto crypto = null;	// RH, 20180917, n
	// RH, 20181102, sn
	private String id_keylocation = null;
	private String pd_keylocation = null;
	private String pc_keylocation = null;
	private String i_point = null;
	private String p_point = null;
	// RH, 20181102, en

	public PartnerData(String sId)
	{
		partnerID = sId;
	}

	
	@Override
	public String toString()
	{
		return "IdPData["+partnerID+"] meta="+metadataUrl+" sync="+sessionSyncUrl+" spec="+specialSettings+" acsi="+assertionconsumerserviceindex;
		
//		return "PartnerData:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();

		  
	}

	/*
	@Override
	public String toString() {
		return String.format(
				"PartnerData [partnerID=%s, metadataUrl=%s, sessionSyncUrl=%s, specialSettings=%s, sRedirectSyncTime=%s, sRedirectPostForm=%s, localIssuer=%s, destination=%s, assertionconsumerserviceindex=%s, attributeconsumerserviceindex=%s, addkeyname=%s, addcertificate=%s, logoutSupport=%s, suppressscoping=%s, idpentryproviderid=%s, federationurl=%s, securityLevels=%s, metadata4partner=%s, testdata4partner=%s, extensionsdata4partner=%s, crypto=%s, id_keylocation=%s, pd_keylocation=%s, pc_keylocation=%s, i_point=%s, p_point=%s]",
				partnerID, metadataUrl, sessionSyncUrl, specialSettings, sRedirectSyncTime, sRedirectPostForm,
				localIssuer, destination, assertionconsumerserviceindex, attributeconsumerserviceindex, addkeyname,
				addcertificate, logoutSupport, suppressscoping, idpentryproviderid, federationurl,
				Arrays.toString(securityLevels), metadata4partner, testdata4partner, extensionsdata4partner, crypto,
				id_keylocation, pd_keylocation, pc_keylocation, i_point, p_point);
	}
*/

	
	public String getPartnerID() {
		return partnerID;
	}

	public void setPartnerID(String partnerId) {
		this.partnerID = partnerId;
	}

	public String getMetadataUrl() {
		return metadataUrl;
	}

	public void setMetadataUrl(String metadataUrl) {
		this.metadataUrl = metadataUrl;
	}

	public String getSessionSyncUrl() {
		return sessionSyncUrl;
	}

	public void setSessionSyncUrl(String sessionSyncUrl) {
		this.sessionSyncUrl = sessionSyncUrl;
	}

	public String getSpecialSettings() {
		return specialSettings;
	}
	public void setSpecialSettings(String special) {
		this.specialSettings = special;
	}
	
	public String getRedirectSyncTime() {
		return sRedirectSyncTime;
	}
	public void setRedirectSyncTime(String sRedirectSyncTime) {
		this.sRedirectSyncTime = sRedirectSyncTime;
	}

	public String getRedirectPostForm() {
		return sRedirectPostForm;
	}
	public void setRedirectPostForm(String sRedirectPostForm) {
		this.sRedirectPostForm = sRedirectPostForm;
	}

	public String getLocalIssuer() {
		return localIssuer;
	}

	public void setLocalIssuer(String issuer) {
		this.localIssuer = issuer;
	}

	public synchronized String getDestination()
	{
		return destination;
	}

	public synchronized void setDestination(String destination)
	{
		this.destination = destination;
	}

	public synchronized String getFederationurl()
	{
		return federationurl;
	}

	public synchronized void setFederationurl(String federationurl)
	{
		this.federationurl = federationurl;
	}

	public synchronized String getAssertionConsumerServiceindex()
	{
		return assertionconsumerserviceindex;
	}

	public synchronized void setAssertionConsumerServiceindex(String serviceindex)
	{
		this.assertionconsumerserviceindex = serviceindex;
	}

	public synchronized String getAddkeyname()
	{
		return addkeyname;
	}

	public synchronized void setAddkeyname(String addkeyname)
	{
		this.addkeyname = addkeyname;
	}

	public synchronized String getAddcertificate()
	{
		return addcertificate;
	}

	public synchronized void setAddcertificate(String addcertificate)
	{
		this.addcertificate = addcertificate;
	}
	
	public synchronized String getAttributeConsumerServiceindex()
	{
		return attributeconsumerserviceindex;
	}

	public synchronized void setAttributeConsumerServiceindex(String attributeconsumerserviceindex)
	{
		this.attributeconsumerserviceindex = attributeconsumerserviceindex;
	}
	
	public synchronized String getLogoutSupport()
	{
		return logoutSupport;
	}

	public synchronized void setLogoutSupport(String logoutSupport)
	{
		this.logoutSupport = logoutSupport;
	}

	/**
	 * @return the suppressscoping
	 */
	public synchronized String getSuppressscoping()
	{
		return suppressscoping;
	}

	/**
	 * @param suppressscoping the suppressscoping to set
	 */
	public synchronized void setSuppressscoping(String suppressscoping)
	{
		this.suppressscoping = suppressscoping;
	}
	
	public synchronized String getSuppresssforcedauthn() {
		return suppresssforcedauthn;
	}

	public synchronized void setSuppresssforcedauthn(String suppresssforcedauthn) {
		this.suppresssforcedauthn = suppresssforcedauthn;
	}

	public synchronized String getIdpentryproviderid() {
		return idpentryproviderid;
	}

	public synchronized void setIdpentryproviderid(String idpentryproviderid) {
		this.idpentryproviderid = idpentryproviderid;
	}

	// Simple wrapper for crypto info
	public class Crypto
	{
		@Override
		public String toString() {
			return String.format("Crypto [x509Cert=%s, sCertFingerPrint=%s]", x509Cert, sCertFingerPrint);
			
//			return "Crypto:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();

		}

		private java.security.cert.X509Certificate x509Cert = null;
		private PrivateKey oPrivateKey = null;
		private String sCertFingerPrint = null;

		private Crypto()
		{
			// hide this constructor
		}

		public Crypto(java.security.cert.X509Certificate x509Cert, PrivateKey oPrivateKey, String sCertFingerPrint)
		{
			this.x509Cert = x509Cert;
			this.oPrivateKey = oPrivateKey;
			this.sCertFingerPrint = sCertFingerPrint;
		}

		public synchronized java.security.cert.X509Certificate getX509Cert() {
			return x509Cert;
		}

		public synchronized void setX509Cert(java.security.cert.X509Certificate x509Cert) {
			this.x509Cert = x509Cert;
		}

		public synchronized PrivateKey getPrivateKey() {
			return oPrivateKey;
		}

		public synchronized void setPrivateKey(PrivateKey oPrivateKey) {
			this.oPrivateKey = oPrivateKey;
		}

		public synchronized String getCertFingerPrint() {
			return sCertFingerPrint;
		}

		public synchronized void setCertFingerPrint(String sCertFingerPrint) {
			this.sCertFingerPrint = sCertFingerPrint;
		}
	}
	
	
	/**
	 * @return the crypto
	 */
	public synchronized Crypto getCrypto() {
		return crypto;
	}
	
//	/**
//	 * @param crypto the crypto to set
//	 */
//	public synchronized void setCrypto(Crypto crypto) {
//		this.crypto = crypto;
//	}
	

	public synchronized void loadSpecificCrypto(String sWorkingDir, String sKeyStoreName, String sAlias, String sPassword) throws ASelectException {
		String sMethod = "loadSpecificCrypto";
		
		StringBuffer sbKeystoreLocation = new StringBuffer(sWorkingDir);

		try {

			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("keystores");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append("partners");
			sbKeystoreLocation.append(File.separator);
			sbKeystoreLocation.append(sKeyStoreName);
			KeyStore ksASelect = KeyStore.getInstance("JKS");
			ksASelect.load(new FileInputStream(sbKeystoreLocation.toString()), null);

			// convert String to char[]
			char[] caPassword = sPassword.toCharArray();
			PrivateKey oPrivateKey = (PrivateKey) ksASelect.getKey(sAlias, caPassword);

			java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) ksASelect
					.getCertificate(sAlias);

			byte[] baCert = x509Cert.getEncoded();
			MessageDigest mdDigest = MessageDigest.getInstance("SHA1");
			mdDigest.update(baCert);
			String sCertFingerPrint = Utils.byteArrayToHexString(mdDigest.digest());

			crypto = new Crypto(x509Cert, oPrivateKey, sCertFingerPrint);
//			crypto.put("signing_cert", x509Cert);
//			crypto.put("private_key", oPrivateKey);
//			crypto.put("cert_id", sCertFingerPrint);
		}
		catch (Exception e) {
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}

	}
	// RH, 20180917, en

	// RH, 20181102, sn
	// Polymorf file locations
	public synchronized String getId_keylocation() {
		return id_keylocation;
	}

	public synchronized void setId_keylocation(String sWorkingDir, String id_keyfile) {
		StringBuffer sbId_keylocation = new StringBuffer(sWorkingDir);
		sbId_keylocation.append(File.separator);
		sbId_keylocation.append("keystores");
		sbId_keylocation.append(File.separator);
		sbId_keylocation.append("partners");
		sbId_keylocation.append(File.separator);
		sbId_keylocation.append(id_keyfile);

		this.id_keylocation = sbId_keylocation.toString();
	}

	public synchronized String getI_point() {
		return i_point;
	}

	public synchronized void setI_point(String i_point) {
		this.i_point = i_point;
	}

	public synchronized String getPd_keylocation() {
		return pd_keylocation;
	}

	public synchronized void setPd_keylocation(String sWorkingDir, String pd_keyfile) {
		StringBuffer sbPd_keylocation = new StringBuffer(sWorkingDir);
		sbPd_keylocation.append(File.separator);
		sbPd_keylocation.append("keystores");
		sbPd_keylocation.append(File.separator);
		sbPd_keylocation.append("partners");
		sbPd_keylocation.append(File.separator);
		sbPd_keylocation.append(pd_keyfile);
		this.pd_keylocation = sbPd_keylocation.toString();
	}

	public synchronized String getPc_keylocation() {
		return pc_keylocation;
	}

	public synchronized void setPc_keylocation(String sWorkingDir, String pc_keyfile) {
		StringBuffer sbPc_keylocation = new StringBuffer(sWorkingDir);
		sbPc_keylocation.append(File.separator);
		sbPc_keylocation.append("keystores");
		sbPc_keylocation.append(File.separator);
		sbPc_keylocation.append("partners");
		sbPc_keylocation.append(File.separator);
		sbPc_keylocation.append(pc_keyfile);
		this.pc_keylocation = sbPc_keylocation.toString();
	}
	// RH, 20181102, en
	
	public synchronized String getP_point() {
		return p_point;
	}

	public synchronized void setP_point(String p_point) {
		this.p_point = p_point;
	}

	/**
	 * @return the metadata4partner
	 */
	public synchronized Metadata4Partner getMetadata4partner()
	{
		if (metadata4partner == null) {
			metadata4partner = new Metadata4Partner();
		}
		return metadata4partner;
	}

	public synchronized SecurityLevelEntry[] getSecurityLevels() {
		return securityLevels;
	}

	public synchronized void setSecurityLevels(SecurityLevelEntry[] securityLevels) {
		this.securityLevels = securityLevels;
	}

	
	// Simple wrapper for handler info
	public class HandlerInfo
	{
		private String type = null;
		private String binding = null;
		private Boolean isdefault = null;
		private Integer index =  null;
		private String responselocation =  null;
		private String location =  null;

		private List<Map<String, ?>> services = null;	// for attributeconsumingservice
		private List<Map<String, ?>> attributes = null;	// for attributeconsumingservice

		private HandlerInfo()
		{
			// hide this constructor
		}

		public HandlerInfo(String type, String binding, Boolean isdefault, Integer index, String responselocation, String location)
		{
			this.type = type;
			this.binding = binding;
			this.isdefault = isdefault;
			this.index =  index;
			this.responselocation = responselocation;
			this.location = location;

		}

		@Override
		public String toString() {
//			return String.format(
//					"HandlerInfo [type=%s, binding=%s, isdefault=%s, index=%s, responselocation=%s, location=%s, services=%s, attributes=%s]",
//					type, binding, isdefault, index, responselocation, location, services, attributes);
			return "HandlerInfo:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();

		}

		/**
		 * @return the type
		 */
		public synchronized String getType()
		{
			return type;
		}

		/**
		 * @return the binding
		 */
		public synchronized String getBinding()
		{
			return binding;
		}

		/**
		 * @return the isdefault
		 */
		public synchronized Boolean getIsdefault()
		{
			return isdefault;
		}

		/**
		 * @return the index
		 */
		public synchronized Integer getIndex()
		{
			return index;
		}

		/**
		 * @return the responselocation
		 */
		public synchronized String getResponselocation()
		{
			return responselocation;
		}

		public synchronized String getLocation()
		{
			return location;
		}

		public synchronized void setLocation(String location)
		{
			this.location = location;
		}
		
		public synchronized List<Map<String, ?>> getServices()
		{
			if (services == null) {
				services = new ArrayList<Map<String, ?>>();
			}
			return services;
		}

		public synchronized List<Map<String, ?>> getAttributes()
		{
			if (attributes == null) {
				attributes = new ArrayList<Map<String, ?>>();
			}
			return attributes;
		}

	}

	
	// Simple wrapper for NamespaceInfo info
	public class NamespaceInfo
	{
		private String prefix = null;
		private String uri = null;
	
		private Hashtable<String, String> attributes = null;

		private NamespaceInfo()
		{
			// hide this constructor
		}

		public NamespaceInfo(String prefix, String uri, Hashtable<String, String> attributes)
		{
			this.prefix = prefix;
			this.uri = uri;
			this.attributes = attributes;
		}

		@Override
		public String toString() {
//			return String.format("NamespaceInfo [prefix=%s, uri=%s, attributes=%s]", prefix, uri, attributes);
			return "NamespaceInfo:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();
			
		}

		/**
		 * @return the prefix
		 */
		public synchronized String getPrefix()
		{
			return prefix;
		}

		/**
		 * @return the uri
		 */
		public synchronized String getUri()
		{
			return uri;
		}

		/**
		 * @return the attributes
		 */
		public synchronized Hashtable<String, String> getAttributes()
		{
			return attributes;
		}

	}

	
	// SImple wrapper class for specific data 
	public class Metadata4Partner
	{
		// signing information
		private String addkeyname= null;
		private String addcertificate = null;
		private String includesigningcertificate = null;
		private String includeencryptioncertificate = null;
		private String includesigningkeyname = null;
		private String includeencryptionkeyname = null;
		private String specialsettings = null;
		private Vector<HandlerInfo> handlers = new Vector<HandlerInfo>();
			
		// organization data
		private String metaorgname = null;
		private String metaorgnamelang = null;
		private String metaorgdisplname = null;
		private String metaorgdisplnamelang = null;
		private String metaorgurl = null;
		private String metaorgurllang = null;
		
		// contact data
		String metacontacttype = null;
		String metacontactname = null;
		String metacontactsurname = null;
		String metacontactemail = null;
		String metacontactephone = null;

		
		private Vector<NamespaceInfo> namespaces = new Vector<NamespaceInfo>();
		
		@Override
		public String toString() {
//			return String.format(
//					"Metadata4Partner [addkeyname=%s, addcertificate=%s, includesigningcertificate=%s, includeencryptioncertificate=%s, includesigningkeyname=%s, includeencryptionkeyname=%s, specialsettings=%s, handlers=%s, metaorgname=%s, metaorgnamelang=%s, metaorgdisplname=%s, metaorgdisplnamelang=%s, metaorgurl=%s, metaorgurllang=%s, metacontacttype=%s, metacontactname=%s, metacontactsurname=%s, metacontactemail=%s, metacontactephone=%s, namespaces=%s]",
//					addkeyname, addcertificate, includesigningcertificate, includeencryptioncertificate,
//					includesigningkeyname, includeencryptionkeyname, specialsettings, handlers, metaorgname,
//					metaorgnamelang, metaorgdisplname, metaorgdisplnamelang, metaorgurl, metaorgurllang,
//					metacontacttype, metacontactname, metacontactsurname, metacontactemail, metacontactephone,
//					namespaces);
			return "Metadata4Partner:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();

		}

		// Set Organization info, only change values if not null
		public void setOrganizationInfo(		String metaorgname, String metaorgnamelang,
																		String metaorgdisplname, String metaorgdisplnamelang,
																		String metaorgurl, String metaorgurllang) {
			if (metaorgname != null) {
				this.metaorgname = metaorgname;
			}
			if (metaorgnamelang != null) {
				this.metaorgnamelang = metaorgnamelang;
			}
			if (metaorgdisplname != null) {
				this.metaorgdisplname = metaorgdisplname;
			}
			if (metaorgdisplnamelang != null) {
				this.metaorgdisplnamelang = metaorgdisplnamelang;
			}
			if (metaorgurl != null) {
				this.metaorgurl = metaorgurl;
			}
			if (metaorgurllang != null) {
				this.metaorgurllang = metaorgurllang;
			}
			
		}

		// Set Contact info, only change values if not null
		public void setContactInfo(		String metacontacttype,	String metacontactname, String metacontactsurname,
																String metacontactemail, String metacontactephone) {
			if (metacontacttype != null) {
				this.metacontacttype = metacontacttype;
			}
			if (metacontactname != null) {
				this.metacontactname = metacontactname;
			}
			if (metacontactsurname != null) {
				this.metacontactsurname = metacontactsurname;
			}
			if (metacontactemail != null) {
				this.metacontactemail = metacontactemail;
			}
			if (metacontactephone != null) {
				this.metacontactephone = metacontactephone;
			}
			
			
		}

		/**
		 * @return the metaorgname
		 */
		public synchronized String getMetaorgname()
		{
			return metaorgname;
		}

		/**
		 * @return the metaorgnamelang
		 */
		public synchronized String getMetaorgnamelang()
		{
			return metaorgnamelang;
		}

		/**
		 * @return the metaorgdisplname
		 */
		public synchronized String getMetaorgdisplname()
		{
			return metaorgdisplname;
		}

		/**
		 * @return the metaorgdisplnamelang
		 */
		public synchronized String getMetaorgdisplnamelang()
		{
			return metaorgdisplnamelang;
		}

		/**
		 * @return the metaorgurl
		 */
		public synchronized String getMetaorgurl()
		{
			return metaorgurl;
		}

		/**
		 * @return the metaorgurllang
		 */
		public synchronized String getMetaorgurllang()
		{
			return metaorgurllang;
		}

		/**
		 * @return the metacontacttype
		 */
		public synchronized String getMetacontacttype()
		{
			return metacontacttype;
		}

		/**
		 * @return the metacontactname
		 */
		public synchronized String getMetacontactname()
		{
			return metacontactname;
		}

		/**
		 * @return the metacontactsurname
		 */
		public synchronized String getMetacontactsurname()
		{
			return metacontactsurname;
		}

		/**
		 * @return the metacontactemail
		 */
		public synchronized String getMetacontactemail()
		{
			return metacontactemail;
		}

		/**
		 * @return the metacontactephone
		 */
		public synchronized String getMetacontactephone()
		{
			return metacontactephone;
		}

		/**
		 * @return the addkeyname
		 */
		public synchronized String getAddkeyname()
		{
			return addkeyname;
		}

		/**
		 * @param addkeyname the addkeyname to set
		 */
		public synchronized void setAddkeyname(String addkeyname)
		{
			this.addkeyname = addkeyname;
		}

		/**
		 * @return the addcertificate
		 */
		public synchronized String getAddcertificate()
		{
			return addcertificate;
		}

		/**
		 * @param addcertificate the addcertificate to set
		 */
		public synchronized void setAddcertificate(String addcertificate)
		{
			this.addcertificate = addcertificate;
		}


		/**
		 * @return the specialsettings
		 */
		public synchronized String getSpecialsettings()
		{
			return specialsettings;
		}

		/**
		 * @param specialsettings the specialsettings to set
		 */
		public synchronized void setSpecialsettings(String specialsettings)
		{
			this.specialsettings = specialsettings;
		}

		/**
		 * @return the handlers
		 */
		public synchronized Vector<HandlerInfo> getHandlers()
		{
			return handlers;
		}

		/**
		 * @param handler the handler to add
		 */
		public void addHandlerInfo(HandlerInfo handler) {
			handlers.addElement(handler);
		}
		
		/**
		 * @param handler the handler to remove
		 * @return true if handler was present
		 */
		public boolean removeHandlerInfo(HandlerInfo handler) {
			return handlers.removeElement(handler);
		}

		
		/**
		 * @return the handlers
		 */
		public synchronized Vector<NamespaceInfo> getNamespaceInfo()
		{
			return namespaces;
		}

		/**
		 * @param namespaceinfo the namespaceinfo to add
		 */
		public void addNamespaceInfo(NamespaceInfo namespaceinfo) {
			namespaces.addElement(namespaceinfo);
		}
		
		/**
		 * @param namespaceinfo the namespaceinfo to remove
		 * @return true if handler was present
		 */
		public boolean removeNamespaceInfo(HandlerInfo namespaceinfo) {
			return namespaces.removeElement(namespaceinfo);
		}

		public synchronized String getIncludesigningcertificate()
		{
			return includesigningcertificate;
		}

		public synchronized void setIncludesigningcertificate(String includesigningcertificate)
		{
			this.includesigningcertificate = includesigningcertificate;
		}

		public synchronized String getIncludeencryptioncertificate()
		{
			return includeencryptioncertificate;
		}

		public synchronized void setIncludeencryptioncertificate(String includeencryptioncertificate)
		{
			this.includeencryptioncertificate = includeencryptioncertificate;
		}

		public synchronized String getIncludesigningkeyname()
		{
			return includesigningkeyname;
		}

		public synchronized void setIncludesigningkeyname(String includesigningkeyname)
		{
			this.includesigningkeyname = includesigningkeyname;
		}

		public synchronized String getIncludeencryptionkeyname()
		{
			return includeencryptionkeyname;
		}

		public synchronized void setIncludeencryptionkeyname(String includeencryptionkeyname)
		{
			this.includeencryptionkeyname = includeencryptionkeyname;
		}

	}

	// SImple wrapper class for Extensions data 
	public class Extensionsdata4Partner {
		 

		private Integer QualityAuthenticationAssuranceLevel= null;	// will be set based on application requirement
		private String spSector= null;
		private String spInstitution = null;
		private String spApplication = null;
		private String spCountry= null;
		private Boolean eIDSectorShare = null;
		private Boolean eIDCrossSectorShare = null;
		private Boolean eIDCrossBorderShare = null;
		private List<Map<String, Object>> requestedAttributes = null;	// probably use ArrayList implementation

//		@Override
//		public String toString()
//		{
//			return "QualityAuthenticationAssuranceLevel=" + QualityAuthenticationAssuranceLevel
//				+ ", spSector=" + spSector
//				+ ", spInstitution=" + spInstitution
//				+ ", spApplication=" + spApplication
//				+ ", pCountry=" + spCountry
//				+ ", eIDSectorShare=" + eIDSectorShare
//				+ ", eIDCrossSectorShare=" + eIDCrossSectorShare
//				+ ", eIDCrossBorderShare=" + eIDCrossBorderShare
//				+ ", requestedAttributes=" + requestedAttributes
//			;			
//		}

		@Override
		public String toString() {
//			return String.format(
//					"Extensionsdata4Partner [QualityAuthenticationAssuranceLevel=%s, spSector=%s, spInstitution=%s, spApplication=%s, spCountry=%s, eIDSectorShare=%s, eIDCrossSectorShare=%s, eIDCrossBorderShare=%s, requestedAttributes=%s]",
//					QualityAuthenticationAssuranceLevel, spSector, spInstitution, spApplication, spCountry,
//					eIDSectorShare, eIDCrossSectorShare, eIDCrossBorderShare, requestedAttributes);
			
			return "Extensionsdata4Partner:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();

		}

		
		public synchronized Integer getQualityAuthenticationAssuranceLevel()
		{
			return QualityAuthenticationAssuranceLevel;
		}

		public synchronized void setQualityAuthenticationAssuranceLevel(Integer qualityAuthenticationAssuranceLevel)
		{
			QualityAuthenticationAssuranceLevel = qualityAuthenticationAssuranceLevel;
		}

		public synchronized String getSpSector()
		{
			return spSector;
		}

		public synchronized void setSpSector(String spSector)
		{
			this.spSector = spSector;
		}

		public synchronized String getSpInstitution()
		{
			return spInstitution;
		}

		public synchronized void setSpInstitution(String spInstitution)
		{
			this.spInstitution = spInstitution;
		}

		public synchronized String getSpApplication()
		{
			return spApplication;
		}

		public synchronized void setSpApplication(String spApplication)
		{
			this.spApplication = spApplication;
		}

		public synchronized String getSpCountry()
		{
			return spCountry;
		}

		public synchronized void setSpCountry(String spCountry)
		{
			this.spCountry = spCountry;
		}


		public synchronized List<Map<String, Object>> getRequestedAttributes()
		{
			return requestedAttributes;
		}

		public synchronized void setRequestedAttributes(List<Map<String, Object>> requestedAttributes)
		{
			this.requestedAttributes = requestedAttributes;
		}

		public synchronized Boolean geteIDSectorShare()
		{
			return eIDSectorShare;
		}

		public synchronized void seteIDSectorShare(Boolean eIDSectorShare)
		{
			this.eIDSectorShare = eIDSectorShare;
		}

		public synchronized Boolean geteIDCrossSectorShare()
		{
			return eIDCrossSectorShare;
		}

		public synchronized void seteIDCrossSectorShare(Boolean eIDCrossSectorShare)
		{
			this.eIDCrossSectorShare = eIDCrossSectorShare;
		}

		public synchronized Boolean geteIDCrossBorderShare()
		{
			return eIDCrossBorderShare;
		}

		public synchronized void seteIDCrossBorderShare(Boolean eIDCrossBorderShare)
		{
			this.eIDCrossBorderShare = eIDCrossBorderShare;
		}
		
		
	}
	// End SImple wrapper class for Extensions data 
	
	/**
	 * @return the extensionsdata4partner
	 */
	public synchronized Extensionsdata4Partner getExtensionsdata4partner()
	{
		if (extensionsdata4partner == null) {
			extensionsdata4partner = new Extensionsdata4Partner();
		}
		return extensionsdata4partner;
	}


	
	
	// SImple wrapper class for test data 
	public class Testdata4Partner {

		private String IssueInstant= null;
		private String Issuer = null;
		private String AuthnContextClassRefURI = null;
		private String AuthnContextComparisonTypeEnumeration= null;
		private String ForceAuthn = null;
		private String ProviderName = null;
		private String AssertionConsumerServiceIndex= null;
		private String AssertionConsumerServiceURL = null;
		private String Destination = null;
		
		private String IssueInstantLogout= null;
		private String IssuerLogout = null;
		private String DestinationLogout = null;

		/*
		@Override
		public String toString()
		{
			return "IssueInstant=" + IssueInstant
				+ ", Issuer=" + Issuer
				+ ", AuthnContextClassRefURI=" + AuthnContextClassRefURI
				+ ", AuthnContextComparisonTypeEnumeration=" + AuthnContextComparisonTypeEnumeration
				+ ", ForceAuthn=" + ForceAuthn
				+ ", ProviderName=" + ProviderName
				+ ", AssertionConsumerServiceIndex=" + AssertionConsumerServiceIndex
				+ ", AssertionConsumerServiceURL=" + AssertionConsumerServiceURL
				+ ", Destination=" + Destination
				+ ", IssueInstantLogout=" + IssueInstantLogout
				+ ", IssuerLogout=" + IssuerLogout
				+ ", DestinationLogout=" + DestinationLogout
			;			
		}
		*/
		
		@Override
		public String toString() {
//			return String.format(
//					"Testdata4Partner [IssueInstant=%s, Issuer=%s, AuthnContextClassRefURI=%s, AuthnContextComparisonTypeEnumeration=%s, ForceAuthn=%s, ProviderName=%s, AssertionConsumerServiceIndex=%s, AssertionConsumerServiceURL=%s, Destination=%s, IssueInstantLogout=%s, IssuerLogout=%s, DestinationLogout=%s]",
//					IssueInstant, Issuer, AuthnContextClassRefURI, AuthnContextComparisonTypeEnumeration, ForceAuthn,
//					ProviderName, AssertionConsumerServiceIndex, AssertionConsumerServiceURL, Destination,
//					IssueInstantLogout, IssuerLogout, DestinationLogout);
			return "Testdata4Partner:" + new ReflectionToStringBuilder( this, new StandardToStringStyle()).toString();
			
		}
		/**
		 * @return the issueInstant
		 */
		public synchronized String getIssueInstant()
		{
			return IssueInstant;
		}
		/**
		 * @param issueInstant the issueInstant to set
		 */
		public synchronized void setIssueInstant(String issueInstant)
		{
			IssueInstant = issueInstant;
		}
		/**
		 * @return the issuer
		 */
		public synchronized String getIssuer()
		{
			return Issuer;
		}
		/**
		 * @param issuer the issuer to set
		 */
		public synchronized void setIssuer(String issuer)
		{
			Issuer = issuer;
		}
		/**
		 * @return the authnContextClassRefURI
		 */
		public synchronized String getAuthnContextClassRefURI()
		{
			return AuthnContextClassRefURI;
		}
		/**
		 * @param authnContextClassRefURI the authnContextClassRefURI to set
		 */
		public synchronized void setAuthnContextClassRefURI(String authnContextClassRefURI)
		{
			AuthnContextClassRefURI = authnContextClassRefURI;
		}
		/**
		 * @return the authnContextComparisonTypeEnumeration
		 */
		public synchronized String getAuthnContextComparisonTypeEnumeration()
		{
			return AuthnContextComparisonTypeEnumeration;
		}
		/**
		 * @param authnContextComparisonTypeEnumeration the authnContextComparisonTypeEnumeration to set
		 */
		public synchronized void setAuthnContextComparisonTypeEnumeration(String authnContextComparisonTypeEnumeration)
		{
			AuthnContextComparisonTypeEnumeration = authnContextComparisonTypeEnumeration;
		}
		/**
		 * @return the forceAuthn
		 */
		public synchronized String getForceAuthn()
		{
			return ForceAuthn;
		}
		/**
		 * @param forceAuthn the forceAuthn to set
		 */
		public synchronized void setForceAuthn(String forceAuthn)
		{
			ForceAuthn = forceAuthn;
		}
		/**
		 * @return the providerName
		 */
		public synchronized String getProviderName()
		{
			return ProviderName;
		}
		/**
		 * @param providerName the providerName to set
		 */
		public synchronized void setProviderName(String providerName)
		{
			ProviderName = providerName;
		}
		/**
		 * @return the assertionConsumerServiceIndex
		 */
		public synchronized String getAssertionConsumerServiceIndex()
		{
			return AssertionConsumerServiceIndex;
		}
		/**
		 * @param assertionConsumerServiceIndex the assertionConsumerServiceIndex to set
		 */
		public synchronized void setAssertionConsumerServiceIndex(String assertionConsumerServiceIndex)
		{
			AssertionConsumerServiceIndex = assertionConsumerServiceIndex;
		}
		/**
		 * @return the assertionConsumerServiceURL
		 */
		public synchronized String getAssertionConsumerServiceURL()
		{
			return AssertionConsumerServiceURL;
		}
		/**
		 * @param assertionConsumerServiceURL the assertionConsumerServiceURL to set
		 */
		public synchronized void setAssertionConsumerServiceURL(String assertionConsumerServiceURL)
		{
			AssertionConsumerServiceURL = assertionConsumerServiceURL;
		}
		/**
		 * @return the destination
		 */
		public synchronized String getDestination()
		{
			return Destination;
		}
		/**
		 * @param destination the destination to set
		 */
		public synchronized void setDestination(String destination)
		{
			Destination = destination;
		}


		/**
		 * @return the issueInstantLogout
		 */
		public String getIssueInstantLogout()
		{
			return IssueInstantLogout;
		}


		/**
		 * @param issueInstantLogout the issueInstantLogout to set
		 */
		public void setIssueInstantLogout(String issueInstantLogout)
		{
			IssueInstantLogout = issueInstantLogout;
		}


		/**
		 * @return the issuerLogout
		 */
		public String getIssuerLogout()
		{
			return IssuerLogout;
		}


		/**
		 * @param issuerLogout the issuerLogout to set
		 */
		public void setIssuerLogout(String issuerLogout)
		{
			IssuerLogout = issuerLogout;
		}


		/**
		 * @return the destinationLogout
		 */
		public String getDestinationLogout()
		{
			return DestinationLogout;
		}


		/**
		 * @param destinationLogout the destinationLogout to set
		 */
		public void setDestinationLogout(String destinationLogout)
		{
			DestinationLogout = destinationLogout;
		}

	}
	// End SImple wrapper class for test data 

	
	
	/**
	 * @return the testdata4partner
	 */
	public synchronized Testdata4Partner getTestdata4partner()
	{
		if (testdata4partner == null) {
			testdata4partner = new Testdata4Partner();
		}
		return testdata4partner;
	}

	
}
