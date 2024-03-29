/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license. See the included
 * LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE please contact SURFnet bv.
 * (http://www.surfnet.nl)
 */

/*
 * $Id: CryptoEngine.java,v 1.33 2006/04/26 12:18:08 tom Exp $
 * 
 * Changelog: 
 * $Log: CryptoEngine.java,v $
 * Revision 1.33  2006/04/26 12:18:08  tom
 * QA: removed javadoc version tag, minor javadoc fixes
 *
 * Revision 1.32  2005/09/08 12:46:35  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.31  2005/04/15 11:51:23  tom
 * Removed old logging statements
 *
 * Revision 1.30  2005/04/11 08:56:54  erwin
 * Added local A-Select Server signing support for cross A-Select.
 *
 * Revision 1.29  2005/04/01 14:24:50  peter
 * cross aselect redesign
 *
 * Revision 1.28  2005/03/29 09:39:21  martijn
 * fixed: getAuthSPSpecificCertId() needs to lowercase the authsp id
 *
 * Revision 1.27  2005/03/24 16:05:15  erwin
 * Added getAuthSPSpecificCerId() which
 * was deleted during source cleanup.
 *
 * Revision 1.26  2005/03/18 13:43:35  remco
 * made credentials shorter (base64 encoding instead of hex representation)
 *
 * Revision 1.25  2005/03/15 15:29:04  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.24  2005/03/15 15:00:50  martijn
 * renamed special authsp to privileged application
 *
 * Revision 1.23  2005/03/15 14:29:52  peter
 * added verifyCrossASelectSignature()
 *
 * Revision 1.22  2005/03/15 12:56:46  martijn
 * fixed a small bug in retrieving the new crypto config
 *
 * Revision 1.21  2005/03/15 10:55:40  martijn
 * removed unused (commented) code
 *
 * Revision 1.20  2005/03/15 10:12:35  martijn
 * The crypto configuration is changed, providers are now also configurable.
 *
 * Revision 1.19  2005/03/11 16:50:21  martijn
 * moved verifying if max server session keys are reached to the storagemanager
 *
 * Revision 1.18  2005/03/11 10:30:37  erwin
 * Added additional logging in init method.
 *
 * Revision 1.17  2005/03/11 08:41:45  martijn
 * fixed bug: keystore aliasses are always stored in lower case, so when retrieved they must be lowercased.
 *
 * Revision 1.16  2005/03/10 13:15:32  erwin
 * Improved logging.
 *
 * Revision 1.15  2005/03/09 17:33:34  remco
 * "cancel" request -> "error" request (with mandatory parameter "result_code")
 * Revision 1.14  2005/03/09 17:08:54  remco
 * Fixed whole bunch of warnings
 * Revision 1.13  2005/03/09 12:10:53  remco
 * added application signing (untested)
 * Revision 1.12  2005/03/08 11:53:08  remco
 * javadoc added
 * Revision 1.6  2005/03/08 11:51:36  remco
 * class variables renamed
 * Revision 1.5  2005/03/08 10:16:32  remco
 * javadoc added
 * Revision 1.3
 * 2005/03/08 09:51:53 remco javadoc added
 */

package org.aselect.server.crypto;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.logging.Level;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.sam.ASelectSAMAgent;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectConfigException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.exception.ASelectStorageException;
import org.aselect.system.storagemanager.StorageManager;
import org.aselect.system.utils.BASE64Decoder;
import org.aselect.system.utils.BASE64Encoder;
import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * This class contains crypto-related (helper) methods. It is thread-safe. <br>
 * 
 * @author Alfa & Ariss
 */
public class CryptoEngine
{
	private final String MODULE = "CryptoEngine";
	private final String DEFAULT_SIGNATURE_ALGORITHM = "SHA1withRSA";
	private final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";
	private final String DEFAULT_ENCRYPTION_ALGORITHM = "DESede";

	private static CryptoEngine _this;

	private HashMap _htAuthspSettings;
	private ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
	private ASelectSystemLogger _systemLogger;
	private PrivateKey _defaultPrivateKey;
	private boolean _bIsActive = false;

	private SecretKey _secretKey;
	private SecretKey _encryptionKey;  // 20130411, Bauke: used for symmetric encryption, key taken from config file
	private Cipher _cipher;
	private SecureRandom _secureRandom;

	private String _sSecureRandomAlgorithm = null;
	private Provider _oSecureRandomProvider = null;

	private String _sSignatureAlgorithm = null;
	private Provider _oSignatureProvider = null;

	private String _sCipherAlgorithm = null;
	private Provider _oCipherProvider = null;

	private StorageManager _storageManager;

	/**
	 * Instantiates a new crypto engine.
	 */
	private CryptoEngine() {
		_storageManager = new StorageManager();
	}

	/**
	 * Return a reference to the CryptoEngine object. <br>
	 * 
	 * @return The <code>CryptoEngine</code> object
	 */
	public static CryptoEngine getHandle()
	{
		if (_this == null)
			_this = new CryptoEngine();
		return _this;
	}

	/**
	 * Initialize the CryptoEngine. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method reads the crypto-configuration and initializes the CryptoEngine. It should be called from the
	 * ASelectConfigManager. <br>
	 * 
	 * @throws ASelectException
	 *             if initialization fails
	 */
	public void init()
	throws ASelectException
	{
		String sMethod = "init";

		try {
			_systemLogger = ASelectSystemLogger.getHandle();
			Object oASelect = null;
			try {
				oASelect = _configManager.getSection(null, "aselect");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.SEVERE, MODULE, sMethod,
						"Could not find aselect config section in config file", eAC);
				throw eAC;
			}

			Object oCryptoSection = null;
			try {
				oCryptoSection = _configManager.getSection(oASelect, "crypto");
			}
			catch (ASelectConfigException eAC) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod,
						"Could not find crypto config section in config file", eAC);
				throw eAC;
			}

			// Add crypto provider(s)
			Object oProvidersSection = null;
			try {
				oProvidersSection = _configManager.getSection(oCryptoSection, "providers");
			}
			catch (ASelectConfigException eAC) {
//				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
//						"Could not find 'providers' config section in configuration. No providers specified", eAC);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod,
						"Could not find 'providers' config section in configuration. No providers specified, using default");
			}

			Object oCryptoProvider = null;

			HashMap htProviders = new HashMap();
			if (oProvidersSection != null) {
				try {
					oCryptoProvider = _configManager.getSection(oProvidersSection, "provider");
				}
				catch (ASelectConfigException e) {
					_systemLogger.log(Level.CONFIG, MODULE, sMethod,
							"Could not find a 'provider' config section in config file. No providers specified", e);

					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
				}

				while (oCryptoProvider != null) // for all providers
				{
					String sProviderID = null;
					try {
						sProviderID = _configManager.getParam(oCryptoProvider, "id");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'id' config item found", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					String sCryptoProvider = null;
					try {
						sCryptoProvider = _configManager.getParam(oCryptoProvider, "class");
					}
					catch (ASelectConfigException e) {
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, "No valid 'class' config item found", e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					Provider oProvider = null;
					try {
						oProvider = (Provider) Class.forName(sCryptoProvider).newInstance();
					}
					catch (Exception e) {
						StringBuffer sbError = new StringBuffer(
								"The configured provider is not a valid Provider class: ");
						sbError.append(sCryptoProvider);
						_systemLogger.log(Level.CONFIG, MODULE, sMethod, sCryptoProvider, e);
						throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR, e);
					}

					java.security.Security.addProvider(oProvider);
					htProviders.put(sProviderID, oProvider);
					oCryptoProvider = _configManager.getNextSection(oCryptoProvider);
				}
			}

			// Obtain algorithm for generating/verifying signatures
			readSignatureConfig(oCryptoSection, htProviders);

			// Obtain algorithm for encryption and create a cipher
			readEncryptionConfig(oCryptoSection, htProviders);
			_systemLogger.log(Level.FINE, MODULE, sMethod, "get cipher");
			if (_oCipherProvider != null)
				_cipher = Cipher.getInstance(_sCipherAlgorithm, _oCipherProvider);
			else
				_cipher = Cipher.getInstance(_sCipherAlgorithm);

			// Obtain algorithm for the random generator
			_systemLogger.log(Level.INFO, MODULE, sMethod, "random generator config");
			readRandomGeneratorConfig(oCryptoSection, htProviders);

			try {
				if (_oSecureRandomProvider != null)
					_secureRandom = SecureRandom.getInstance(_sSecureRandomAlgorithm, _oSecureRandomProvider);
				else
					_secureRandom = SecureRandom.getInstance(_sSecureRandomAlgorithm);
				_secureRandom.nextBytes(new byte[64]);		// RH, 20160105, n, let the PRNG seed itself
			}
			catch (Exception e) {
				StringBuffer sbInfo = new StringBuffer("Unable to create random generator with algorithm: ");
				sbInfo.append(_sSecureRandomAlgorithm);
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbInfo.toString());
				throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
			}

			// Get public/private keys from ConfigManager
			_defaultPrivateKey = _configManager.getDefaultPrivateKey();
			_htAuthspSettings = _configManager.getAuthspSettings();

			// Init the storage manager
			_systemLogger.log(Level.INFO, MODULE, sMethod, "init storagemanager");
			_storageManager.init(_configManager.getSection(null, "storagemanager", "id=crypto"), _configManager,
					ASelectSystemLogger.getHandle(), ASelectSAMAgent.getHandle());
			_systemLogger.log(Level.INFO, MODULE, sMethod, "server key");
			try {
				_secretKey = (SecretKey) _storageManager.get("server-session-key");
			}
			catch (Exception e) {
				_systemLogger.log(Level.INFO, MODULE, sMethod, "Generating new A-Select Server key");

				if (_oCipherProvider != null) {
					_secretKey = KeyGenerator.getInstance(_sCipherAlgorithm, _oCipherProvider).generateKey();
				}
				else {
					_secretKey = KeyGenerator.getInstance(_sCipherAlgorithm).generateKey();
				}

				try {
					_storageManager.put("server-session-key", _secretKey);
				}
				catch (ASelectStorageException ee) {
					if (e.getMessage().equals(Errors.ERROR_ASELECT_STORAGE_MAXIMUM_REACHED)) {
						_systemLogger.log(Level.WARNING, MODULE, sMethod, "Maximum server session keys reached");
					}
					throw ee;
				}
			}
			
			// 20130411, Bauke: allow fixed valued key to symmetrically encode/decode data 
			String sKey = ASelectConfigManager.getSimpleParam(oASelect, "encryption_key", false);
			if (Utils.hasValue(sKey)) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using configured encryption key: "+Auxiliary.obfuscate(sKey));
				_encryptionKey =  generate3DESKey(sKey, false /* not stored as base64 */);
			}
		}
		catch (ASelectException eAS) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Could not initialize", eAS);
			throw eAS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "Unable to initialize CryptoEngine", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
		}
	}

	/**
	 * Verify a signature generated by a privileged application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies a signature generated over a block of data by a "privileged application", which is simply an
	 * application acting as an authsp. It is used to verify signatures attached to a "create_tgt" API call. <br>
	 * 
	 * @param sAlias
	 *            The id of the privileged application, which is also the alias under which the application public key
	 *            is stored in the keystore.
	 * @param sData
	 *            The data to be verified
	 * @param sSignature
	 *            The data's signature
	 * @return <code>true</code> if verification was succesful, <code>false</code> otherwise
	 */
	public synchronized boolean verifyPrivilegedSignature(String sAlias, String sData, String sSignature)
	{

		String sMethod = "verifyPrivilegedSignature";
		PublicKey oPublicKey = null;
		boolean bVerified = false;
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			sAlias = sAlias.toLowerCase();
			oPublicKey = _configManager.getPrivilegedPublicKey(sAlias);

			if (oPublicKey == null) {
				_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not find privileged public key with alias "
						+ sAlias);
				bVerified = false;
			}
			else {
				oSignature.initVerify(oPublicKey);
				oSignature.update(sData.getBytes());

				BASE64Decoder xDecoder = new BASE64Decoder();
				byte[] xRawSignature = xDecoder.decodeBuffer(sSignature);

				bVerified = oSignature.verify(xRawSignature);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "could not verify signature for alias: " + sAlias, e);
			bVerified = false;
		}
		return bVerified;
	}

	/**
	 * Verify a signature generated by an authsp. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies a signature generated over a block of data by an authsp. It is typically used to verify the
	 * authenticity of a response from an authsp. <br>
	 * 
	 * @param sAlias
	 *            The id of the authsp, which is also the alias under which the authsp's public key is stored in the
	 *            keystore.
	 * @param sData
	 *            The data to be verified
	 * @param sSignature
	 *            The data's signature
	 * @return <code>true</code> if verification was succesful, <code>false</code> otherwise
	 */
	public synchronized boolean verifySignature(String sAlias, String sData, String sSignature)
	{
		String sMethod = "verifySignature";
		PublicKey oPublicKey = null;
		int iLoop = 0;
		boolean bVerified = false;
//		_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== VS alias="+sAlias + " data="+sData);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== VS alias="+sAlias + " data="+"...");
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== VS _htAuthspSettings=\n"+_htAuthspSettings );

			sAlias = sAlias.toLowerCase();
			while (!bVerified && (iLoop == 0 || oPublicKey != null)) {
				if (iLoop == 0) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Looking for public key with alias " + sAlias);
					oPublicKey = (PublicKey) _htAuthspSettings.get(sAlias + ".public_key");
				}
				else {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Looking for public key with alias " + sAlias + iLoop);
					oPublicKey = (PublicKey) _htAuthspSettings.get(sAlias + iLoop + ".public_key");
				}

				if (oPublicKey == null) {
//					_systemLogger.log(Level.FINE, MODULE, sMethod, "could not find public key with alias " + sAlias);// RH, 20180405, 0
					_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not find public key with alias " + sAlias + 
							(iLoop == 0 ? "" : iLoop));// RH, 20180405, n
					bVerified = false;
				}
				else {
					oSignature.initVerify(oPublicKey);
					oSignature.update(sData.getBytes());
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== VS oSignature="+oSignature.toString() );

					BASE64Decoder xDecoder = new BASE64Decoder();
					byte[] xRawSignature = xDecoder.decodeBuffer(sSignature);

					bVerified = oSignature.verify(xRawSignature);
					_systemLogger.log(Level.FINE, MODULE, sMethod, "==== VS verify success="+bVerified );

					iLoop++;
				}
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "could not verify signature for alias: " + sAlias, e);
			bVerified = false;
		}
		return bVerified;
	}

	/**
	 * Verify a signature generated by a remote cross A-Select Server. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies a signature generated over a block of data by a cross A-Select Server. It is typically used
	 * to verify the authenticity of a response from a remote A-Select Server. <br>
	 * 
	 * @param oPublicKey
	 *            The A-Select Server's public key
	 * @param sData
	 *            The data to be verified
	 * @param sSignature
	 *            The data's signature
	 * @return <code>true</code> if verification was succesful, <code>false</code> otherwise
	 */
	public synchronized boolean verifyCrossASelectSignature(PublicKey oPublicKey, String sData, String sSignature)
	{
		String sMethod = "verifyCrossASelectSignature";
		// PublicKey oPublicKey = null;
		boolean bVerified = false;
		// String sServer = "";
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initVerify(oPublicKey);
			oSignature.update(sData.getBytes());

			BASE64Decoder xDecoder = new BASE64Decoder();
			byte[] xRawSignature = xDecoder.decodeBuffer(sSignature);

			bVerified = oSignature.verify(xRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "could not verify A-Select Server signature.", e);
			bVerified = false;
		}
		return bVerified;
	}

	/**
	 * Verify a signature generated by an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies a signature generated over a block of data by an application. It is used to verify the
	 * authenticity of an application request. <br>
	 * 
	 * @param oPublicKey
	 *            The application's public key
	 * @param sData
	 *            The data to be verified
	 * @param baRawSignature
	 *            The raw ( byte[] ) data's signature
	 * @return <code>true</code> if verification was succesful, <code>false</code> otherwise
	 */
	public boolean verifyApplicationSignature(PublicKey oPublicKey, String sData,  byte[] baRawSignature)
	{
		String sMethod = "verifyApplicationSignature";
		boolean bVerified = false;
//		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== VAS " + baRawSignature); // we don't like bytes in the log
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== VAS ");
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initVerify(oPublicKey);
			oSignature.update(sData.getBytes());

			bVerified = oSignature.verify(baRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not verify application signature", e);
			bVerified = false;
		}
		return bVerified;
	}

	/**
	 * Verify a signature generated by an application. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method verifies a signature generated over a block of data by an application. It is used to verify the
	 * authenticity of an application request. <br>
	 * 
	 * @param oPublicKey
	 *            The application's public key
	 * @param sData
	 *            The data to be verified
	 * @param sSignature
	 *            The data's signature
	 * @return <code>true</code> if verification was succesful, <code>false</code> otherwise
	 */
	public boolean verifyApplicationSignature(PublicKey oPublicKey, String sData, String sSignature)
	{
		String sMethod = "verifyApplicationSignature";
		boolean bVerified = false;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "==== VAS " + sSignature);
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initVerify(oPublicKey);
			oSignature.update(sData.getBytes());

			BASE64Decoder oDecoder = new BASE64Decoder();
			byte[] baRawSignature = oDecoder.decodeBuffer(sSignature);

			bVerified = oSignature.verify(baRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.FINE, MODULE, sMethod, "Could not verify application signature", e);
			bVerified = false;
		}
		return bVerified;
	}

	/**
	 * Generate a signature using the authsp-specific private key. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates a signature over a block of data that is to be sent to an authsp. <br>
	 * <br>
	 * 
	 * @param sAuthsp
	 *            The id of the authsp, or <code>null</code> to use the default signing key.
	 * @param sData
	 *            The data to be signed.
	 * @return The base64 encoded signature
	 */
	public synchronized String generateSignature(String sAuthsp, String sData)
	{
		String sMethod = "CryptoEngine.generateSignature";

		try {
			PrivateKey oPrivateKey = null;

//			_systemLogger.log(Level.FINER, MODULE, sMethod, "sAuthsp="+sAuthsp+" data=["+sData+"]");
			_systemLogger.log(Level.FINER, MODULE, sMethod, "sAuthsp="+sAuthsp+" data=["+"..."+"]");
			if (sAuthsp != null) {
				sAuthsp = sAuthsp.toLowerCase();

				oPrivateKey = (PrivateKey)_htAuthspSettings.get(sAuthsp + ".specific_private_key");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Specific private key " + (oPrivateKey == null ? "NOT" : "") + " found for: "+ sAuthsp);
			}
			if (oPrivateKey == null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using default private key");
				oPrivateKey = _defaultPrivateKey;
			}

			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			oSignature.initSign(oPrivateKey);
			oSignature.update(sData.getBytes());
			byte[] xRawSignature = oSignature.sign();

			BASE64Encoder xBase64Enc = new BASE64Encoder();
			return xBase64Enc.encode(xRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not compute signature", e);
		}
		return null;
	}

	/**
	 * Generate a signature using the authsp-specific private key and optional signature algorithm. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates a signature over a block of data that is to be sent to an authsp. <br>
	 * <br>
	 * 
	 * @param sAuthsp
	 *            The id of the authsp, or <code>null</code> to use the default signing key.
	 * @param bData
	 *            The data to be signed.
	 * @param signAlg
	 *            Optional signature algoritn
	 * @return The byte[] signature
	 */
	public synchronized byte[] generateSignature(String sAuthsp, byte[] bData, String signAlg)
	{
		String sMethod = "CryptoEngine.generateSignature";

		try {
			PrivateKey oPrivateKey = null;

			_systemLogger.log(Level.FINER, MODULE, sMethod, "sAuthsp="+sAuthsp);
			if (sAuthsp != null) {
				sAuthsp = sAuthsp.toLowerCase();

				oPrivateKey = (PrivateKey)_htAuthspSettings.get(sAuthsp + ".specific_private_key");
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Specific private key " + (oPrivateKey == null ? "NOT" : "") + " found for: "+ sAuthsp);
			}
			if (oPrivateKey == null) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Using default private key");
				oPrivateKey = _defaultPrivateKey;
			}

			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(signAlg != null ? signAlg : _sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(signAlg != null ? signAlg : _sSignatureAlgorithm);

			oSignature.initSign(oPrivateKey);
			oSignature.update(bData);
			byte[] xRawSignature = oSignature.sign();

			return xRawSignature;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not compute signature", e);
		}
		return null;
	}

	
	/**
	 * RSA ecncrypt data for the (remote) authsp. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method RSA encrypts  a block of data using the (remote) authsp public key<br>
	 * 
	 * @param sAlias
	 *            The id of the authsp, which is also the alias under which the authsp's public key is stored in the
	 *            keystore.
	 * @param sData
	 *            The data to be encrypted
	 * @param sAlgorithm
	 *            Which Algorithm to use, e.g. "RSA" or "RSA/ECB/PKCS1Padding"
	 * @return <code>byte[]</code> if encryption was successful, <code>null</code> otherwise
	 */
	public synchronized byte[] RSAEncrypt(String sAlias, byte[] sData, String sAlgorithm)
	{
		String sMethod = "RSAEncrypt";
		PublicKey oPublicKey = null;
	    byte[] cipherText = null;
		if (sAlgorithm == null) {	// defaults to RSA
//			sAlgorithm = "RSA";	// RH, 20210318, o
			// now defaults to RSA/ECB/PKCS1Padding
			sAlgorithm = "RSA/ECB/PKCS1Padding";	// RH, 20210318, n
		}
		try {
			final Cipher cipher = Cipher.getInstance(sAlgorithm);
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== ENCRYPT alias="+sAlias + " data="+Arrays.toString(sData));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== ENCRYPT alias="+sAlias + " data="+"...");
				sAlias = sAlias.toLowerCase();
				oPublicKey = (PublicKey) _htAuthspSettings.get(sAlias + ".public_key");
	
				if (oPublicKey == null) {
					_systemLogger.log(Level.FINE, MODULE, sMethod, "could not find public key with alias " + sAlias);
				}
				else {
					// encrypt the plain text using the public key
					cipher.init(Cipher.ENCRYPT_MODE, oPublicKey);
					cipherText = cipher.doFinal(sData);
				}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not encrypt data for alias: " + sAlias, e);
		}
		return cipherText;
	}

	/**
	 * RSA ecncrypt data forwith pubKey <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method RSA encrypts  a block of data using the (remote) authsp public key<br>
	 * 
	 * @param pubKey
	 *            The public key to use for encryption
	 *            keystore.
	 * @param sData
	 *            The data to be encrypted
	 * @param sAlgorithm
	 *            Which Algorithm to use, e.g. "RSA" or "RSA/ECB/PKCS1Padding"
	 * @return <code>byte[]</code> if encryption was successful, <code>null</code> otherwise
	 */
	public synchronized byte[] RSAEncrypt(PublicKey oPublicKey, byte[] sData, String sAlgorithm)
	{
		String sMethod = "RSAEncrypt";
		
	    byte[] cipherText = null;
		if (sAlgorithm == null) {	// defaults to RSA
			sAlgorithm = "RSA";
		}
		try {
			final Cipher cipher = Cipher.getInstance(sAlgorithm);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "==== ENCRYPT pubKey="+oPublicKey + ", alg=" +sAlgorithm + ", data="+"...");
	
				if (oPublicKey != null) {
					// encrypt the plain text using the public key
					cipher.init(Cipher.ENCRYPT_MODE, oPublicKey);
					cipherText = cipher.doFinal(sData);
				}
				else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Provided public key == null");
				}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not encrypt data with pubKey: " + oPublicKey, e);
		}
		return cipherText;
	}

	/**
	 * Generate a 3DES (symmetric) encrypted string using (remote) public key <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates a 3DES encrypted string over a block of data <br>
	 * <br>
	 * 
	 * 
	 * @param sData
	 *            The data to be signed.
	 * @param sKey
	 *            secret key as base64 string
	 * @return The base64 3des encrypted string
	 * @throws ASelectException 
	 */
	public synchronized String generate3DES(String sData, String sKeyBase64) throws ASelectException
	{
		String sMethod = "CryptoEngine.generate3DES";

		try {
			SecretKey key = _secretKey;	// the default;
			if (sKeyBase64 != null) {  // generate a new one
				key = generate3DESKey(sKeyBase64, true);	
			}
			
			_cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[]encrypted = _cipher.doFinal(sData.getBytes("UTF-8"));
			BASE64Encoder b64enc = new BASE64Encoder();
			String sBase64rep = b64enc.encode(encrypted);
			return sBase64rep;
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not encrypt", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Generate a new 3DES key based on it's string representation.
	 * 
	 * @param sKeyValue
	 *            the base64 key
	 * @return the generated secret key
	 * @throws ASelectException
	 */
	public SecretKey generate3DESKey(String sKeyValue, boolean isBase64)
	throws ASelectException
	{
		String sMethod = "generate3DESKey";
		DESedeKeySpec keyspec = null;
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			if (isBase64)
				keyspec = new DESedeKeySpec(b64dec.decodeBuffer(sKeyValue));
			else
				keyspec = new DESedeKeySpec(sKeyValue.getBytes());

			SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
			return keyfactory.generateSecret(keyspec);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "could not encrypt", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Encrypt a TGT using the configured encryption algorithm (cipher). <br>
	 * The encryption key may possibly be generated every time the server is started.
	 * 
	 * @param baData
	 *            A byte array representing the TGT
	 * @return A String representation of the encrypted TGT
	 * @throws ASelectException
	 *             If encrypting fails.
	 */
	public synchronized String encryptTGT(byte[] baData)
	throws ASelectException
	{
		return encryptUsingKey(baData, _secretKey);
	}
	
	/**
	 * Encrypt data symmetrically.
	 * The encryption key is taken from the configuration file
	 * 
	 * @param baData - the data to be encrypted
	 * @return the encrypted result
	 * @throws ASelectException
	 */
	// 20130411, Bauke: allow fixed valued key to symmetrically encode/decode data 
	public synchronized String encryptData(byte[] baData)
	throws ASelectException
	{
		return encryptUsingKey(baData, _encryptionKey);
	}

	private synchronized String encryptUsingKey(byte[] baData, SecretKey secretKey)
	throws ASelectException
	{
		String sMethod = "encryptUsingKey";
		BASE64Encoder b64enc = new BASE64Encoder();
		if (secretKey == null)
			secretKey = _secretKey;  // NOTE: this key is generated every time the server starts, unless database storage is used
		
/* TEST CODE
 * 		// Convert key to a string
		String stringKey = b64enc.encode(secretKey.getEncoded());
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "stringKey="+stringKey);
		// And back to key again
		BASE64Decoder b64dec = new BASE64Decoder();	
	    byte[] encodedKey = b64dec.decodeBuffer(stringKey);
	    SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DESede");	    
	    secretKey = originalKey;  // Does it work?
*/	
		try {
			_cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] baEncryped = _cipher.doFinal(baData);
			String sBase64rep = b64enc.encode(baEncryped);
			//_systemLogger.log(Level.FINEST, MODULE, sMethod, "encrypted["+sBase64rep+"]");
			return sBase64rep.replace('+', '-').replace('=', '_').replace('/', '*');	// RH, 20100805, n, '/' is not nice for URLs
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not encrypt, bad encryption key?");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Decrypt a TGT using the configured encryption algorithm (cipher). <br>
	 * The encryption key may possibly be generated every time the server is started.
	 * 
	 * @param sEncTgt
	 *            A String representation of the encrypted TGT
	 * @return A byte array containing the decrypted TGT
	 * @throws ASelectException
	 *             If decrypting fails.
	 */
	public synchronized byte[] decryptTGT(String sEncTgt)
	throws ASelectException
	{
		return decryptUsingKey(sEncTgt, _secretKey);
	}

	/**
	 * Decrypt data symmetrically.
	 * The encryption key is taken from the configuration file
	 * 
	 * @param sEncTgt - the encrypted data
	 * @return the decrypted result as a byte array
	 * @throws ASelectException
	 */
	// 20130411, Bauke: allow fixed valued key to symmetrically encode/decode data 
	public synchronized byte[] decryptData(String sEncTgt)
	throws ASelectException
	{
		return decryptUsingKey(sEncTgt, _encryptionKey);
	}

	private synchronized byte[] decryptUsingKey(String sEncodedText, SecretKey secretKey)
	throws ASelectException
	{
		String sMethod = "decryptUsingKey";
		if (secretKey == null)
			secretKey = _secretKey;  // NOTE: this key is generated every time the server starts, unless database storage is used

		try {
			BASE64Decoder b64dec = new BASE64Decoder();	
			sEncodedText = sEncodedText.replace('_', '=').replace('-', '+').replace('*', '/');	// RH, 20100805, n, '/' is not nice for URLs
			
			//_systemLogger.log(Level.FINEST, MODULE, sMethod, "decrypting["+sEncodedText+"]");
			byte[] baData = b64dec.decodeBuffer(sEncodedText);
			_cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return _cipher.doFinal(baData);
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not decrypt, bad decryption key or data?");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}

	/**
	 * Retrieve the optional configured AuthSP specific Certificate ID. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Retrieve the AuthSP specific Certificate ID if it is configured, otherwise the default certificate ID is
	 * returned. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>sAuthsp != null</code> <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * - <br>
	 * 
	 * @param sAuthsp
	 *            The AuthSP name.
	 * @return The certificate ID of the AuthSP.
	 */
	public String getAuthSPSpecificCertId(String sAuthsp)
	{
		sAuthsp = sAuthsp.toLowerCase();

		String sCertId = (String) _htAuthspSettings.get(sAuthsp + ".specific_private_key.cert_id");

		if (sCertId == null)
			return _configManager.getDefaultCertId();

		return sCertId;
	}

	/**
	 * Stops the CryptoEngine and performs cleanup. <br>
	 * <b>Postconditions:</b> <br>
	 * Do not use the CryptoEngine after calling this method.
	 */
	public void stop()
	{
		if (_bIsActive) {
			_systemLogger.log(Level.WARNING, MODULE, "stop", "Stop Crypto");
			_bIsActive = false;
			_storageManager.destroy();
			_storageManager = null;
		}
	}

	/**
	 * Generate random bytes. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates n random bytes, where n is the size of the passed byte array. It uses the configured
	 * SecureRandom object to generate this data. <br>
	 * 
	 * @param baRandom
	 *            A byte array that will hold the random bytes upon completion of this method
	 */
	public static void nextRandomBytes(byte[] baRandom)
	{
		getHandle()._secureRandom.nextBytes(baRandom);
	}

	/**
	 * Generate random long number. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates a long random number, It uses the configured
	 * SecureRandom object to generate this data. <br>
	 * 
	 */
	public static long nextRandomLong()
	{
		return getHandle()._secureRandom.nextLong();
	}

	/**
	 * Generate random integer number. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method generates a integer random number, It uses the configured
	 * SecureRandom object to generate this data. <br>
	 * 
	 */
	public static int nextRandomInt()
	{
		return getHandle()._secureRandom.nextInt();
	}
	
	
	/**
	 * Read signature config.
	 * 
	 * @param oCryptoSection
	 *            the o crypto section
	 * @param htProviders
	 *            the ht providers
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void readSignatureConfig(Object oCryptoSection, HashMap htProviders)
	throws ASelectException
	{
		String sMethod = "readSignatureConfig";
		String sProvider = null;

		Object oSection = null;
		try {
			oSection = _configManager.getSection(oCryptoSection, "signature_algorithm");
		}
		catch (ASelectConfigException e) {
			oSection = null;
			_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

			_systemLogger
					.log(
							Level.CONFIG,
							MODULE,
							sMethod,
							"Could not retrieve 'signature_algorithm' config section in crypto config section. Using default algorithm and provider.");
		}

		if (oSection != null) {
			// retrieve algorithm
			try {
				_sSignatureAlgorithm = _configManager.getParam(oSection, "algorithm");
			}
			catch (ASelectConfigException e) {
				_sSignatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

				StringBuffer sbConfig = new StringBuffer(
						"Could not retrieve 'algorithm' config parameter in crypto config section. Using default algorithm: ");
				sbConfig.append(_sSignatureAlgorithm);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}
		}

		// retrieve provider
		if (oSection != null) {
			try {
				sProvider = _configManager.getParam(oSection, "provider");
			}
			catch (ASelectConfigException e) {
				sProvider = null;

				_systemLogger
						.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve 'provider' config section in crypto config section. Using default provider.");
			}

			if (sProvider != null) {
				if (!htProviders.containsKey(sProvider)) {
					StringBuffer sbError = new StringBuffer("Unknown 'provider': ");
					sbError.append(sProvider);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				_oSignatureProvider = (Provider) htProviders.get(sProvider);

				StringBuffer sbInfo = new StringBuffer("Using provider '");
				sbInfo.append(sProvider);
				sbInfo.append("' for signature generation");
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			}
		}
	}

	/**
	 * Read encryption config.
	 * 
	 * @param oCryptoSection
	 *            the o crypto section
	 * @param htProviders
	 *            the ht providers
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void readEncryptionConfig(Object oCryptoSection, HashMap htProviders)
	throws ASelectException
	{
		String sMethod = "readEncryptionConfig";
		String sProvider = null;

		Object oSection = null;
		try {
			oSection = _configManager.getSection(oCryptoSection, "encryption_algorithm");
		}
		catch (ASelectConfigException e) {
			oSection = null;
			_sCipherAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, 
				"Could not retrieve 'encryption_algorithm' config section in crypto config section. Using default algorithm and provider.");
		}

		if (oSection != null) {
			// retrieve algorithm
			try {
				_sCipherAlgorithm = _configManager.getParam(oSection, "algorithm");
			}
			catch (ASelectConfigException e) {
				_sCipherAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM;
				StringBuffer sbConfig = new StringBuffer(
						"Could not retrieve 'encryption_algorithm' config parameter in crypto config section. Using default algorithm: ");
				sbConfig.append(_sCipherAlgorithm);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}
		}

		if (oSection != null) { // retrieve provider
			try {
				sProvider = _configManager.getParam(oSection, "provider");
			}
			catch (ASelectConfigException e) {
				sProvider = null;
				_systemLogger
						.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve 'provider' config parameter in crypto config section. Using default provider.");
			}
			_systemLogger.log(Level.FINE, MODULE, sMethod, "provider=" + sProvider);

			if (sProvider != null) {
				if (!htProviders.containsKey(sProvider)) {
					StringBuffer sbError = new StringBuffer("Unknown 'provider': ");
					sbError.append(sProvider);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				_oCipherProvider = (Provider) htProviders.get(sProvider);

				StringBuffer sbInfo = new StringBuffer("Using provider '");
				sbInfo.append(sProvider);
				sbInfo.append("' for encryption");
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			}
		}
		_systemLogger.log(Level.FINE, MODULE, sMethod, "done");
	}

	/**
	 * Read random generator config.
	 * 
	 * @param oCryptoSection
	 *            the o crypto section
	 * @param htProviders
	 *            the ht providers
	 * @throws ASelectException
	 *             the a select exception
	 */
	private void readRandomGeneratorConfig(Object oCryptoSection, HashMap htProviders)
	throws ASelectException
	{
		String sMethod = "readRandomGeneratorConfig";
		String sProvider = null;

		Object oSection = null;
		try {
			oSection = _configManager.getSection(oCryptoSection, "random_generator_algorithm");
		}
		catch (ASelectConfigException e) {
			oSection = null;
			_sSecureRandomAlgorithm = DEFAULT_RANDOM_ALGORITHM;
			_systemLogger.log(Level.CONFIG, MODULE, sMethod, "Could not retrieve 'random_generator_algorithm' config section in crypto config section. Using default algorithm and provider.");
		}

		if (oSection != null) {
			// retrieve algorithm
			try {
				_sSecureRandomAlgorithm = _configManager.getParam(oSection, "algorithm");
			}
			catch (ASelectConfigException e) {
				_sSecureRandomAlgorithm = DEFAULT_RANDOM_ALGORITHM;

				StringBuffer sbConfig = new StringBuffer(
						"Could not retrieve 'random_generator_algorithm' config parameter in crypto config section. Using default algorithm: ");
				sbConfig.append(_sSecureRandomAlgorithm);
				_systemLogger.log(Level.CONFIG, MODULE, sMethod, sbConfig.toString());
			}
		}

		if (oSection != null) {
			// retrieve provider
			try {
				sProvider = _configManager.getParam(oSection, "provider");
			}
			catch (ASelectConfigException e) {
				sProvider = null;

				_systemLogger
						.log(Level.CONFIG, MODULE, sMethod,
								"Could not retrieve 'provider' config parameter in crypto config section. Using default provider.");
			}

			if (sProvider != null) {
				if (!htProviders.containsKey(sProvider)) {
					StringBuffer sbError = new StringBuffer("Unknown 'provider': ");
					sbError.append(sProvider);
					_systemLogger.log(Level.SEVERE, MODULE, sMethod, sbError.toString());
					throw new ASelectException(Errors.ERROR_ASELECT_INIT_ERROR);
				}
				_oSecureRandomProvider = (Provider) htProviders.get(sProvider);

				StringBuffer sbInfo = new StringBuffer("Using provider '");
				sbInfo.append(sProvider);
				sbInfo.append("' for the random generator.");
				_systemLogger.log(Level.INFO, MODULE, sMethod, sbInfo.toString());
			}
		}
	}

	/**
	 * Sign a request. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method is used in a cross A-Select environment to Generate a Signature for a request to a remote A-Select
	 * server. <br>
	 * <br>
	 * <i> Note: All request parameters are first sorted in the natural ordening of the parameter names. The signature
	 * is created over all appended parameter values in this order. </i> <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * - <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * <code>htRequest</code> should contain all parameters that are send to the remote A-Select Server. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * <code>htRequest</code> will contain an additional "signature" parameter containg the generated signature of the
	 * request. <br>
	 * 
	 * @param htRequest
	 *            The request that should be signed.
	 * @throws ASelectException
	 *             If signing fails.
	 */
	public void signRequest(HashMap htRequest)
	throws ASelectException
	{
		try {
			Signature oSignature = null;
			if (_oSignatureProvider != null)
				oSignature = Signature.getInstance(_sSignatureAlgorithm, _oSignatureProvider);
			else
				oSignature = Signature.getInstance(_sSignatureAlgorithm);

			StringBuffer sbCreateFrom = new StringBuffer();
			TreeSet sortedSet = new TreeSet(htRequest.keySet());
			for (Iterator i = sortedSet.iterator(); i.hasNext();) {
				String sKey = (String) i.next();
				if (!sKey.equals("request"))
					sbCreateFrom.append(htRequest.get(sKey));
			}

			oSignature.initSign(_configManager.getDefaultPrivateKey());
			oSignature.update(sbCreateFrom.toString().getBytes());
			byte[] baRawSignature = oSignature.sign();
			BASE64Encoder oBase64Enc = new BASE64Encoder();
			String sRawSignature = oBase64Enc.encode(baRawSignature);
			htRequest.put("signature", sRawSignature);
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, "signRequest", "Could not sign request", e);
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR);
		}
	}
	
	
	
}
