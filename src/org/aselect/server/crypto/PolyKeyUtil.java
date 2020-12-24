/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" example package.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 * adapted for siam: RH
 */

package org.aselect.server.crypto;


import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Map;
import java.util.logging.Level;

import javax.crypto.Cipher;

import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;

import nl.logius.resource.pp.crypto.CMS;
import nl.logius.resource.pp.key.DecryptKey;
import nl.logius.resource.pp.key.EncryptedVerifiers;
import nl.logius.resource.pp.key.IdentityDecryptKey;
import nl.logius.resource.pp.key.PseudonymClosingKey;
import nl.logius.resource.pp.key.PseudonymDecryptKey;

public class PolyKeyUtil {
	
	private final String MODULE = "PolyKeyUtil";
	
	private IdentityDecryptKey decryptKey;
	private EncryptedVerifiers verifiers;
	private EncryptedVerifiers pVerifiers;
	private PseudonymDecryptKey pDecryptKey;
	private PseudonymClosingKey pClosingKey;
	
	private PrivateKey  privatekey;
	
	private ASelectConfigManager _configManager = ASelectConfigManager.getHandle();
	private ASelectSystemLogger _systemLogger = ASelectSystemLogger.getHandle();

	private PolyKeyUtil() {	// hide this contructor
		
	}

	public PolyKeyUtil(String idkey_location, String identity_point, 
			String pdkey_location, String pckey_location, String pseudonym_point)
	{
		this(idkey_location, identity_point, 
			pdkey_location, pckey_location, pseudonym_point, null);
	}

//	public PolyKeyUtil(String idkey_location, String identity_point, 
//			String pdkey_location, String pckey_location, String pseudonym_point)
	public PolyKeyUtil(String idkey_location, String identity_point, 
			String pdkey_location, String pckey_location, String pseudonym_point, PrivateKey  privatekey)	// RH, 20201218, n
	{
		// RH, 20201218, sn
		if (privatekey != null) {
			setPrivatekey(privatekey);
		}
		// RH, 20201218, en
		fixKeyLength();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (idkey_location != null && idkey_location.length() > 0) { getIdentityKeys(idkey_location, identity_point); };
        if (pdkey_location != null && pckey_location != null && pdkey_location.length() > 0 && pckey_location.length() > 0) {getPseudoKeys(pdkey_location, pckey_location, pseudonym_point);};
	}
	
	private void getIdentityKeys(String id_key_location, String identity_point)
	{
		String sMethod = "getIdentityKeys";

        // Convert P7 key to PEM
        try (final InputStream is = new FileInputStream(id_key_location)) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Inputstream identitykey openend");	// RH, 20190805, n
            String identityKeyPem = CMS.read(getPrivateKey(), is);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Identitykey read from file");	// RH, 20190805, n
            // Convert PEM to IdentityDecryptKey
            decryptKey = DecryptKey.fromPem(identityKeyPem, IdentityDecryptKey.class);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Identitykey parsed from pem");	// RH, 20190805, n
            // Derive verifier (for signature verifying) from key
            verifiers = identity_point != null ? decryptKey.toVerifiers(identity_point) : null;
			_systemLogger.log(Level.FINEST, MODULE, sMethod, (identity_point != null) ? "Verifier created" : "No identity point supplied for verifier");	// RH, 20190805, n
        }        
        catch (Exception e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load identityKey");	// RH, 20190805, o
        	//	try to get some more info
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load identityKey, " + e.getMessage());	// RH, 20190805, n
		}
	}
	
	private void getPseudoKeys(String pdkey_location, String pckey_location, String pseudonym_point)
	{
		String sMethod = "getPseudoKeys";

		try (final InputStream is = new FileInputStream(pdkey_location)) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Inputstream pseudoKey openend");	// RH, 20190805, n
        	String pseudoKeyPem = CMS.read(getPrivateKey(), is);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "PseudoKey read from file");	// RH, 20190805, n
            // Convert PEM to IdentityDecryptKey
        	pDecryptKey = DecryptKey.fromPem(pseudoKeyPem, PseudonymDecryptKey.class);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "PseudoKey parsed from pem");	// RH, 20190805, n
            // Derive verifier (for signature verifying) from key
            pVerifiers = pseudonym_point != null ? pDecryptKey.toVerifiers(pseudonym_point) : null;
			_systemLogger.log(Level.FINEST, MODULE, sMethod, (pseudonym_point != null) ? "Verifier created" : "No pseudonym point supplied for verifier");	// RH, 20190805, n
        }        
        catch (Exception e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load pseudoKey");	// RH, 20190805, o
//        	try to get some more info
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load pseudoKey, " + e.getMessage());	// RH, 20190805, n
		}
        
		try (final InputStream is = new FileInputStream(pckey_location)) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Inputstream closingKey openend");	// RH, 20190805, n
        	String pseudoClosingKeyPem = CMS.read(getPrivateKey(), is);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "ClosingKey read from file");	// RH, 20190805, n
            // Convert PEM to IdentityDecryptKey
        	pClosingKey = DecryptKey.fromPem(pseudoClosingKeyPem, PseudonymClosingKey.class);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "ClosingKey parsed from pem");	// RH, 20190805, n
        }        
        catch (Exception e) {
//			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load pseudoClosingKey");	// RH, 20190805, o
        	//	try to get some more info
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Could not load pseudoClosingKey, " + e.getMessage());	// RH, 20190805, n
		}
	}
	
	private PrivateKey getPrivateKey() throws Exception {
		// RH, 20201218, sn
		if (getPrivatekey() != null) {
			return getPrivatekey();
		} else {
			return _configManager.getDefaultPrivateKey();
		}
		// RH, 20201218, en
//		return _configManager.getDefaultPrivateKey();	// RH, 20201218, o
        
    }
		
	public IdentityDecryptKey getDecryptKey()
	{
		return decryptKey;
	}
	
	public EncryptedVerifiers getVerifiers()
	{
		return verifiers;
	}
	
	public EncryptedVerifiers getPVerifiers()
	{
		return pVerifiers;
	}
	
	public PseudonymDecryptKey getPDecryptKey()
	{
		return pDecryptKey;
	}
	
	public PseudonymClosingKey getPClosingKey()
	{
		return pClosingKey;
	}
	
	public static void fixKeyLength() {
	    String errorString = "Failed manually overriding key-length permissions.";
	    int newMaxKeyLength;
	    try {
	        if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
	            Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
	            Constructor con = c.getDeclaredConstructor();
	            con.setAccessible(true);
	            Object allPermissionCollection = con.newInstance();
	            Field f = c.getDeclaredField("all_allowed");
	            f.setAccessible(true);
	            f.setBoolean(allPermissionCollection, true);

	            c = Class.forName("javax.crypto.CryptoPermissions");
	            con = c.getDeclaredConstructor();
	            con.setAccessible(true);
	            Object allPermissions = con.newInstance();
	            f = c.getDeclaredField("perms");
	            f.setAccessible(true);
	            ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

	            c = Class.forName("javax.crypto.JceSecurityManager");
	            f = c.getDeclaredField("defaultPolicy");
	            f.setAccessible(true);
	            Field mf = Field.class.getDeclaredField("modifiers");
	            mf.setAccessible(true);
	            mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
	            f.set(null, allPermissions);

	            newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
	        }
	    } catch (Exception e) {
	        throw new RuntimeException(errorString, e);
	    }
	    if (newMaxKeyLength < 256)
	        throw new RuntimeException(errorString); // hack failed
	}

	/**
	 * @return the privatekey
	 */
	public synchronized PrivateKey getPrivatekey() {
		return privatekey;
	}

	/**
	 * @param privatekey the privatekey to set
	 */
	public synchronized void setPrivatekey(PrivateKey privatekey) {
		this.privatekey = privatekey;
	}

}
