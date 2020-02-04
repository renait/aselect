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
 *
 * Auxiliary static convenience methods assisting simple crypto needs
 * @author RH - www.anoigo.nl
 * 
 */
package org.aselect.system.utils.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.aselect.system.logging.ISystemLogger;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Utils;

public  final class Auxiliary
{	
	private final static String MODULE = "Auxiliary";

	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final int DEFAULT_PBKDF2_KEYLENGTH = 256;	// bits


//	private static final String DEFAULT_DIGEST_ALG = "SHA-256";	// RH, 20160510, o
//	private static final String DEFAULT_DIGEST_ALG = "RANDOM";	// RH, 20160510, n, 	// RH, 20170724, o
	private static final String DEFAULT_DIGEST_ALG = "BLANK";	// RH, 20170724, n
	private static final String PROPERTY_DEFAULT_DIGEST_ALG = "aselect.default.digest.alg";
	private static final String[] ALGS = { "BLANK", "NONE", "RANDOM", "SHA-256" , "SHA-384" , "SHA-512" };
	private static final List<String> ALLOWED_DIGEST_ALGS = Arrays.asList(ALGS);

	private static String DIGEST_ALG = null;
	// in the end we want REGS and KEYS to be retrieved from some external source
	private static final String[] DEFAULT_REGS = { "^([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})$", "^([0-9]{9})$"};	// anything resembling a BSN
	public static List<Pattern> REGEX_PATTERNS =  new ArrayList<Pattern>();

	private static final String[] DEFAULT_KEYS = { "uid", "Uid", "UID", "uID", "bsn", "Bsn", "BSN", "obouid", "user_id" , "sel_uid", "userId", "user_Id", ""
			+ "burgerservicenummer", "patientnummer", "Burgerservicenummer", "Patientnummer",
		"name_id", "Name_ID", "NAME_ID", "Name_id", "authid", "Authid", "AuthId", "AuthID",
		"password", "pw", "passwd", "shared_secret", "secret", "cn", "CN",
	 	"full_dn", "mail", "email", "contents", "Authorization" };
	public static final List<String> BANNED_KEYS = Arrays.asList(DEFAULT_KEYS);
	private static SecureRandom sr = null;
	private static  byte bytes[] = new byte[20];
//	private static final Map<String, String> digestedMap = new HashMap<String, String>();
//	private static final Map<String, String> digestedMap = new ConcurrentHashMap<String, String>();	// RH, 20180710, o
	private static Map<String, String> digestedMap = null;	// RH, 20180710, n
//	private static final ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(2);	// RH, 20180710, o
	private static ScheduledExecutorService scheduledThreadPool = null;	// RH, 20180710, n
	
	static {
		try {
			DIGEST_ALG = System.getProperty(PROPERTY_DEFAULT_DIGEST_ALG);
			if (DIGEST_ALG == null || !ALLOWED_DIGEST_ALGS.contains(DIGEST_ALG )) {
				DIGEST_ALG = DEFAULT_DIGEST_ALG;
			}
			// RH, 20180710. so
//			if (DEFAULT_DIGEST_ALG.equals(DIGEST_ALG)) {
//				scheduledThreadPool.scheduleAtFixedRate(new Auxiliary.CleanupDigestMap(), 0, 24,
//			            TimeUnit.HOURS);
//			}
			// RH, 20180710. so
		} catch (Exception se) {
			System.err.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
					": " + Thread.currentThread().getName() + ": " + "Exception at Auxiliary static initializer: " + se.getMessage());
			DIGEST_ALG = DEFAULT_DIGEST_ALG;
		}
	}

	static {
		for (int i=0; i<DEFAULT_REGS.length; i++) {
			Pattern pattern = Pattern.compile(DEFAULT_REGS[i]);
			REGEX_PATTERNS.add(pattern);
		}
		
	}
	

	static {
		try {
			sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
			sr.nextBytes(bytes);	// calls setSeed
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			DIGEST_ALG = DEFAULT_DIGEST_ALG;
		}
		catch (NoSuchProviderException e) {
			e.printStackTrace();
			DIGEST_ALG = DEFAULT_DIGEST_ALG;
		}
		
	}

	private static Map<String, String> getDigestedMapInstane() {	// lazy
		if (digestedMap == null) {
			digestedMap = new ConcurrentHashMap<String, String>();
			scheduledThreadPool = Executors.newScheduledThreadPool(2);
			scheduledThreadPool.scheduleAtFixedRate(new Auxiliary.CleanupDigestMap(), 0, 24,
		            TimeUnit.HOURS);	// only cleanup when there is a digestedMap
		}
		return digestedMap;
	}
	
	private Auxiliary() {	// hide contructor
		
	}
	
	/**
	 * 
	 * @param original
	 * @return
	 */
	public static String obfuscate(String original) {
		return obfuscate(original, null);
	}	

	/**
	 * 
	 * @param original
	 * @param patterns
	 * @return
	 */
	public static String obfuscate(String original, List<Pattern> patterns) {
		String obfuscated = original;
		if (original != null) {
			if ( patterns != null ) {
				StringBuffer sb = new StringBuffer(original);
				for (Pattern p : patterns) {
					Matcher matcher = p.matcher(sb);
					while (matcher.find()) {
						String match = matcher.group(1);
						int sAddress = sb.indexOf(match, matcher.start());
						sb.replace(sAddress, sAddress + match.length(), base64Digest(match));
					}
				}
				obfuscated = sb.toString();
			} else {
				obfuscated = base64Digest(original);
			}
		}
		return obfuscated;
	}
	
	/**
	 * 
	 * @param o object to be deep cloned
	 * @return deep cloned copy of o
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private static Serializable serialize(Serializable o) throws IOException, ClassNotFoundException {
   		Serializable s = null;
   		if (o != null) {
			PipedOutputStream outstr = new PipedOutputStream();
			// maybe we can connect the input tot the output later, after estimating the objectsize so we will be able to estimate the size of the buffer needed
	
	        PipedInputStream instr = new PipedInputStream(outstr, 0xFFFFF);
	               
			ObjectOutputStream out = new ObjectOutputStream(outstr);
	//		ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(outstr, 0x00FFFFF));
	        BufferedInputStream bin = new BufferedInputStream(instr);
			// we must be sure the buffer is big enough to hold our object, otherwise the write will stall
	//       BufferedInputStream bin = new BufferedInputStream(instr, 0x00FFFFF);	// this is expensive
	       final ObjectInputStream in = new ObjectInputStream(bin);
	        out.writeObject(o);
	        out.flush();
	
	        
			s = (Serializable) in.readObject();
	
	        out.close();
	        in.close();
   		}
		return s;
	}

	
	
	/**
	 * 
	 * @param m
	 * @return a reference to the original Map, Map has been obfuscated ( and so probably modified )
	 */
	private static Map obf(Map m) {
		if (m != null) {
			for (String k : BANNED_KEYS) {
				if (m.containsKey(k)) {
					m.put(k, base64Digest( String.valueOf(m.get(k)) ));
				}
			}
			Collection c = m.values();
			for (Object o : c) {
				if ( o instanceof Map) {
					obf((Map)o);
				} else if (o instanceof List) {
					obf( (List) o);
				}
			}
		}
		return m;
	}

	private static List obf(List m) {
		if (m != null) {
			for (Object o : m) {
				if (o instanceof String) {
					m.set(m.indexOf(o), obfuscate( String.valueOf(o) ));
				} else if (o instanceof Map) {
					m.set(m.indexOf(o), (Map) obf( (Map) o ));
				} else if (o instanceof List) {
					m.set(m.indexOf(o), (List) obf( (List) o ));
				}
			}
		}
		return m;
	}

/**
 * 	
 * @param original
 * @return		
 */
	public static Object obfuscate(Object original) {
		if ( original == null ) {
			return null;
		} else 	if (original instanceof Map) {
			return obfuscate((Map) original);
		} else 	if (original instanceof String) {
			return obfuscate((String) original);
		} else 	if (original instanceof List) {
			return obfuscate((List) original);
		} else 	{
			// Gives way to much cluttering of the output log
			// For now we disable the messages
//			System.err.println("WARNING, don't know how to obfuscate this object:" + original.toString());	// RH, 20170331, o
			return original;	// 	we would like to inform but have no logger
		}
	}

	
	/**
	 * 
	 * @param original
	 * @return an obfuscated copy of the original Map
	 */
//	public static Map obfuscate(Map original) {
	private static Map obfuscate(Map original) {
		
		Map obfuscated = null;
		if (original != null) {
			if ("BLANK".equals(DIGEST_ALG)) {
				obfuscated = new HashMap();	// return empty Map
			} else 	if (!"NONE".equals(DIGEST_ALG)) {	// obfuscating is expensive, so be sure you have to.
		//		Map obfuscated = new HashMap();
		//		obfuscated.putAll(original);	// no deep clone
	//			obfuscated = (Map) SerializationUtils.clone((Serializable)original);	// Does deep clone, works but needs commons-lang
				try {
					obfuscated = (Map) serialize((Serializable)original);	// Does deep clone
					obfuscated = obf(obfuscated);
				}
				catch (IOException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
				}
				catch (ClassNotFoundException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
				}
			} else {
				obfuscated = original;
			}
		}
		return obfuscated;
	}
	
//	public static List obfuscate(List original) {
	private static List obfuscate(List original) {
		
		List obfuscated = null;
		if (original != null) {
			if ("BLANK".equals(DIGEST_ALG)) {
				obfuscated = new ArrayList();	// return empty List
			} else 	if (!"NONE".equals(DIGEST_ALG)) {	// obfuscating is expensive, so be sure you have to.
		//		Map obfuscated = new HashMap();
		//		obfuscated.putAll(original);	// no deep clone
	//			obfuscated = (Map) SerializationUtils.clone((Serializable)original);	// Does deep clone, works but needs commons-lang
				try {
					obfuscated = (List) serialize((Serializable)original);	// Does deep clone
					obfuscated = obf(obfuscated);
				}
				catch (IOException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
				}
				catch (ClassNotFoundException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
				}
			} else {
				obfuscated = original;
			}
		}
		return obfuscated;
	}

	
	/**
	 * @param plaintext	plain text input to be digested ( using current digest algorithm DIGEST_ALG )
	 * @return base64 coded digest string
	 */
//	public static String base64Digest(String plaintext) {
	private static String base64Digest(String plaintext) {
		return base64Digest(plaintext, DIGEST_ALG);
	}
	
	/**
	 * @param plaintext	plain text input to be digested
	 * @param algorithm one of BLANK, NONE, SHA-256, SHA-384, SHA-512
	 * @return base64 coded digest string
	 */
//	public static String base64Digest(String plaintext, String algorithm) {
	private static String base64Digest(String plaintext, String algorithm) {
		String digested = null;
		if ( plaintext != null ) {
			if ("BLANK".equalsIgnoreCase(algorithm)) {
				digested = "{" +algorithm + "}{"+"}";
			} else	if ("NONE".equalsIgnoreCase(algorithm)) {
//				digested = "{" +algorithm + "}{" + plaintext + "}";	// RH, 20170413, o
				digested = plaintext;	// RH, 20170413, n,  NONE does really nothing
			} else if ("RANDOM".equalsIgnoreCase(algorithm)) {
//		        sr.nextBytes(bytes);
//		        digested = "{" +algorithm + "}{" + Base64Codec.encode(bytes) + "}";
		        digested = "{" +algorithm + "}{" + getRandom(plaintext) + "}";
			} else {
				MessageDigest md;
				try {
					md = MessageDigest.getInstance(algorithm);
			        md.update(plaintext.getBytes("UTF-8"));
			        byte byteData[] = md.digest();
			        digested = "{" +algorithm + "}{" + Base64Codec.encode(byteData) + "}";
				}
				catch (NoSuchAlgorithmException e) {
					digested = null;
					e.printStackTrace();
				}
				catch (UnsupportedEncodingException e) {
					digested = null;
					e.printStackTrace();
				}
			}
		}
		return digested;
	}
	
	
	
	private static String getRandom(String plaintext)
	{
//		String digested = digestedMap.get(plaintext);
		String digested = getDigestedMapInstane().get(plaintext);
		if (digested == null) {
	        sr.nextBytes(bytes);
	        digested =  Base64Codec.encode(bytes) ;	        
//	        digestedMap.put(plaintext, digested);
	        getDigestedMapInstane().put(plaintext, digested);
	    }
		return digested;
	}

	public static byte[] calculateRawRFC2104HMAC(byte[] data, byte[] key)
	throws java.security.SignatureException
	{
		return calculateRawRFC2104HMAC(data, key, null);
	}

	
	/**
	* Computes raw (byte[]) RFC 2104-compliant HMAC signature.
	* * @param data
	* The raw (byte[]) data to be signed.
	* @param key
	* The raw signing key byte[].
	* @return
	* The raw (byte[] RFC 2104-compliant HMAC signature.
	* @throws
	* java.security.SignatureException when signature generation fails
	*/
	public static byte[] calculateRawRFC2104HMAC(byte[] data, byte[] key, String alg)
	throws java.security.SignatureException
	{
	byte[] result;
	if ( alg == null ) {
		alg = HMAC_SHA256_ALGORITHM;	// SHA256 used as default
	}
	try {

		// get an hmac_sha1/sha256 key from the raw key bytes
		SecretKeySpec signingKey = new SecretKeySpec(key, alg);	// might not work with this alg, then will throw exception
	
		// get an hmac_sha1/sha256 Mac instance and initialize with the signing key
		Mac mac = Mac.getInstance(alg);
		mac.init(signingKey);
	
		// compute the hmac on input data bytes
		byte[] rawHmac = mac.doFinal(data);
	
		result = rawHmac;

	} catch (Exception e) {
		throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
	}
	return result;
	}

	

	/**
	 * 		Rfc2898DeriveBytes 
	 * @param data
	 * @param password
	 * @param salt
	 * @param noIterations
	 * @param keyLength, bits
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
//	public static byte[] PBKDF2(char[] password,
	public static SecretKey PBKDF2Key(char[] password,
		    byte[] salt, int noIterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		  String ALGORITHM = "PBKDF2WithHmacSHA1";
//		  String ALGORITHM = "PBKDF2WithHmacSHA256";	// unfortunately we need java8 for this
		  
//		  byte[] hash = null;
		  SecretKey key = null;		
		  
	      PBEKeySpec spec = new PBEKeySpec(password, salt, noIterations, keyLength);
	      SecretKeyFactory factory;
	      factory = SecretKeyFactory.getInstance(ALGORITHM);
//	      hash =  factory.generateSecret(spec).getEncoded();
	      key =  factory.generateSecret(spec);
	      return key;
		}

	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return PBKDF2(password, salt, noIterations, DEFAULT_PBKDF2_KEYLENGTH);
	}

	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return PBKDF2Key(password, salt, noIterations, keyLength).getEncoded();
	}	
	
	
	public static String certToString(X509Certificate cert) {
	    StringWriter sw = new StringWriter();
	    try {
	        sw.write("-----BEGIN CERTIFICATE-----\n");
	        sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
	        sw.write("\n-----END CERTIFICATE-----\n");
	    } catch (CertificateEncodingException e) {
	        e.printStackTrace();
	    }
	    return sw.toString();
	}
	
	public static List<X509Certificate> parseCertificates(String certAsString) throws CertificateException, IOException{
//		StringReader fis = new StringReader(certAsString);
//		FileInputStream fis = new FileInputStream(filename);
		 BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(certAsString.getBytes("UTF-8")));

		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Collection<? extends Certificate> c = cf.generateCertificates(bis);
		 Iterator<? extends Certificate> i = c.iterator();
		 ArrayList<X509Certificate> a = new ArrayList<X509Certificate>();
		 while (i.hasNext()) {
			 X509Certificate cert = (X509Certificate)i.next();
			 a.add(cert);
//		    Certificate cert = (Certificate)i.next();
//		    System.out.println( cert.getIssuerDN());
//		    System.out.println(cert);
		 }
		 return a;
		
//	    //before decoding we need to get rod off the prefix and suffix
//	    byte [] decoded = Base64.decode(certStr.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
//
//	    return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
	}
	
	
	public static X509Certificate parseCertificate(String certAsString) throws CertificateException, IOException{
//		StringReader fis = new StringReader(certAsString);
//		FileInputStream fis = new FileInputStream(filename);
		 BufferedInputStream bis = new BufferedInputStream(new ByteArrayInputStream(certAsString.getBytes("UTF-8")));

		 CertificateFactory cf = CertificateFactory.getInstance("X.509");
		 Certificate cert = null;
		 while (bis.available() > 0) {
		    cert = cf.generateCertificate(bis);
//		    System.out.println(cert.getPublicKey().getFormat());
//		    System.out.println(cert.toString());
		 }
		 // return last, there should only be zero or one
		 return (X509Certificate)cert;
		
//	    //before decoding we need to get rod off the prefix and suffix
//	    byte [] decoded = Base64.decode(certStr.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
//
//	    return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
	}

	// Experimental
	public static List<PublicKey> parsePubKey(String pubKeyAsString) throws  IOException{
		
		List<PublicKey>  pubKeys = null;
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		kpg.initialize(2014);
		KeyPair kp = kpg.genKeyPair();
		kp.getPublic().getAlgorithm(); // should return "RSA"
		kp.getPublic().getFormat(); // should return "X.509", NOT "PKCS#8" because that would be your secret private key
		byte[] yourSideEncodedPubKey = kp.getPublic().getEncoded(); // returns byteArray
		String yourSidePubKeyAsString = Utils.byteArrayToHexString(yourSideEncodedPubKey); // make a hexstring for sending off
		// POST in form field parameter
		
		// Retrieve from POST parameters
		byte[] mySideEncodedPubKey = Utils.hexStringToByteArray(yourSidePubKeyAsString); // 
		
		X509EncodedKeySpec mySidePubKeySpec = new X509EncodedKeySpec(mySideEncodedPubKey);
		 KeyFactory keyFactory = null;
		 PublicKey mySidePubKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			mySidePubKey = keyFactory.generatePublic(mySidePubKeySpec);
		}
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return pubKeys;
	}
	
	// Experimental
	public static PublicKey parsePubKey(byte[] pubKeyBytes) throws  IOException{
		
		X509EncodedKeySpec mySidePubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		 KeyFactory keyFactory = null;
		 PublicKey mySidePubKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			mySidePubKey = keyFactory.generatePublic(mySidePubKeySpec);
		}
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return mySidePubKey;
	}

	
	
	// no lambdas yet so use simple wrapper
	private static class LogWrapper  {
		
		public static void log(ISystemLogger logger, Level level, String module, String method, String message)
		{
			if (logger != null) {
				logger.log(level, module, method, message);
			}
		}

		
		public static void log(ISystemLogger logger, Level level, String module, String method, String message, Throwable cause) {
			if (logger != null) {
				logger.log(level, module, method, message, cause);
			}
		}

	}
	
    public static boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
    	return isSelfSigned(cert, null);
    }
	
    public static boolean isSelfSigned(X509Certificate cert, ISystemLogger oSystemLogger)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
		String sMethod = "isSelfSigned";

		LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "DN, trusted cert: "+cert.getSubjectDN());

        try {
            PublicKey key = cert.getPublicKey();
            LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "found PublicKey, verifying key");
             cert.verify(key);
             LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "verifying key OK");
            return true;
        } catch (SignatureException sigEx) {
        	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "SignatureException: "+ sigEx.getMessage());
            return false;
        } catch (InvalidKeyException keyEx) {
        	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "InvalidKeyException: "+ keyEx.getMessage());
            return false;
        }
    }

    
    /**
     * 
     * @param clientCert
     * @param trustedCerts
     * @param date2compare, if null, date checking is disabled
     * @param revocationEnabled
     * @param oSystemLogger
     * @return
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean validateCertAgainstChainPKI(X509Certificate clientCert,
            List<X509Certificate> trustedCerts, Date date2compare, boolean revocationEnabled, ISystemLogger oSystemLogger) throws CertificateException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {

    	String sMethod = "validateKeyChainPKI";
        boolean found = false;
        int i = trustedCerts.size();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor trustedAnchor;
        Set<TrustAnchor> trustedAnchors;
        CertPath certPath;
        List<Certificate> certList;
        PKIXParameters paramsPKIX = null;
        CertPathValidator validatorPKIX = CertPathValidator.getInstance("PKIX");
        String clientRfc2253Subject = clientCert.getSubjectX500Principal().getName();

        LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Start validating:" + clientRfc2253Subject 
        		+ " with validator algoritm "+ validatorPKIX.getAlgorithm() );

        while (!found && i > 0) {
            trustedAnchor = new TrustAnchor(trustedCerts.get(--i), null);
            String clientRfc2253Issuer = clientCert.getIssuerX500Principal().getName();
            String trustedRfc2253Subject = trustedCerts.get(i).getSubjectX500Principal().getName();
            LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Using (next) trustedCert: "+ trustedRfc2253Subject);
            trustedAnchors = Collections.singleton(trustedAnchor);
 
            certList = Arrays.asList(new Certificate[] { clientCert });
            certPath = cf.generateCertPath(certList);
 
            paramsPKIX = new PKIXParameters(trustedAnchors);
            LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Setting param RevocationEnabled to : "+revocationEnabled);
            paramsPKIX.setRevocationEnabled(revocationEnabled);
            if (date2compare == null) {	// ignore date
	            date2compare = clientCert.getNotBefore();
	            if (date2compare == null) {	// one of them should not be null
	            	date2compare = clientCert.getNotAfter();
	            }
            }
            LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Setting param Date to : "+date2compare);
            paramsPKIX.setDate(date2compare);
            
            LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Comparing Rfc2253 DN, client issuer="+clientRfc2253Issuer 
            		+ " to trusted-cert subject=" + trustedRfc2253Subject);

            if ( clientRfc2253Issuer.equals(trustedRfc2253Subject) ) {
            	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "DNs Rfc2253 equal, validating...");
                try {
                    validatorPKIX.validate(certPath, paramsPKIX);
                    LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Validation ok for:" + clientRfc2253Subject 
                    		+ " against trusted-cert:" + trustedRfc2253Subject + ", is trusted cert selfsigned?");
                    if ( isSelfSigned(trustedCerts.get(i), oSystemLogger) ) {
                        // found a root ca
                        found = true;
                        LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Selfsigned validated root for: " + trustedRfc2253Subject);
                    } else if ( !clientCert.equals(trustedCerts.get(i)) ) {	// don't check yourself
                        // find parent ca
                    	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Not selfsigned, validating against parent:" + trustedCerts.get(i).getIssuerX500Principal().getName());
                        found = validateCertAgainstChainPKI(trustedCerts.get(i), trustedCerts, date2compare, revocationEnabled, oSystemLogger);
                    }
                } catch (CertPathValidatorException e) {
                    // validation fail, check next certificate in the trustedCerts array
                	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Validation fail, CertPathValidatorException: " + e.getMessage());
                } catch (InvalidAlgorithmParameterException e) {
                	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Validation fail, InvalidAlgorithmParameterException: " + e.getMessage());
                }
            } else {
            	LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "DNs not Rfc2253 equal, maybe next");
            }
        }
        LogWrapper.log(oSystemLogger, Level.FINEST, MODULE, sMethod, "Last trustedCert done, found="+ found);
 
        return found;
    }

    
    
	public static class CleanupDigestMap implements Runnable {
		
		@Override
		public void run() {
//			System.out.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
//					Thread.currentThread().getName() + ": " + "Cleaning up digestedMap");// must go
			if (digestedMap != null) digestedMap.clear();
		}
	}
	

	public  static void teardown () {
		if (scheduledThreadPool != null) {
//			System.out.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
//					Thread.currentThread().getName() + ": " + "Shutting down  scheduledThreadPool");// must go
			scheduledThreadPool.shutdown();
			try {
				if (!scheduledThreadPool.awaitTermination(10, TimeUnit.SECONDS)) {
					scheduledThreadPool.shutdownNow();
				}
			} catch (InterruptedException e) {
				scheduledThreadPool.shutdownNow();
			}
//			System.out.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
//					Thread.currentThread().getName() + ": " + "scheduledThreadPool shut down initialized");// must go
		}
    }

	
	public static final String AES_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";	// use this as a default
	
	/* See also Java: Standard Algorithm Name Documentation
	 * 
	 * 	AES/CBC/NoPadding (128)
		AES/CBC/PKCS5Padding (128)
		AES/ECB/NoPadding (128)
		AES/ECB/PKCS5Padding (128)
		DES/CBC/NoPadding (56)
		DES/CBC/PKCS5Padding (56)
		DES/ECB/NoPadding (56)
		DES/ECB/PKCS5Padding (56)
		DESede/CBC/NoPadding (168)
		DESede/CBC/PKCS5Padding (168)
		DESede/ECB/NoPadding (168)
		DESede/ECB/PKCS5Padding (168)
		RSA/ECB/PKCS1Padding (2048)
		RSA/ECB/OAEPPadding (2048)
	 */
	public static byte[] EncryptAESData(SecretKey key, byte[] data,  String cipherAlg) {
		try {
			// get an RSA cipher object and print the provider
			if (cipherAlg == null)  cipherAlg = AES_CIPHER_ALGORITHM;
			Cipher cipher = Cipher.getInstance(cipherAlg);
			//mLog.wtf("RSA Cipher provider used is: ", cipher.getProvider().toString());
			//encrypt the plain text using the key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] DecryptAESData(SecretKey key, byte[] data, String cipherAlg) {
		try {
			// get an RSA cipher object and print the provider
			if (cipherAlg == null)  cipherAlg = AES_CIPHER_ALGORITHM;
			Cipher cipher = Cipher.getInstance(cipherAlg);
			//mLog.wtf("RSA Cipher provider used is: ", cipher.getProvider().toString());
			//encrypt the plain text using the key
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// RH, 20190927, sn
	public static synchronized String encryptRSAString(String plain, PublicKey pub_key, ISystemLogger oSystemLogger)
	{
		return encryptRSAString(plain, pub_key, null, oSystemLogger);
	}
	
	public static synchronized String encryptRSAString(String plain, PublicKey pub_key, String encoding, ISystemLogger oSystemLogger)
	{
		String sMethod = "encryptRSAString";

		String encrypted = null;
		if (plain != null) {
			if (encoding == null) { encoding = "UTF-8"; }
			if (pub_key != null) {
				Cipher _cipher;
				try {
					_cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
					// alternatives could be "RSA/None/NoPadding" or "RSA/ECB/PKCS1Padding" or "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
					try {
						_cipher.init(Cipher.ENCRYPT_MODE, pub_key);
						byte[] baCipher =_cipher.doFinal(plain.getBytes(encoding));
						encrypted =  Utils.byteArrayToHexString(baCipher);
					} catch (InvalidKeyException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "InvalidKeyException: " + e.getMessage());
					} catch (IllegalBlockSizeException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "IllegalBlockSizeException: " + e.getMessage());
					} catch (BadPaddingException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "BadPaddingException: " + e.getMessage());
					} catch (UnsupportedEncodingException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "UnsupportedEncodingException: " + e.getMessage());
					}
				} catch (NoSuchAlgorithmException e) {
					LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchAlgorithmException: " + e.getMessage());
				} catch (NoSuchPaddingException e) {
					LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchPaddingException: " + e.getMessage());
				}
			} else {
				LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No public key provided for encryption");
			}
		} else {
			LogWrapper.log(oSystemLogger, Level.FINER, MODULE, sMethod, "plain text == null, no encryption done!");
		}
		return encrypted;
	}

	public static synchronized String decryptRSAString(String sEncodedText, PrivateKey secretKey, ISystemLogger oSystemLogger)
	{
		return decryptRSAString(sEncodedText, secretKey, null, oSystemLogger);
	}
	
	public static synchronized String decryptRSAString(String sEncryptedText, PrivateKey secretKey, String encoding, ISystemLogger oSystemLogger)
	{
		String sMethod = "decryptRSAString";
		
		String decrypted = null;
		if (sEncryptedText != null) {
			if (encoding == null) { encoding = "UTF-8"; }
			if (secretKey != null) {
				Cipher _cipher;
				try {
					_cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
					// alternatives could be "RSA/None/NoPadding" or "RSA/ECB/PKCS1Padding" or "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
					try {
						_cipher.init(Cipher.DECRYPT_MODE, secretKey);
						byte[] baData = Utils.hexStringToByteArray(sEncryptedText);
						decrypted = new String(_cipher.doFinal(baData), encoding);
					} catch (InvalidKeyException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "InvalidKeyException: " + e.getMessage());
					} catch (UnsupportedEncodingException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "UnsupportedEncodingException: " + e.getMessage());
					} catch (IllegalBlockSizeException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "IllegalBlockSizeException: " + e.getMessage());
					} catch (BadPaddingException e) {
						LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "BadPaddingException: " + e.getMessage());
					}
				} catch (NoSuchAlgorithmException e) {
					LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchAlgorithmException: " + e.getMessage());
				} catch (NoSuchPaddingException e) {
					LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchPaddingException: " + e.getMessage());
				}
			} else {
				LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No private key provided for encryption");
			}
		} else {
			LogWrapper.log(oSystemLogger, Level.FINER, MODULE, sMethod, "encrypted text == null, no decryption done!");
		}
		return decrypted;
	}
	// RH, 20190927, en

	// RH, 20191001, sn
	public static synchronized PrivateKey getPrivateKeyFromLocation(String location, String pw, String alias, ISystemLogger oSystemLogger) {
		KeyStore ks = loadKeystore(location, oSystemLogger);
		PrivateKey _oPrivateKey =  getPrivateKeyFromKeystore(ks, pw, alias, oSystemLogger);
		return _oPrivateKey;
	}

	public static synchronized PublicKey getPublicKeyFromLocation(String location, String alias, ISystemLogger oSystemLogger) {
		KeyStore ks = loadKeystore(location, oSystemLogger);
		PublicKey _oPublicKey =  getPublicKeyFromKeystore(ks, alias, oSystemLogger);
		return _oPublicKey;
	}

	public static synchronized KeyStore loadKeystore(String location, ISystemLogger oSystemLogger) {
		String sMethod = "loadKeystore";
		
		if (location == null) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No location provided");
			return null;
		}
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(location), null);
		} catch (KeyStoreException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "KeyStoreException: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchAlgorithmException: " + e.getMessage());
		} catch (CertificateException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "CertificateException: " + e.getMessage());
		} catch (FileNotFoundException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "FileNotFoundException: " + e.getMessage());
		} catch (IOException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "IOException: " + e.getMessage());
		}
		return ks;
	}
	
	public static synchronized PrivateKey getPrivateKeyFromKeystore(KeyStore ks, String pw, String alias, ISystemLogger oSystemLogger) {
		String sMethod = "getCertificateFromKeystore";

		if (ks == null) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No KeyStore provided");
			return null;
		}

		char[] caPasswordChars = pw.toCharArray();
		PrivateKey _oPrivateKey = null;
		try {
			_oPrivateKey = (PrivateKey) ks.getKey(alias, caPasswordChars);
		} catch (UnrecoverableKeyException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "UnrecoverableKeyException: " + e.getMessage());
		} catch (KeyStoreException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "KeyStoreException: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "NoSuchAlgorithmException: " + e.getMessage());
		}
		return _oPrivateKey;
	}

	public static synchronized PublicKey getPublicKeyFromKeystore(KeyStore ks, String alias, ISystemLogger oSystemLogger) {
		java.security.cert.X509Certificate x509Cert = getCertificateFromKeystore(ks, alias, oSystemLogger);
		PublicKey _oPublicKey = getPublicKeyFromCert(x509Cert, oSystemLogger);
		return _oPublicKey;
	}

	public static synchronized java.security.cert.X509Certificate getCertificateFromKeystore(KeyStore ks, String alias, ISystemLogger oSystemLogger) {
		String sMethod = "getCertificateFromKeystore";

		if (ks == null) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No KeyStore provided");
			return null;
		}
		if (alias == null) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No alias provided");
			return null;
		}
		java.security.cert.X509Certificate x509Cert = null;
		try {
			x509Cert = (java.security.cert.X509Certificate) ks
				.getCertificate(alias);
		} catch (KeyStoreException e) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "KeyStoreException: " + e.getMessage());
		}
		return x509Cert;
	}

	public static synchronized PublicKey getPublicKeyFromCert(java.security.cert.X509Certificate x509Cert, ISystemLogger oSystemLogger) {
		String sMethod = "getPublicKeyFromCert";

		if (x509Cert == null) {
			LogWrapper.log(oSystemLogger, Level.WARNING, MODULE, sMethod, "No X509Certificate provided");
			return null;
		}
		PublicKey _oPublicKey = x509Cert.getPublicKey();
		return _oPublicKey;
	}
	// RH, 20191001, en
	
	
	private static void usage(PrintStream outStream) {
		outStream.println("Usage: org.aselect.system.utils.crypto.Auxiliary \"<plaintext_1>\" [\"<plaintext_2>\" ... \"<plaintext_n>\"]");
	}
	
	/*
	public static void main(String[] args)
	{
		if ( args.length > 0 ) {
			for (String s : args) {
				System.out.println(base64Digest(s));
//				System.out.print(s + "\t\t\t");System.out.println("obfuscate:" + obfuscate(s));
			}
		} else {
			usage(System.out);
		}
	}
	*/
	/*
	public static void main(String[] args)	// for testing
	{
		String certificateAsString = "-----BEGIN CERTIFICATE-----\n" + 
				"MIIHqDCCBZCgAwIBAgIUESCpFlJRCRjMUdKYM98EtPNxt8owDQYJKoZIhvcNAQEL\n" + 
				"BQAwgYUxCzAJBgNVBAYTAk5MMR4wHAYDVQQKDBVRdW9WYWRpcyBUcnVzdGxpbmsg\n" + 
				"QlYxKDAmBgNVBAsMH0lzc3VpbmcgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxLDAq\n" + 
				"BgNVBAMMI1F1b1ZhZGlzIENTUCAtIFBLSSBPdmVyaGVpZCBDQSAtIEcyMB4XDTE0\n" + 
				"MTExODEwNDUzM1oXDTE1MTExODEwNDUzMlowgb8xHTAbBgNVBAUTFDAwMDAwMDAx\n" + 
				"MDAzMTY2OTQ2MDAwMQswCQYDVQQGEwJOTDEVMBMGA1UECBMMWnVpZC1Ib2xsYW5k\n" + 
				"MRYwFAYDVQQHEw0ncy1HcmF2ZW5oYWdlMSkwJwYDVQQKEyBNaW5pc3RlcmllIHZh\n" + 
				"biBFY29ub21pc2NoZSBaYWtlbjEOMAwGA1UECxMFRGljdHUxJzAlBgNVBAMTHnd3\n" + 
				"dy5taWpub25kZXJuZW1pbmdzZG9zc2llci5ubDCCASIwDQYJKoZIhvcNAQEBBQAD\n" + 
				"ggEPADCCAQoCggEBANbeYKr6sVzE2PX0kD6mAK89WFTpyvYACUBo12BML/sciT0R\n" + 
				"gxdEInIAAib3rtLRpfIKrCtgzh9u/SGjlOw95A2jEbIuvQgRJIDnTu4NMcENHlGb\n" + 
				"Jkbo36TC+O3eVLbUUdR7HE2oLbFzkOBvG/3MuFQPC+h4H5e1tGMNCaP6R6fYwMcs\n" + 
				"u1l0kSHR0MafZk3X8FUaaHyUyRavobpoSUHQUFPRkKlAXdqTycwVJxjb2harfMys\n" + 
				"daO3Bqb40wNet9acyRQQPqg9PywZ0jRwj655QqPv1039jIF5Z4oBnfMTT2J/UteZ\n" + 
				"snFYqybQo8uEilyGb30jImq9Qjck2vcDSxHupT0CAwEAAaOCAtIwggLOMAwGA1Ud\n" + 
				"EwEB/wQCMAAwggExBgNVHSAEggEoMIIBJDCCASAGCmCEEAGHawECBQYwggEQMIHX\n" + 
				"BggrBgEFBQcCAjCByhqBx1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkg\n" + 
				"YW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgcmVsZXZhbnQgUXVv\n" + 
				"VmFkaXMgQ2VydGlmaWNhdGlvbiBQcmFjdGljZSBTdGF0ZW1lbnQgYW5kIG90aGVy\n" + 
				"IGRvY3VtZW50cyBpbiB0aGUgUXVvVmFkaXMgcmVwb3NpdG9yeSAgKGh0dHA6Ly93\n" + 
				"d3cucXVvdmFkaXNnbG9iYWwuY29tKS4wNAYIKwYBBQUHAgEWKGh0dHA6Ly93d3cu\n" + 
				"cXVvdmFkaXNnbG9iYWwuY29tL3JlcG9zaXRvcnkwaQYDVR0RBGIwYKA+BgorBgEE\n" + 
				"AYI3FAIDoDAMLjIuMTYuNTI4LjEuMTAwMy4xLjMuNS4yLjEtMDAwMDAwMDEwMDMx\n" + 
				"NjY5NDYwMDCCHnd3dy5taWpub25kZXJuZW1pbmdzZG9zc2llci5ubDBzBggrBgEF\n" + 
				"BQcBAQRnMGUwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnF1b3ZhZGlzZ2xvYmFs\n" + 
				"LmNvbTA3BggrBgEFBQcwAoYraHR0cDovL3RydXN0LnF1b3ZhZGlzZ2xvYmFsLmNv\n" + 
				"bS9xdm9jYWcyLmNydDAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUH\n" + 
				"AwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFGnLf1B2AIZTlXkSwVh2HxPv8k2jMDoG\n" + 
				"A1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwucXVvdmFkaXNnbG9iYWwuY29tL3F2\n" + 
				"b2NhZzIuY3JsMB0GA1UdDgQWBBQDk0P/als3z+/ta/HqxZqSMQv1GTANBgkqhkiG\n" + 
				"9w0BAQsFAAOCAgEAP6D8v4Em6hLx3FXgd9DOm3ix+j5vMH8uN7E9M1mZoXBwOe3f\n" + 
				"88Fs4OtdynnN642eqKMKLvJOtp8tUrH3L0z/ncJEHG49SGw201ZHoJNZY5umOzO1\n" + 
				"1G0QyXC8aqgGbdAvzXe8OrEcOYZ8DSBI/qDegAM2z/byAIK4Nf2IJTRT9ADRMDkA\n" + 
				"901MKQ3nr7fX4CplfYGbuRNgQm1w5gTepZg82m2mjaHnk3VoGPWWtHv3qW+A867D\n" + 
				"gZkwk1d2yxS6kM44kmDyjhfS1PLWLNsF7Qs7KKGyRC518Tro+jjg+VTnZn7aGIP6\n" + 
				"2VEVuHqKhmtCMGKfzz03Mly2FNoLjeaCtZHUu+GzvYRFL6RUB1hR9wuN42+OF1br\n" + 
				"zM1oSa/rDNRgQgoxGOBa4v1Ahhkmqfc4ezVYGCmGSexgYc6dPuPNJiu7MeC130CV\n" + 
				"GJYYUMQfnt7fnaxnbxlHDoEm0sceLD8727/Pmth9LdCuiaJ5Zq76h86TQ7rLw9gO\n" + 
				"i0HI3B+WLS1mfibzalQBs8cKiqvZmuGr+QauL90kfJDIU7SjNucW6kDxwa6s2ot5\n" + 
				"UaYL4u8Tg+w+mW96A8OOAVUiiKVOeLq0L6v8aIvjDwIFgb3CX1u4zlshqmR1W9kJ\n" + 
				"utqihtsVcVwQKi03s+WoXX4FYJ0f+J8wroAh0PqzIue/90/iBG/zfe2qwRU=\n" + 
				"-----END CERTIFICATE-----";
		try {
//			parseCertificate(certificateAsString);
			 List<X509Certificate> l = parseCertificates(certificateAsString);
			 for (X509Certificate c : l) {
				 System.out.println(c.getSubjectDN().getName());
			 }
		}
		catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}
	*/
	
	/*
	public static void main(String[] args)	// for testing
	{
		HashMap outermap = new HashMap();
		HashMap innermap = new HashMap();
		
		innermap.put("naam", "jan");
		innermap.put("adres", "adresvanjan");
		innermap.put("uid", "900123");
		innermap.put("url", "https://www.ergens.nl");
		innermap.put("uID", "900456");
		innermap.put("BSN", "900456");

		String[] sArray = { "Jantje", "09000293890", "Pietje"};
		List l = Arrays.asList(sArray);
		innermap.put("list", l);
		
		Vector v = new Vector();
		v.add("Keesje");
		v.add("Kareltje");
		v.add("900029389");
		innermap.put("vector", v);
		
		outermap.put("UID", "20151130134900");
		outermap.put("content", innermap);
		outermap.put("uID", innermap);

		
		System.out.println("innermap:" + innermap);

		System.out.println("outermap:" + outermap);
		
		System.out.println("obfuscated outermap:" + obfuscate(outermap));
		
		System.out.println("original outermap after obfuscation:" + outermap);
		
		String originalString =  "Hello 900029389 world. Hello900029389world, 09000293890 >900029389< uid=900029389" +
		"&ticket_exp_time=1449238721723&uid=900029389&organization=https%3A%2F%2F";
		System.out.println("original string:" + originalString);
		System.out.println("obfuscated string:" + obfuscate(originalString));

//		String simpleString = "123456789 900029389 987654321 900029389987611111";
		String simpleString = "123456789 900029389 987654321 90002938998761111 900029389";
//		String simpleString = "123456789";
		System.out.println("original simpleString:" + simpleString);
		System.out.println("obfuscated simpleString:" + obfuscate(simpleString));
	}
	*/

}
