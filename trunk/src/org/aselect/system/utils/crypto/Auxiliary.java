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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
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
import org.aselect.system.logging.SystemLogger;
import org.aselect.system.utils.Base64Codec;
import org.aselect.system.utils.Utils;

public  final class Auxiliary
{	
	private final static String MODULE = "Auxiliary";

	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final int DEFAULT_PBKDF2_KEYLENGTH = 256;	// bits


//	private static final String DEFAULT_DIGEST_ALG = "SHA-256";	// RH, 20160510, o
	private static final String DEFAULT_DIGEST_ALG = "RANDOM";	// RH, 20160510, n
	private static final String PROPERTY_DEFAULT_DIGEST_ALG = "aselect.default.digest.alg";
	private static final String[] ALGS = { "BLANK", "NONE", "RANDOM", "SHA-256" , "SHA-384" , "SHA-512" };
	private static final List<String> ALLOWED_DIGEST_ALGS = Arrays.asList(ALGS);

	private static String DIGEST_ALG = null;
	// in the end we want REGS and KEYS to be retrieved from some external source
	private static final String[] DEFAULT_REGS = { "^([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})$", "^([0-9]{9})$"};	// anything resembling a BSN
	public static List<Pattern> REGEX_PATTERNS =  new ArrayList<Pattern>();

	private static final String[] DEFAULT_KEYS = { "uid", "Uid", "UID", "uID", "bsn", "Bsn", "BSN", "obouid", "user_id" , "sel_uid", "userId", "user_Id",
		"name_id", "Name_ID", "NAME_ID", "Name_id", "authid", "Authid", "AuthId", "AuthID",
		"password", "pw", "passwd", "shared_secret", "secret", "cn", "CN",
	 	"full_dn", "mail", "email", "contents" };
	public static final List<String> BANNED_KEYS = Arrays.asList(DEFAULT_KEYS);
	private static SecureRandom sr = null;
	private static  byte bytes[] = new byte[20];
//	private static final Map<String, String> digestedMap = new HashMap<String, String>();
	private static final Map<String, String> digestedMap = new ConcurrentHashMap<String, String>();
	private static final ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(2);
	
	static {
		try {
			DIGEST_ALG = System.getProperty(PROPERTY_DEFAULT_DIGEST_ALG);
			if (DIGEST_ALG == null || !ALLOWED_DIGEST_ALGS.contains(DIGEST_ALG )) {
				DIGEST_ALG = DEFAULT_DIGEST_ALG;
			}
			if (DEFAULT_DIGEST_ALG.equals(DIGEST_ALG)) {
				scheduledThreadPool.scheduleAtFixedRate(new Auxiliary.CleanupDigestMap(), 0, 24,
			            TimeUnit.HOURS);
			}
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
				obfuscated = new HashMap<>();	// return empty Map
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
		String digested = digestedMap.get(plaintext);
		if (digested == null) {
	        sr.nextBytes(bytes);
	        digested =  Base64Codec.encode(bytes) ;
	        digestedMap.put(plaintext, digested);
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

	
	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return PBKDF2(password, salt, noIterations, DEFAULT_PBKDF2_KEYLENGTH);
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
	public static byte[] PBKDF2(char[] password,
		    byte[] salt, int noIterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		  String ALGORITHM = "PBKDF2WithHmacSHA1";
//		  String ALGORITHM = "PBKDF2WithHmacSHA256";	// unfortunately we need java8 for this
		  
		  byte[] hash = null;
		  
	      PBEKeySpec spec = new PBEKeySpec(password, salt, noIterations, keyLength);
	      SecretKeyFactory factory;
	      factory = SecretKeyFactory.getInstance(ALGORITHM);
	      hash =  factory.generateSecret(spec).getEncoded();
	      return hash;
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
			digestedMap.clear();
		}
	}
	

	public  static void teardown () {
		if (scheduledThreadPool != null) {
//			System.out.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
//					Thread.currentThread().getName() + ": " + "Shutting down  scheduledThreadPool");// must go
			scheduledThreadPool.shutdownNow();
//			System.out.println( "=+=+=+=+=" + ( new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSS" ) ).format( Calendar.getInstance().getTime() ) + 
//					Thread.currentThread().getName() + ": " + "scheduledThreadPool shut down initialized");// must go
		}
    }

	
	public static final String AES_CIPHER_ALGORITHM = "AES";
	public byte[] EncryptAESData(SecretKey key, byte[] data,  String cipherAlg) {
		try {
			// get an RSA cipher object and print the provider
			Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
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

	public byte[] DecryptAESData(SecretKey key, byte[] data) {
		try {
			// get an RSA cipher object and print the provider
			Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
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
	
}
