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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.aselect.system.utils.Base64Codec;

public class Auxiliary
{	
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
	private static final int DEFAULT_PBKDF2_KEYLENGTH = 256;	// bits


//	private static final String DEFAULT_DIGEST_ALG = "SHA-256";	// RH, 20160510, o
	private static final String DEFAULT_DIGEST_ALG = "RANDOM";	// RH, 20160510, n
	private static final String PROPERTY_DEFAULT_DIGEST_ALG = "aselect.default.digest.alg";
	private static final String[] ALGS = { "NONE", "RANDOM", "SHA-256" , "SHA-384" , "SHA-512" };
	private static final List<String> ALLOWED_DIGEST_ALGS = Arrays.asList(ALGS);

	private static String DIGEST_ALG = null;
	// in the end we want REGS and KEYS to be retrieved from some external source
	private static final String[] DEFAULT_REGS = { "^([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})$", "^([0-9]{9})$"};	// anything resembling a BSN
	public static List<Pattern> REGEX_PATTERNS =  new ArrayList<Pattern>();

	private static final String[] DEFAULT_KEYS = { "uid", "Uid", "UID", "uID", "bsn", "Bsn", "BSN", "obouid", "user_id" , "sel_uid", "userId", "user_Id",
		"name_id", "Name_ID", "NAME_ID", "Name_id", "authid", "Authid", "AuthId", "AuthID",
		"password", "pw", "passwd", "shared_secret", "secret", "cn", "CN",
	 	"full_dn", "mail", "email" };
	public static final List<String> BANNED_KEYS = Arrays.asList(DEFAULT_KEYS);
	private static SecureRandom sr = null;
	private static  byte bytes[] = new byte[20];
 
	
	static {
		try {
			DIGEST_ALG = System.getProperty(PROPERTY_DEFAULT_DIGEST_ALG);
			if (DIGEST_ALG == null || !ALLOWED_DIGEST_ALGS.contains(DIGEST_ALG )) {
				DIGEST_ALG = DEFAULT_DIGEST_ALG;
			}
		} catch (Exception se) {
			DIGEST_ALG = DEFAULT_DIGEST_ALG;
		}
	}

	static {
		for (int i=0; i<DEFAULT_REGS.length; i++) {
//			System.out.println("REGS:" +  DEFAULT_REGS[i]);	// must go
			Pattern pattern = Pattern.compile(DEFAULT_REGS[i]);
//			System.out.println("pattern:" +  pattern.pattern());		// must go
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
//						System.out.println("\t\tmatch:" +  match);	// must go
						int sAddress = sb.indexOf(match, matcher.start());
						sb.replace(sAddress, sAddress + match.length(), base64Digest(match));
//						System.out.println("\t\tinput:" +  sb.toString());	// must go
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
//		System.out.println("start serializing the object...");	// must go
   		Serializable s = null;
   		if (o != null) {
			PipedOutputStream outstr = new PipedOutputStream();
			// maybe we can connect the input tot the output later, after estimating the objectsize so we will be able to estimate the size of the buffer needed
			//		System.out.println("object size:");	// must go
	
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
//		System.out.println("...finish serializing the object.");	// must go
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
			System.err.println("WARNING, don't know how to obfuscate this object:" + original.toString());
			return original;	// 	we would like to inform but have no logger
		}
	}

	
	/**
	 * 
	 * @param original
	 * @return an obfuscated copy of the original Map
	 */
	public static Map obfuscate(Map original) {
		
		Map obfuscated = null;
		if (original != null) {
			if (!"NONE".equals(DIGEST_ALG)) {	// obfuscating is expensive, so be sure you have to.
//				System.out.println("start obfuscating the Map...");	// must go
		//		Map obfuscated = new HashMap();
		//		obfuscated.putAll(original);	// no deep clone
	//			obfuscated = (Map) SerializationUtils.clone((Serializable)original);	// Does deep clone, works but needs commons-lang
				try {
					obfuscated = (Map) serialize((Serializable)original);	// Does deep clone
					obfuscated = obf(obfuscated);
				}
				catch (IOException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
//					System.out.println("IOException obfuscating the Map:" + e.getMessage());	// must go
				}
				catch (ClassNotFoundException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
//					System.out.println("ClassNotFoundException obfuscating the Map:" + e.getMessage());	// must go
				}
//				System.out.println("...finish obfuscating the Map");	// must go
			} else {
				obfuscated = original;
//				System.out.println("Not obfuscating the Map");	// must go
			}
		}
		return obfuscated;
	}
	
	public static List obfuscate(List original) {
		
		List obfuscated = null;
		if (original != null) {
			if (!"NONE".equals(DIGEST_ALG)) {	// obfuscating is expensive, so be sure you have to.
//				System.out.println("start obfuscating the List...");	// must go
		//		Map obfuscated = new HashMap();
		//		obfuscated.putAll(original);	// no deep clone
	//			obfuscated = (Map) SerializationUtils.clone((Serializable)original);	// Does deep clone, works but needs commons-lang
				try {
					obfuscated = (List) serialize((Serializable)original);	// Does deep clone
					obfuscated = obf(obfuscated);
				}
				catch (IOException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
//					System.out.println("IOException obfuscating the Map:" + e.getMessage());	// must go
				}
				catch (ClassNotFoundException e) {
					obfuscated = null; // we don't want to return unobfuscated data 
//					System.out.println("ClassNotFoundException obfuscating the Map:" + e.getMessage());	// must go
				}
//				System.out.println("...finish obfuscating the List");	// must go
			} else {
				obfuscated = original;
//				System.out.println("Not obfuscating the List");	// must go
			}
		}
		return obfuscated;
	}

	
	/**
	 * @param plaintext	plain text input to be digested ( using current digest algorithm DIGEST_ALG )
	 * @return base64 coded digest string
	 */
	public static String base64Digest(String plaintext) {
		return base64Digest(plaintext, DIGEST_ALG);
	}
	
	/**
	 * @param plaintext	plain text input to be digested
	 * @param algorithm one of NONE, SHA-256, SHA-384, SHA-512
	 * @return base64 coded digest string
	 */
	public static String base64Digest(String plaintext, String algorithm) {
		String digested = null;
		if ( plaintext != null ) {
			if ("NONE".equalsIgnoreCase(algorithm)) {
				digested = "{" +algorithm + "}{" + plaintext + "}";
//				System.out.println("Not digesting the String.");	// must go
			} else if ("RANDOM".equalsIgnoreCase(algorithm)) {
		        sr.nextBytes(bytes);
		        digested = "{" +algorithm + "}{" + Base64Codec.encode(bytes) + "}";
			} else {
//				System.out.println("Start digesting the String...");	// must go
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
//				System.out.println("...finish digesting the String.");	// must go
			}
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

	
	
	

	private static void usage(PrintStream outStream) {
		outStream.println("Usage: org.aselect.system.utils.crypto.Auxiliary \"<plaintext_1>\" [\"<plaintext_2>\" ... \"<plaintext_n>\"]");
	}
	
//	public static void main(String[] args)
//	{
//		if ( args.length > 0 ) {
//			for (String s : args) {
//				System.out.println(base64Digest(s));
////				System.out.print(s + "\t\t\t");System.out.println("obfuscate:" + obfuscate(s));
//			}
//		} else {
//			usage(System.out);
//		}
//	}
	
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
