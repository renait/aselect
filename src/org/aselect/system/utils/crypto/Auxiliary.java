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
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.instrument.Instrumentation;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.SerializationUtils;
import org.aselect.system.utils.Base64Codec;


public class Auxiliary
{

	private static final String DEFAULT_DIGEST_ALG = "SHA-256";
	private static final String PROPERTY_DEFAULT_DIGEST_ALG = "aselect.default.digest.alg";
	private static final String[] ALGS = { "NONE", "RANDOM", "SHA-256" , "SHA-384" , "SHA-512" };
	private static final List<String> ALLOWED_DIGEST_ALGS = Arrays.asList(ALGS);

	private static String DIGEST_ALG = null;
	// in the end we want REGS and KEYS to be retrieved from some external source
	private static final String[] DEFAULT_REGS = { "^([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})[^0-9]", "[^0-9]([0-9]{9})$", "^([0-9]{9})$"};	// anything resembling a BSN
	public static List<Pattern> REGEX_PATTERNS =  new ArrayList<Pattern>();

	private static final String[] DEFAULT_KEYS = { "uid", "Uid", "UID", "uID", "bsn", "Bsn", "BSN", "obouid", "user_id" , "sel_uid", "userId", "user_Id",
		"password", "pw", "passwd", "shared_secret", "secret"  };
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

	private static void usage(PrintStream outStream) {
		outStream.println("Usage: org.aselect.system.utils.crypto.Auxiliary \"<plaintext_1>\" [\"<plaintext_2>\" ... \"<plaintext_n>\"]");
	}
	
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
