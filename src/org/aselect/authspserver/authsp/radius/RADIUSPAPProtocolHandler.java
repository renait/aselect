/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 */

/* 
 * $Id: RADIUSPAPProtocolHandler.java,v 1.11 2006/05/03 10:07:31 tom Exp $ 
 *
 * Changelog:
 * $Log: RADIUSPAPProtocolHandler.java,v $
 * Revision 1.11  2006/05/03 10:07:31  tom
 * Removed Javadoc version
 *
 * Revision 1.10  2006/04/12 13:29:35  martijn
 * merged A-SELECT-1_5_0-SAML
 *
 * Revision 1.9.2.1  2006/04/12 06:08:51  jeroen
 * Fix in full uid check. Now also the index is checked > -1.
 *
 * Revision 1.9  2005/09/08 13:07:37  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.8  2005/04/29 11:46:37  martijn
 * fixed bugs in logging
 *
 * Revision 1.7  2005/03/29 12:39:26  erwin
 * Improved logging.
 *
 * Revision 1.6  2005/03/14 07:30:54  tom
 * Minor code style changes
 *
 * Revision 1.5  2005/03/10 07:48:20  tom
 * Added new Logger functionality
 * Added new Configuration functionality
 * Fixed small bug in Authenticator verification
 *
 * Revision 1.4  2005/03/07 15:57:40  leon
 * - New Failure Handling
 * - Extra Javadoc
 *
 * Revision 1.3  2005/02/09 09:17:04  leon
 * added License
 * code restyle
 *
 */
package org.aselect.authspserver.authsp.radius;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.aselect.system.utils.Utils;
import org.aselect.system.utils.crypto.Auxiliary;

/**
 * The Radius Protocol Handler which handles the Radius PAP requests. <br>
 * <br>
 * <b>Description:</b><br>
 * This Radius Protocol handler handles Authentication requests using Radius PAP <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None <br>
 * 
 * @author Alfa & Ariss
 */
public class RADIUSPAPProtocolHandler extends AbstractRADIUSProtocolHandler
{
	private static final int MAXNAS_IDENT_LENGTH = 253;
	private byte _bIdentifier;
	private byte[] _baRandom;
	private DatagramSocket _listenSocket = null;
	private int _iSocketTimeout = 10000; // (154)
	private String _sErrorCode;
	private final String MODULE = "RADIUSPAPProtocolHandler";

	/**
	 * . <br>
	 * <br>
	 * 
	 * @param sPassword
	 *            the s password
	 * @return the string
	 * @see org.aselect.authspserver.authsp.radius.IRADIUSProtocolHandler#authenticate(java.lang.String)
	 */
	@Override
	public String authenticate(String sPassword)
	{
		String sMethod = "authenticate";
		_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "PAP uid=" + Auxiliary.obfuscate(_sUid));
		try {
			DatagramPacket oRADIUSPacket;
			byte xBuffer[] = new byte[MAX_RADIUS_PACKET_SIZE];
			
			byte xBufferReceive[] = new byte[MAX_RADIUS_PACKET_SIZE];		// RH, 20120823, sn
			DatagramPacket oRADIUSPacketReceive;		// we use clean receive buffer so no leftovers from sending process ( cutting buffers, old values etc.)
			oRADIUSPacketReceive = new DatagramPacket(xBufferReceive, xBufferReceive.length);	// RH, 20120823, en
			_baRandom = new byte[16];

			if (!_bFullUid) {
				int iIndex = _sUid.indexOf('@');
				if (iIndex > 0)
					_sUid = _sUid.substring(0, iIndex);
			}

			_listenSocket = new DatagramSocket();
			oRADIUSPacket = new DatagramPacket(xBuffer, xBuffer.length);

//			_systemLogger.log(Level.INFO, MODULE, sMethod, "compose pass=" + sPassword);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "composed pass");
			composeRequest(sPassword, oRADIUSPacket);
			if (_sErrorCode != Errors.ERROR_RADIUS_SUCCESS) {
				try {
					_listenSocket.close();
				}
				catch (Exception e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception while closing connection with "
							+ "RADIUS server at " + _sRadiusServer + ": ", e);
				}
				return _sErrorCode;
			}

			_listenSocket.setSoTimeout(_iSocketTimeout); // added timeout (154)
			_listenSocket.send(oRADIUSPacket);
			_systemLogger.log(Level.INFO, MODULE, sMethod, "datagram send");
			
//			_listenSocket.receive(oRADIUSPacket);// RH, 20120823, o
			_listenSocket.receive(oRADIUSPacketReceive);// RH, 20120823, n
			
			_systemLogger.log(Level.INFO, MODULE, sMethod, "received response");
//			handleResponse(oRADIUSPacket);// RH, 20120823, o
			handleResponse(oRADIUSPacketReceive);// RH, 20120823, n

			try {
				_listenSocket.close();
			}
			catch (Exception e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception while closing connection with "
						+ "RADIUS server at " + _sRadiusServer + ": ", e);
			}
		}
		catch (Exception e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "error in Radius communication", e); // (154)
			try {
				_listenSocket.close();
			}
			catch (Exception e2) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "exception while closing connection with RADIUS "
						+ " server at " + _sRadiusServer + ": " + e2);
			}
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "exception while authenticating user " + Auxiliary.obfuscate(_sUid)
					+ " with with RADIUS " + "server at " + _sRadiusServer + ": ", e);
			_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
		}

		return _sErrorCode;
	}

	/**
	 * This methods composes a RADIUS <code>access-request</code> packet and sends it to the RADIUS Server. <br>
	 * <br>
	 * 
	 * @param sPassword
	 *            the password
	 * @param oRADIUSPacket
	 *            the radius packet
	 */
//	NOTE rfc2865 obsoletes rfc2138
//	   An Access-Request is now required to contain either a NAS-IP-Address
//	   or NAS-Identifier (or may contain both).
	void composeRequest(String sPassword, DatagramPacket oRADIUSPacket)
	{
		String sMethod = "composeRequest";
		_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + Auxiliary.obfuscate(_sUid));
		try {
			Random randomGenerator;
			byte[] baTempBuffer1, baTempBuffer2, baTempBuffer3;
			byte[] baOutputBuffer;
			int iIndex = 0;

			oRADIUSPacket.setAddress(InetAddress.getByName(_sRadiusServer));
			oRADIUSPacket.setPort(_iPort);

			// 1 byte: access request
			// 1 byte: identifier
			// 2 bytes: length
			// 16 bytes: random seed
			// user attribute: type=01 len=2+uid.length uid
			// password: type=02 len=2+16 hashed pwd
			randomGenerator = new Random();
			randomGenerator.nextBytes(_baRandom);
			_bIdentifier = (byte) randomGenerator.nextInt();

			baOutputBuffer = oRADIUSPacket.getData();
			baOutputBuffer[iIndex++] = ACCESS_REQUEST;
			baOutputBuffer[iIndex++] = _bIdentifier;
			baOutputBuffer[iIndex++] = 0; // hibyte length
			baOutputBuffer[iIndex++] = 0; // lobyte length
			// 16 bytes random ; aka authenticator
			System.arraycopy(_baRandom, 0, baOutputBuffer, iIndex, _baRandom.length);
			iIndex += _baRandom.length;

			baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_USER_NAME;
			baOutputBuffer[iIndex++] = (byte) (_sUid.length() + 2);
			baTempBuffer1 = _sUid.getBytes();
			System.arraycopy(baTempBuffer1, 0, baOutputBuffer, iIndex, _sUid.length());
			iIndex += _sUid.length();

			baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_USER_PASSWORD;
			baOutputBuffer[iIndex++] = (byte) (16 + 2);

			// copy password to baTempBuffer2, pad with zeroes to a length of 16 bytes
			baTempBuffer1 = sPassword.getBytes();	// RH, beware of "default" char set
			baTempBuffer2 = new byte[16];
			for (int i = 0; i < baTempBuffer1.length; i++) {
				baTempBuffer2[i] = baTempBuffer1[i];
			}
			// reset the remaining bytes to 0x00 in baTempBuffer2
			for (int i = baTempBuffer1.length; i < 16; i++) {
				baTempBuffer2[i] = (byte) 0x00;
			}
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "pwd=" + Utils.byteArrayToHexString(baOutputBuffer));

			// compute b1 = MD5(S + RSA) as in rfc2138
			MessageDigest md5Object = MessageDigest.getInstance("MD5");
			md5Object.update(_sSharedSecret.getBytes());
			md5Object.update(_baRandom);
			byte[] baHash = md5Object.digest();

			// compute c1 = p1 xor b1
			for (int i = 0; i < 16; i++) {
				baOutputBuffer[iIndex++] = (byte) (baTempBuffer2[i] ^ baHash[i]);
			}
			// RH, so the password cannot exceed 16 chars !
			
//			_systemLogger.log(Level.INFO, MODULE, sMethod, "hashpwd=" + Utils.byteArrayToHexString(baOutputBuffer));

//			BEGIN NEW 20110705, Bauke
//			NOTE rfc2865 obsoletes rfc2138
			// Add signature according ro rfc 2869
/*			baOutputBuffer[iIndex++] = RADIUS_MESSAGE_AUTHENTICATION_ATTRIBUTE;
			baOutputBuffer[iIndex++] = (byte)(16 + 2);
			for (int i = 0; i < 16; i++) {  // fill with a null signature
				baOutputBuffer[iIndex+i] = (byte)0x00;
			}
			
			// Length now is iIndex+16
			// MD5 hash the complete message and copy over the null signature
//			md5Object.reset();
//			md5Object.update(baOutputBuffer, 0, iIndex+16);
//			baHash = md5Object.digest();

			Mac mac = Mac.getInstance("HmacMD5");
			// RFC 2104, key should be 64 bytes! Padded to the right with 0-bytes.
	        SecretKeySpec key = new SecretKeySpec(_sSharedSecret.getBytes(), "HmacMD5");
	        mac.init(key);
			mac.update(baOutputBuffer, 0, iIndex+16);
	        baHash = mac.doFinal();
			_systemLogger.log(Level.INFO, MODULE, sMethod, "baHash=" + Utils.byteArrayToHexString(baHash));
			
			for (int i = 0; i < 16; i++) {
				baOutputBuffer[iIndex++] = baHash[i];
			}
*/			// END NEW
			
			
			
			// RH, 20110728, set the NAS-Identifier, sn
//			try {
			    InetAddress addr = InetAddress.getLocalHost();

			    // Get IP Address
//			    byte[] ipAddr = addr.getAddress();

			    // Get hostname
			    String hostname = addr.getHostName();
//			} catch (UnknownHostException e) {
//			}

				baOutputBuffer[iIndex++] = RADIUS_ATTRIBUTE_TYPE_NAS_IDENTIFIER;
				baTempBuffer3 = hostname.getBytes();	// RH, beware of "default" char set
				int trimmedLength =  (baTempBuffer3.length > MAXNAS_IDENT_LENGTH) ? MAXNAS_IDENT_LENGTH : baTempBuffer3.length;
				baOutputBuffer[iIndex++] = (byte) (trimmedLength + 2);
				System.arraycopy( baTempBuffer3, 0, baOutputBuffer, iIndex, trimmedLength );	// We want max MAXNAS_IDENT_LENGTH chars 
				iIndex +=  trimmedLength;
				
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "hostname (as hexstring, only using first  " + MAXNAS_IDENT_LENGTH + " bytes as nas-identifier): " + Utils.byteArrayToHexString( baTempBuffer3 ));

				// RH, 20110728, set the NAS-Identifier, en
			
			
			// store actual length
			baOutputBuffer[2] = (byte) (iIndex >> 8);
			baOutputBuffer[3] = (byte) (iIndex & 0x00ff);
			
			// Cut off the buffer
			byte[] newBuf = new byte[iIndex];
			System.arraycopy(baOutputBuffer, 0, newBuf, 0, iIndex);
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "len="+iIndex+ " request=" + Utils.byteArrayToHexString(newBuf));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "data len="+iIndex);
			
			oRADIUSPacket.setData(newBuf);
			_sErrorCode = Errors.ERROR_RADIUS_SUCCESS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
		}
	}

	/**
	 * This methods handles the response comming from the Radius Server.
	 * 
	 * @param oRADIUSPacket
	 *            the radius packet
	 */
	void handleResponse(DatagramPacket oRADIUSPacket)
	{
		byte[] baAuthenticator;
		byte[] baAttributes;
		byte[] baHash;
		int iLength;
		int iResponseBufferIndex;

		String sMethod = "handleResponse";
		_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;

		_systemLogger.log(Level.INFO, MODULE, sMethod, "uid=" + Auxiliary.obfuscate(_sUid));
		try {
			byte[] baResponseBuffer = oRADIUSPacket.getData();
//			_systemLogger.log(Level.FINEST, MODULE, sMethod, "response=" + Utils.byteArrayToHexString(baResponseBuffer));
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Received response");

			// check code
			iResponseBufferIndex = 0;
			if (baResponseBuffer[iResponseBufferIndex++] != ACCESS_ACCEPT) {
				StringBuffer sbFine = new StringBuffer("RADIUS returned ACCESS DENIED for user: ");
				sbFine.append(Auxiliary.obfuscate(_sUid));
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFine.toString());
				_sErrorCode = Errors.ERROR_RADIUS_ACCESS_DENIED;
				return;
			}
			// check identifier
			if (baResponseBuffer[iResponseBufferIndex++] != _bIdentifier) {
				StringBuffer sbFine = new StringBuffer("RADIUS Identifier mismatch for user: ");
				sbFine.append(Auxiliary.obfuscate(_sUid));
				_systemLogger.log(Level.WARNING, MODULE, sMethod, sbFine.toString());
				_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
				return;
			}

			// length
			iLength = ((baResponseBuffer[2] & 255) * 256) + (baResponseBuffer[3] & 255);
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "len="+iLength);
			// skip length
			iResponseBufferIndex += 2;

			// copy authenticator field
			baAuthenticator = new byte[16];
			System.arraycopy(baResponseBuffer, iResponseBufferIndex, baAuthenticator, 0, 16);

			// copy attributes field
			// attributeslength = totallength - header - authenticatorlength
			baAttributes = new byte[iLength - 4 - 16];
			System.arraycopy(baResponseBuffer, 20, baAttributes, 0, baAttributes.length);

			// verify authenticity
			MessageDigest md5Object = MessageDigest.getInstance("MD5");
			md5Object.update(ACCESS_ACCEPT);
			md5Object.update(_bIdentifier);
			md5Object.update(baResponseBuffer[2]);
			md5Object.update(baResponseBuffer[3]);
			md5Object.update(_baRandom);
			md5Object.update(baAttributes);
			md5Object.update(_sSharedSecret.getBytes());
			baHash = md5Object.digest();

//			_systemLogger.log(Level.INFO, MODULE, sMethod, "authenticator="+Utils.byteArrayToHexString(baResponseBuffer)+
//							" hash="+Utils.byteArrayToHexString(baHash));
			for (int i = 0; i < 16; i++) {
				if (baAuthenticator[i] != baHash[i]) {
					StringBuffer sbTemp = new StringBuffer("RADIUS Authenticator mismatch Server\r\n");
					sbTemp.append("Authenticator: ");
					sbTemp.append(Utils.byteArrayToHexString(baAuthenticator));
					sbTemp.append("\r\n Computed Authenticator: ");
					sbTemp.append(Utils.byteArrayToHexString(baHash));

					_systemLogger.log(Level.FINE, MODULE, sMethod, sbTemp.toString());
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "RADIUS Authenticator mismatch");
					_sErrorCode = Errors.ERROR_RADIUS_COULD_NOT_AUTHENTICATE_USER;
					return;
				}
			}
			_sErrorCode = Errors.ERROR_RADIUS_SUCCESS;
		}
		catch (Exception e) {
			_systemLogger.log(Level.SEVERE, MODULE, sMethod, "INTERNAL ERROR", e);
			_sErrorCode = Errors.ERROR_RADIUS_INTERNAL_ERROR;
		}
		_systemLogger.log(Level.INFO, MODULE, sMethod, "_sErrorCode="+_sErrorCode);
	}
}
