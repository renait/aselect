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
 * $Id: Base64.java,v 1.4 2006/05/03 09:31:06 tom Exp $ 
 * 
 * Changelog:
 * $Log: Base64.java,v $
 * Revision 1.4  2006/05/03 09:31:06  tom
 * Removed Javadoc version
 *
 * Revision 1.3  2005/09/08 12:47:11  erwin
 * Changed version number to 1.4.2
 *
 * Revision 1.2  2005/04/07 08:32:52  remco
 * base64 decoder couldn't handle empty strings
 *
 * Revision 1.1  2005/02/22 12:03:29  martijn
 * moved org.aselect.utils to org.aselect.system.utils
 *
 * Revision 1.2  2005/01/28 10:09:44  ali
 * Javadoc toegevoegd en kleine code cleanup acties.
 *
 */
package org.aselect.system.utils;

// TODO: Auto-generated Javadoc
/**
 * RFC 2045 compliant Base64 Codec. <br>
 * <br>
 * <b>Description:</b><br>
 * This class implements a Base64 codec engine according to RFC 2045. This class should not be called directly. <br>
 * <br>
 * <b>Concurrency issues:</b> <br>
 * None. <br>
 * 
 * @author Alfa & Ariss
 */
public class Base64
{
	
	/**
	 * Encodes an array of bytes into Base64 format. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method encodes a byte array taking 3 bytes with each run until the whole input is encoded. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param xData
	 *            Input byte array.
	 * @return String containing the corresponding Base64 encoding of <code>xInput</code>.
	 */
	public static String encode(byte[] xData)
	{
		StringBuffer xEncoded = new StringBuffer();
		for (int i = 0; i < xData.length; i += 3) {
			xEncoded.append(encodeBlock(xData, i));
		}
		return xEncoded.toString();
	}

	/**
	 * Encodes a block of 3 bytes. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param xData
	 *            input block
	 * @param xOffset
	 *            current offset
	 * @return Encoded String.
	 */
	protected static char[] encodeBlock(byte[] xData, int xOffset)
	{
		int xBlock = 0;
		int xSlack = xData.length - xOffset - 1;
		int xEnd = (xSlack >= 2) ? 2 : xSlack;

		for (int i = 0; i <= xEnd; i++) {
			byte xByte = xData[xOffset + i];
			int xNoSign = (xByte < 0) ? xByte + 256 : xByte;
			xBlock += xNoSign << (8 * (2 - i));
		}

		char[] xEncodedBuffer = new char[4];
		for (int i = 0; i < 4; i++) {
			int x6Bits = (xBlock >>> (6 * (3 - i))) & 0x3f;
			xEncodedBuffer[i] = getChar(x6Bits);
		}
		if (xSlack < 1)
			xEncodedBuffer[2] = '=';
		if (xSlack < 2)
			xEncodedBuffer[3] = '=';
		return xEncodedBuffer;
	}

	/**
	 * Returns the carachter in the 6 lower bits of the input int. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * Returns the character represented by the lower 6 bits or one of the trailing character as specified in RFC 2045. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param x6Bits
	 *            Input character.
	 * @return Encoded char according to RFC 2045.
	 */
	protected static char getChar(int x6Bits)
	{
		if (x6Bits >= 0 && x6Bits <= 25)
			return (char) ('A' + x6Bits);

		if (x6Bits >= 26 && x6Bits <= 51)
			return (char) ('a' + (x6Bits - 26));

		if (x6Bits >= 52 && x6Bits <= 61)
			return (char) ('0' + (x6Bits - 52));

		if (x6Bits == 62)
			return '+';

		if (x6Bits == 63)
			return '/';

		return '?';
	}

	/**
	 * This method decodes a Base64 respresentation of a byte array back to a byte array.
	 * 
	 * @param xEncodedString
	 *            the x encoded string
	 * @return the byte[]
	 */
	/**
	 * Decodes a Base64 encoded String. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method decodes an RFC 2045 Base64 encoded String. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param xEncodedString
	 *            Base64 encoded String.
	 * @return byte array contining the decoded bytes.
	 */
	public static byte[] decode(String xEncodedString)
	{
		int xPad = 0;

		if (xEncodedString.equals(""))
			return new byte[0];

		for (int i = xEncodedString.length() - 1; xEncodedString.charAt(i) == '='; i--)
			xPad++;

		int xLength = xEncodedString.length() * 6 / 8 - xPad;
		byte[] xData = new byte[xLength];
		int xIndex = 0;

		for (int i = 0; i < xEncodedString.length(); i += 4) {
			int xBlock = (getValue(xEncodedString.charAt(i)) << 18) + (getValue(xEncodedString.charAt(i + 1)) << 12)
					+ (getValue(xEncodedString.charAt(i + 2)) << 6) + (getValue(xEncodedString.charAt(i + 3)));

			for (int j = 0; j < 3 && xIndex + j < xData.length; j++) {
				xData[xIndex + j] = (byte) ((xBlock >> (8 * (2 - j))) & 0xff);
			}
			xIndex += 3;
		}
		return xData;
	}

	/**
	 * Decodes the value of a Base64 encoded character. <br>
	 * <br>
	 * <b>Description:</b> <br>
	 * This method returns the value of a Base64 encoded character. <br>
	 * <br>
	 * <b>Concurrency issues:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Preconditions:</b> <br>
	 * None. <br>
	 * <br>
	 * <b>Postconditions:</b> <br>
	 * None. <br>
	 * 
	 * @param xChar
	 *            Base64 encoded character.
	 * @return Decoded value or -1 if non-Base64 input charachter.
	 */
	protected static int getValue(char xChar)
	{
		if (xChar >= 'A' && xChar <= 'Z')
			return xChar - 'A';

		if (xChar >= 'a' && xChar <= 'z')
			return xChar - 'a' + 26;

		if (xChar >= '0' && xChar <= '9')
			return xChar - '0' + 52;

		if (xChar == '+')
			return 62;

		if (xChar == '/')
			return 63;

		if (xChar == '=')
			return 0;

		return -1;
	}
}
