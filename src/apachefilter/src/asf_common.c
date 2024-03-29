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
 *
// Marked Parts:
// Author: Bauke Hiemstra - www.anoigo.nl
//
// 20130629, Bauke, corrected indentation and solved compilation warnings on 64 bits
//   NOTE tab stops have to be set to 4 positions.
//   In vi use ":set tabstop=4"
 */
 
/* asf_common.c
 *
 * Functions shared by the Apache 1.3 and 2.0 filters.
 */

/* 
 * $Id: asf_common.c,v 1.10 2006/05/01 12:37:59 remco Exp $
 * 
 * Changelog:
 * $Log: asf_common.c,v $
 * Revision 1.10  2006/05/01 12:37:59  remco
 * Fixed bug that could cause the filter to generate an incorrect query string in the authcomplete redirect url
 *
 * Revision 1.9  2006/04/14 08:15:17  jeroen
 * added license
 *
 * Revision 1.8  2006/03/01 08:56:39  remco
 * Added option "url=..." in aselect_filter_add_secure_app, which forces the Server and filter to redirect to a fixed url after a succesful authentication.
 *
 * Revision 1.7  2005/09/12 13:50:49  remco
 * Added authorization support (untested)
 *
 * Revision 1.6  2005/05/23 15:40:42  leon
 * html logout button changed in logout bar template
 *
 * Revision 1.4  2005/05/04 08:55:00  remco
 * - Added application config directive "extra="
 * - Filter now logs if incoming message from Agent is too large
 *
 * Revision 1.3  2005/05/02 09:21:15  remco
 * - Changed parsing of application options
 * - Added 3 new application options: uid, language, and country
 * - Changed internal application storage
 * - Fixed handling of errors: some errors incorrectly resulted in re-authentication. Error response is now the same as in the ISAPI filter.
 *
 * Revision 1.2  2005/04/19 14:27:57  remco
 * Resolved bug in aselect_show_bar when no arguments were present
 *
 * Revision 1.1  2005/04/13 09:44:29  remco
 * RC1 of integrated apache 1.3 & 2.0 filter
 *
 */

#include "asf_common.h"

//	#ifdef ASELECT_FILTER_TRACE
//
// Bauke: Added fall back when logfile cannot be created
//
// NOTE: Best to create this file in advance, the owner must be the use running the Apache filter
// During initialization "root" is running the filter, changes during operation
// RM_11_01
//       
static char *LogfileName = ASELECT_FILTER_TRACE_FILE;

//  static void aselect_filter_removeUnwantedCharacters2(char *args)    // RH, 20200925,o
void aselect_filter_removeUnwantedCharacters2(char *args)    // RH, 20200925,n
{
    int stop, len;
    char *p, *q;

    for (stop=0 ; !stop; ) {
		len = strlen(args);
//		aselect_filter_url_decode(args);
		TRACE1("Loop: %s", (args)? args: "NULL");
		if (len == strlen(args)) {
			for (p = q = args; *q; ) {
				// 20100521, Bauke: " added to the list below
				if (*q == '\r' || *q == '\n' || *q == '>' || *q == '<' || *q == '"')
					q++;
				else
                                    if ( (*q == '%') &&
                                            ( ((*(q+1) == '0') && ( *(q+2) == 'A' || *(q+2) == 'a' || *(q+2) == 'D' || *(q+2) == 'd' ) ) ||
                                                ((*(q+1) == '3') && ( *(q+2) == 'C' || *(q+2) == 'c' || *(q+2) == 'E' || *(q+2) == 'e' )) ||
                                                ((*(q+1) == '2') && ( *(q+2) == '2')) )
                                       )
                                        q = q+3;
                                    else
					*p++ = *q++;
			}
			*p++ = '\0';
			stop = 1;
		}
    }
}



void aselect_filter_trace_logfilename(char *filename)
{
    if (filename)
	LogfileName = filename;
}

//
// Trace function, traces the time, process id and the logstring
//
void aselect_filter_trace_not_used(const char *fmt, ...)
{
    char    *pcTime;
    time_t  t;
    FILE    *f;
    va_list vlist;
    char *fallBack;

    //chmod(LogfileName, S_IROTH | S_IWOTH);
    //chmod(LogfileName, S_IREAD | S_IWRITE);
    f = fopen(LogfileName, "a+");
    if (!f) {
    	fallBack = "/tmp/aselect_filter.log"; // fall back
		f = fopen(fallBack, "a+");
    }
    if (f) {
        time(&t);
        pcTime = ctime(&t);
        *(pcTime + strlen(pcTime) - 1) = '\0';
        fprintf(f, "%s [%d] ", pcTime, getpid());
        va_start(vlist, fmt);
        vfprintf(f, fmt, vlist);
        va_end(vlist);
        putc('\n', f);
        fflush(f);
        fclose(f);
    }
}

void aselect_filter_trace2(const char *filename, int line, const char *fmt, ...)
{
    char    *pcTime;
    time_t  t;
    FILE    *f;
    va_list vlist;
    char *fallBack;

    //chmod(LogfileName, S_IROTH | S_IWOTH);
    f = fopen(LogfileName, "a+");
    if (!f) {
    	fallBack = "/tmp/aselect_filter.log";
		f = fopen(fallBack, "a+");
    }
    if (f) {
        time(&t);
        pcTime = ctime(&t);
        *(pcTime + strlen(pcTime) - 1) = '\0';
        fprintf(f, "%s [%s:%d / %d] ", pcTime, filename, line, getpid());
        va_start(vlist, fmt);
        vfprintf(f, fmt, vlist);
        va_end(vlist);
        putc('\n', f);
        fflush(f);
        fclose(f);
    }
}
//	#endif

//
// Prints out the contents of a table if tracing is enabled
// data is a pointer to user data
//
static int aselect_filter_print_table_item(void *data, const char *key, const char *value)
{
	TRACE2("+ %s: %s", key, value);
    return 1;  // continue with other entries
}

// Log contents of a table, e.g. the header tables
void aselect_filter_print_table(request_rec *r, apr_table_t *t, char *hdr_text)
{
	TRACE1("TABLE %s", hdr_text);
	apr_table_do(aselect_filter_print_table_item, r, t, NULL);
}

// Convert a hex-formatted string into an array of bytes
char *aselect_filter_hex_to_bytes(pool *pPool, char *pcString, int *ccBytes)
{
    int i, length;
    char pcByte[4] = {0, 0, 0, 0};
    char *pcBytes, *pcEnd;

    length = strlen(pcString) >> 1;
    if ((pcBytes = (char *)ap_palloc(pPool, strlen(pcString) >> 1))) {
        for (i=0; *pcString; i++) {
            pcByte[0] = pcString[0];
            pcByte[1] = pcString[1];
            pcBytes[i] = (char)strtol(pcByte, &pcEnd, 16);
            pcString += 2;
        }
    }
    (*ccBytes) = length;
    return pcBytes;
}

// Convert a byte buffer into a hex string. The result is stored
// in lpResult, which must be big enough to hold the result (length*2+1 characters)
void aselect_filter_bytes_to_hex(const unsigned char *pcBytes, size_t length, char *pcResult)
{
    int i;
    char szTemp[4];

    for (i=0; (size_t)i < length; i++) {
        sprintf(szTemp, "%02X", pcBytes[i]);
        memcpy(pcResult+(i*2), szTemp, 2);
    }
    pcResult[length*2] = 0;
}

//
// Reads in a 2 byte error string and converts it to an int
//
int aselect_filter_get_error(pool *pPool, char *pcError)
{
    int iError = ASELECT_FILTER_ERROR_INTERNAL;
    char *pcTemp;
    char pcTemp2[5];
    char *pcTemp3;
    int iLength;

    if ((pcTemp = strstr(pcError, "result_code="))) {
        // copy 4 bytes of error code
        memcpy(pcTemp2, pcTemp+12, 4);
        pcTemp2[4] = 0;
        
        TRACE1("aselect_filter_get_error: error: %s", pcTemp2);
        if ((pcTemp3 = aselect_filter_hex_to_bytes(pPool, pcTemp2, &iLength))) {
            iError = pcTemp3[0];
            iError <<= 8;
            iError |= pcTemp3[1];
            //TRACE2("aselect_filter_get_error: length=%d, error=%d", iLength, iError);
        }
    }
    return iError;
}

// Replace pcTag in pcSource with pcValue
char *aselect_filter_replace_tag(pool *pPool, char *pcTag, char *pcValue, char *pcSource)
{
    char    *pcDest = NULL;
    int     ccDest;
    char    *pcTemp;
    int     ccTag;
    int     i;

    //
    // Calculate new html size
    // size of template - length of tag + length of url + 1 for "\0"
    //
    ccTag = strlen(pcTag);
    ccDest = strlen(pcSource) - ccTag + strlen(pcValue) + 1;

    if ((pcDest = (char *) (ap_palloc(pPool, ccDest)))) {
        //
        // Copy part of the source up till the tag
        //
        if ((pcTemp = strstr(pcSource, pcTag))) {
            i = pcTemp - pcSource;
            memcpy(pcDest, pcSource, i);
            memcpy(pcDest + i, pcValue, strlen(pcValue));
            memcpy(pcDest + i + strlen(pcValue), pcSource + i + ccTag, strlen(pcSource) - i);
            *(pcDest + ccDest) = '\0';
        }
    }
    else {
        pcDest = NULL;
    }
    return pcDest;
}

//
// strips any parameters from the string
// effectivly deletes everything after the ?
//
char *aselect_filter_strip_param(pool *pPool, char * pcASelectServerURL)
{
    char *pcReturn = NULL;
    char *pcTemp;

    if ((pcTemp = strstr(pcASelectServerURL , "?")))
        pcReturn = ap_pstrndup(pPool, pcASelectServerURL, strlen(pcASelectServerURL) - strlen(pcTemp));
    else
        pcReturn = ap_pstrdup(pPool, pcASelectServerURL);

    return pcReturn;
}

//
// Loops until enough data is received or a "\r" is received
// returns number of bytes received, returns -1 if error has occured
//
char *aselect_filter_receive_msg(pool *pPool, int sd)  //, char *pcReceiveMsg, int ccReceiveMsg)
{
#define INIT_BUFSIZE 12300
#define BUF_NEED 800
#define BUF_INCR 6001
	char *pReceiveBuf = 0, *pLF;
	int iReadSofar = 0, iBufSize = INIT_BUFSIZE;
    int iReceived = 0;
    //int iRemaining = ccReceiveMsg;
    char *pMsg;
    static int count = 1000;

    TRACE2("RCV[%d] receive_msg: alloc=%d", ++count, iBufSize);
	//
    // Receive data while there is data or till we find a "\r"
	//
    pReceiveBuf = (char *)ap_palloc(pPool, iBufSize+1); // plus null-byte
	*pReceiveBuf = '\0';
	for ( ; ; ) {
		if ((iBufSize - iReadSofar) <= BUF_NEED) {  // enlarge the buffer
			TRACE3("RCV[%d] receive_msg: realloc=%d sofar=%d", count, iBufSize+BUF_INCR, iReadSofar);
			char *pNewBuf = (char *)ap_palloc(pPool, iBufSize+BUF_INCR+1);
			iBufSize += BUF_INCR;
			strncpy(pNewBuf, pReceiveBuf, iReadSofar+1);
			pReceiveBuf = pNewBuf;
		}
		// Read new data
		pMsg = pReceiveBuf+iReadSofar;  // put new data here
		iReceived = recv(sd, pMsg, iBufSize-iReadSofar, 0);
        if (iReceived <= 0)
            break;
		*(pMsg+iReceived) = '\0';
        pLF = strchr(pMsg, '\r');
        if (pLF) { // cut off the data and finish
			iReceived = pLF - pMsg;
			*(pMsg+iReceived) = '\0';
			iReadSofar += iReceived;
            break;
        }
		iReadSofar += iReceived;
	}
    TRACE2("RCV[%d] receive_msg: read=%d", count, iReadSofar);
	return (iReceived>=0)? pReceiveBuf: NULL;

	/* 20151026, Bauke: replaced following code
    // Receive data while there is data or till we find a "\r"
    while ((iRemaining > 0) && ((iReceived = recv(sd, pMsg, iRemaining, 0)) > 0)) {
        if (iReceived == -1)
            break;
        if ((pLF = strchr(pMsg, '\r'))) {
            iRemaining -= (pLF-pMsg);
            break;
        }
        iRemaining -= iReceived;
        pMsg += iReceived;
    }

    if (iReceived != -1)
        iReceived = ccReceiveMsg - iRemaining;
        
    TRACE2("RCV[%d] aselect_filter_receive_msg: recv=%d", cnt, iReceived);
    return iReceived;
	*/
}

//
// Connect to ASelect Agent send request and wait for response
//
char *aselect_filter_send_request(server_rec *pServer, pool *pPool, char *pcASAIP, int iASAPort, char *pcSendMessage, int ccSendMessage, TIMER_DATA *pt, int toAgent)
{
	int sd;
	struct sockaddr_in pin;
	struct hostent *hp;
	int  timeout;
	//char pcReceiveMessage[ASELECT_FILTER_MAX_RECV+1];
	//int  ccReceiveMessage;
	char *pcResponse = NULL;
	static int count = 0;
	int cnt = ++count;

    char *sDest = (toAgent)? "AGENT": "LbSensor";
    TRACE3("To%s[%d] aselect_filter_send_request { [%s]", sDest, cnt, pcSendMessage);
    //memset(pcReceiveMessage, 0, ASELECT_FILTER_MAX_RECV);

    // Retrieve the host information
    if ((hp = gethostbyname(pcASAIP)) != NULL) { // Initialize the connection information
		memset(&pin, 0, sizeof(pin));
		pin.sin_family = AF_INET;
		pin.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
		pin.sin_port = htons(iASAPort); 
    }
    else { // gethostbyname failed, so try IP address
		memset(&pin, 0, sizeof(pin));
		pin.sin_family = AF_INET;
		pin.sin_addr.s_addr = inet_addr(pcASAIP);
		pin.sin_port = htons(iASAPort);
    }

    // Create a socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
        // Connect using connection information
        if (connect(sd,(struct sockaddr *) &pin, sizeof(pin)) != -1) {
            // Set the socket timeouts on the send and receive
            // SO_SNDTIMEO - send timeout
            // SO_RCVTIMEO - receive timeout
            timeout = ASELECT_FILTER_SOCKET_TIME_OUT;
            if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char*) &timeout, sizeof(timeout)) != -1) {
                // Could not connect to specified address and port
                TRACE1("could not set socket send timeout (%d)", errno);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pServer,
						"ASELECT_FILTER:: could not set socket send timeout (%d)", errno);
            }

            if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout)) != -1) {
                TRACE1("could not set socket receive timeout (%d)", errno);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pServer,
						"ASELECT_FILTER:: could not set socket receive timeout (%d)", errno);
            }

            // Check if information is not too large for message
            if ((ccSendMessage + 1) < ASELECT_FILTER_MAX_MSG) {
                // Send the message, PAUSE TIMER
				if (pt != NULL) timer_pause(pt);
				if (send(sd, (void *)pcSendMessage, (ccSendMessage), 0) > 0) { // 20111116 don't send null-byte
					// ====

					// Message has been sent, now wait for response
					// 20151026, Bauke: changed receive_msg routine
					pcResponse = aselect_filter_receive_msg(pPool, sd);  // , pcReceiveMessage, sizeof(pcReceiveMessage)-1);
					if (pcResponse == NULL) {  // Could not receive data
						TRACE1("error while receiving data (%d)", errno);
						ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: error while receiving data (%d)", errno);
					}

					// 20151026: ccReceiveMessage = aselect_filter_receive_msg(sd, pcReceiveMessage, sizeof(pcReceiveMessage)-1);
					/*
					if (ccReceiveMessage > 0) {
						if (ccReceiveMessage >= sizeof(pcReceiveMessage)-1) {
							// Received message too large
							TRACE1("received message too large (%d)", ccReceiveMessage);
							ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: received message was too large");
						}
						else {
							pcResponse = ap_pstrndup(pPool, pcReceiveMessage, ccReceiveMessage+1);  // 20111110 added +1
							*(pcResponse + ccReceiveMessage) = '\0';
						}
					}
					else { // Could not receive data
						TRACE1("error while receiving data (%d)", errno);
						ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: error while receiving data (%d)", errno);
					}
					*/

					// ====
				}
				else { // Could not send data
					TRACE1("error while sending data (%d)", errno);
					ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: error while sending data (%d)", errno);
				}
				// RESUME TIMER
				if (pt != NULL) timer_resume(pt);
            }
            else { // Message is too large for sending
                TRACE("Message is too large for sending");
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: message is too large for sending");
            }
        } // connect 
        else { // Could not connect to specified address and port
            TRACE4("Could not connect to %s at %s:%d (%d)", sDest, pcASAIP, iASAPort, errno);
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer,
						"ASELECT_FILTER:: could not connect to %s at %s:%d (%d)", sDest, pcASAIP, iASAPort, errno);
        }
        close(sd);
    } // socket
    else { // Could not create socket
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pServer, "ASELECT_FILTER:: could not create socket (%d)", errno);
    }
    TRACE3("} From%s[%d] aselect_filter_send_request, response=[%s]", sDest, cnt, pcResponse?pcResponse:"NULL");
    return pcResponse;
}

//
// Extract a parameter value from a list of <key>=<value> pairs seperated by a <delimiter>
// The <delimiter> can be followed by a space.
//
char *aselect_filter_get_param(pool *pPool, char *pcArgs, char *pcKey, char *pcDelimiter, int bUrlDecode)
{
	return aselect_filter_get_param_multi(pPool, pcArgs, pcKey, pcDelimiter, bUrlDecode, NULL);
}

char *aselect_filter_get_param_multi(pool *pPool, char *pcArgs, char *pcKey, char *pcDelimiter, int bUrlDecode, int *pSearchPos)
{
    char *pcTemp = NULL, *pcTemp2, *pcValue = NULL;
    int lenValue = 0;
	int first = 1;
	int multiValued = 0;
	int searchPos = (pSearchPos)? *pSearchPos: 0;
    char *p, *pcSearch;

    //TRACE2("aselect_filter_get_param: %s args=%.60s", pcKey, pcArgs);
    if (!pcArgs) {
		TRACE1("get_param: %s - No arguments given", pcKey);
		return NULL;
	}

	// Bauke: example args: my_uid=9876&uid2=0000&uid=1234&...
	//        get parameter "uid=" must result in: 1234
	// NOTE: Delimiter is a single character, but in pcArgs it can be followed by a space!
	pcSearch = (char*)ap_palloc(pPool, strlen(pcKey)+10);
	sprintf(pcSearch, "%s=", pcKey);

	for (p = pcArgs+searchPos; p != NULL; p = pcTemp+1) {
		pcTemp = strstr(p, pcSearch);
		if (!pcTemp && first) {  // try multi-valued as well
			sprintf(pcSearch, (bUrlDecode)? "%s%%5B%%5D=": "%s[]", pcKey);
			pcTemp = strstr(p, pcSearch);  // and search again
			if (pcTemp)  // found multi-valued
				multiValued = 1;
			first = 0; // switch only once to multi-value search
		}
		if (!pcTemp)
			break;
		TRACE3("get_param: search=%s pcTemp=%s prev_char=%c", pcSearch, pcTemp, (pcTemp==pcArgs)? '#': *(pcTemp-1));
		//TRACE3("get_param: %d %d %d", (pcTemp==pcArgs), *(pcTemp-1) == *pcDelimiter, *(pcTemp-1) == ' ');
		if (pcTemp==pcArgs || *(pcTemp-1) == *pcDelimiter || *(pcTemp-1) == ' ') {
			// would be even better if we test delimiter presence before space
			break;
		}
	}

	if (pcTemp) {  // found <key>=
		// Update pointer to point to parameter data 
		pcTemp = pcTemp + strlen(pcSearch);
		//TRACE1("get_param: value=%.60s", pcTemp);

		// Found the query parameter attribute
		searchPos = pcTemp-pcArgs;
		pcTemp2 = strstr(pcTemp, pcDelimiter);
		if (pcTemp2) {
			lenValue = pcTemp2 - pcTemp;
			searchPos += (lenValue+1);
		}
		else {
			lenValue = strlen(pcTemp);
			searchPos += lenValue;
		}

		// Stop iterating for single-valued attributes
		if (pSearchPos)
			*pSearchPos = (multiValued==0)? -1: searchPos;

		//TRACE3("get_param: value=%.*s len=%d", lenValue, pcTemp, lenValue);
		if (lenValue >= 0) {
			pcValue = ap_pstrndup(pPool, pcTemp, lenValue+1);
			if (pcValue) {
				*(pcValue + lenValue) = '\0';
				if (bUrlDecode)
					aselect_filter_url_decode(pcValue);
			}
			else { // Not enough memory, Set error
				pcValue = NULL;
			}
		}
		else { // Parameter value is empty
		}
	}
	// else not found at all

	if (pcValue == NULL) {
		TRACE2("get_param: %s=NULL multi=%d", pcKey, multiValued);
	}
	else {
		TRACE4("get_param: %s=%.60s%s multi=%d", pcKey, pcValue, (strlen(pcValue)>60)? "...": "", multiValued);
	}
    return pcValue;
}

/**
 * Encode a string as application/x-www-form-urlencoded.
 * The result is returned in a newly allocated string.
 */
char *aselect_filter_url_encode(pool *pPool, const char *pszValue)
{
    static char *_safe = ".-*_";
    char szHex[4+4];
    int len, cnt=0;
    char *s, *result;

    //TRACE1("aselect_filter_url_encode 1: [%s]", pszValue);
    // Calculate required length
    len = 0;
    for (s=(char *)pszValue; *s; ++s) {
        if (isalnum(*s) || (strchr(_safe, *s) != NULL) || (*s == ' '))
            ++len;
        else
            len += 3;
    }

    result = s = (char *)ap_palloc(pPool, len+1+10);
    for (; *pszValue; ++pszValue) {
		if ((unsigned char)*pszValue >= 0x80) // leave 8-bit alone
			*(s++) = *pszValue;
        else if (isalnum(*pszValue) || (strchr(_safe, *pszValue) != NULL)) {
            // no change
            *(s++) = *pszValue;
        }
        else if (*pszValue == ' ') {
            // convert space to +
            *(s++) = '+';
			cnt++;
        }
        else {
            // convert to %xx
            sprintf(szHex, "%02x", *pszValue);
            *(s++) = '%';
            *(s++) = szHex[0];
            *(s++) = szHex[1];
			cnt++;
        }
    }
    *s = 0;
    //TRACE2("aselect_filter_url_encode 2: [%s] cnt=%d", result, cnt);
    return result;
}

/**
 * Decode an URL encoded string
 */
int aselect_filter_url_decode(char *pszValue)
{
    static char *_hexchars = "0123456789abcdef";
    char *nh, *nl;
	//char *begin = pszValue;
    int v, cnt=0;

    //TRACE1("aselect_filter_url_decode 1: [%s]", pszValue);
    for (; *pszValue; ++pszValue) {
        if (*pszValue == '+') {
            *pszValue = ' '; cnt++;
		}
        else if (*pszValue == '%') {
            // decode %xx character
            nh = strchr(_hexchars, tolower(pszValue[1]));
            nl = strchr(_hexchars, tolower(pszValue[2]));
            if (nl == NULL || nh == NULL)
                return FALSE;
            v = (nl-_hexchars) + ((nh-_hexchars)<<4);
            memmove(pszValue+1, pszValue+3, strlen(pszValue)-1);
            *pszValue = v;
			cnt++;
        }
    }
    //TRACE2("aselect_filter_url_decode 2: [%s] cnt=%d", begin, cnt);
    return TRUE;
}

void aselect_filter_add_nocache_headers(table *headers_out)
{
    TRACE("Add no-cache hdrs");
    ap_table_add(headers_out, "Pragma", "no-cache");
    ap_table_add(headers_out, "Cache-Control", "no-cache, no-store, must-revalidate");
    ap_table_add(headers_out, "Expires", "-1");
}

int aselect_filter_gen_error_page(pool *pPool, request_rec *pRequest, int iError, char *pcErrorTemplate)
{
    table   *headers_out = pRequest->headers_out;
    char    *pcErrorHTML, *pcContinueURL;
    char    pcError[256];
    int     iRet;

    TRACE("aselect_filter_gen_error_page");

    iRet = ASELECT_FILTER_ERROR_FAILED;
    pRequest->content_type = "text/html; charset=utf-8";
    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);
    sprintf(pcError, "%x", iError);

    pcErrorHTML = pcErrorTemplate;
    while (pcErrorHTML && (strstr(pcErrorHTML, "[error_code]") != NULL))
	    pcErrorHTML = aselect_filter_replace_tag(pPool, "[error_code]", pcError, pcErrorHTML);

    // Bauke: Added to facilitate a Continue button
    // NOTE: app_url is only available on successful calls
    if (pRequest->parsed_uri.port == 0)
		pcContinueURL = ap_psprintf(pPool, "http://%s/%s", pRequest->hostname, pRequest->parsed_uri.path);
    else
		pcContinueURL = ap_psprintf(pPool, "http://%s:%d/%s", pRequest->hostname, pRequest->parsed_uri.port, pRequest->parsed_uri.path);
    TRACE1("ContinueUrl=%s", pcContinueURL);
    while (pcErrorHTML && (strstr(pcErrorHTML, "[continue_url]") != NULL))
	    pcErrorHTML = aselect_filter_replace_tag(pPool, "[continue_url]", pcContinueURL, pcErrorHTML);
    // end of add

    if (pcErrorHTML) {
		ap_rprintf(pRequest, "%s\n", pcErrorHTML);
		iRet = ASELECT_FILTER_ERROR_OK;
    }
    return iRet;
}

// 20091224, Bauke: prevent repeated addition of the same arguments
// 'urlAndArgs' may contain: request=aselect_show_bar&aselect_app_url=<encoded_url>
// We don't want to repeat that.
static char *constructShowBarURL(pool *pPool, char *urlAndArgs)
{
    char *pcSep;
    char *pcEncodedUrl;
    //char *pcFormat = "request=aselect_show_bar&aselect_app_url=";
    char *pcFormat = "request=aselect_show_bar";

    TRACE1("constructShowBarURL, urlAndArgs=%s", urlAndArgs);
    if (strstr(urlAndArgs, pcFormat) != NULL)
		return urlAndArgs;

    pcSep = (strchr(urlAndArgs, '?')) ? "&" : "?";
    pcEncodedUrl = aselect_filter_url_encode(pPool, urlAndArgs);
    // 20100521, old: urlAndArgs = ap_psprintf(pPool, "%s%s%s%s", urlAndArgs, pcSep, pcFormat, pcEncodedUrl);
    urlAndArgs = ap_psprintf(pPool, "%s%s%s", urlAndArgs, pcSep, pcFormat);
    return urlAndArgs;
}

//
// Generate a client-side (HTML) redirection page.
// This function is used after a succesful "verify_credentials"
//
int aselect_filter_gen_authcomplete_redirect(pool * pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig)
{
    table   *headers_out = pRequest->headers_out;
    int     bArgs;
    char    *pcURI;
    char    *pcURL;
    char    *pcSep;
    char    *pcRedirectURL;
    //char *pcFrameUrl;
    //int bFrameHtml = 0;

    pRequest->content_type = "text/html; charset=utf-8";
    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);
   
    bArgs = (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL && pRequest->args != NULL && *pRequest->args != 0);

    if (*pConfig->pCurrentApp->pcRedirectURL) {
		pcRedirectURL = pConfig->pCurrentApp->pcRedirectURL;
		TRACE4("1.RedirectURL=%s Args=%s bArgs=%d UseBar=%d", pcRedirectURL, pRequest->args, bArgs, pConfig->bUseASelectBar);
		if (bArgs) {
			pcRedirectURL = ap_psprintf(pPool, "%s%s", pcRedirectURL, pRequest->args);
		}
		else {
			pcRedirectURL = pConfig->pCurrentApp->pcRedirectURL;
		}
		if (pConfig->bUseASelectBar) {
			pcRedirectURL = constructShowBarURL(pPool, pcRedirectURL);
			//bFrameHtml = 1;
			TRACE1("2.RedirectURL=%s", pcRedirectURL);
		}
    }
    else {
		TRACE4("1.NoRedirectURL URI=%s Args=%s bArgs=%d UseBar=%d", pRequest->uri, pRequest->args, bArgs, pConfig->bUseASelectBar);
		if (!bArgs)
			pcURI = pRequest->uri;
		else {
			pcURI = ap_psprintf(pPool, "%s%s", pRequest->uri, pRequest->args);
			pcSep = strstr(pcURI, "a-select-server=");
			if (pcSep != NULL) {
				*(pcSep-1) = 0;
				if (strchr(pcURI, '?') == NULL)
					bArgs = FALSE;
			}
		}
		if (pConfig->bUseASelectBar) {
			pcURL = constructShowBarURL(pPool, pcURI);
			// Code below works, but cannot handle refresh page since the url does not contain: request=aselect_show_bar
			//pcFrameUrl = aselect_filter_url_encode(pPool, pcURI);
			//slash = (*pcURI == '/')? "": "/";
			//ap_rprintf(pRequest, ASELECT_LOGOUT_BAR_FRAME, pConfig->pCurrentApp->pcLocation, slash, pcURI);
			//bFrameHtml = 1;
		}
		else
			pcURL = pcURI;
		
		pcRedirectURL = ap_construct_url(pPool, pcURL, pRequest);
		TRACE1("2.NoRedirectURL=%s", pcRedirectURL);
    }

    //if (!bFrameHtml) {
    if (pConfig->bSecureUrl && pcRedirectURL) {    // RH, 20200925, n
        TRACE("aselect_filter_removeUnwantedCharacters2");
        aselect_filter_removeUnwantedCharacters2(pcRedirectURL);
    }       // RH, 20200925, n
    TRACE1("aselect_filter_gen_authcomplete_redirect:: redirecting to: %s", pcRedirectURL);
    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcRedirectURL, pcRedirectURL);
    //}
    return DONE;
}

//
// Set top frame to redirect to a-select-server
//
int aselect_filter_gen_top_redirect(pool *pPool, char *addedSecurity, request_rec *pRequest, char *pcASUrl, char *pcASelectServer, char *pcRID, char *cookiePath)
{
    table   *headers_out = pRequest->headers_out;
    char    *pcRedirectURL;
    char    *pcASelectServerURL;
    char    *pcCookie;

    TRACE4("aselect_filter_gen_top_redirect::%s-%s-%s-%s.", pcASUrl, pcASelectServer, pcRID, cookiePath); 
    pRequest->content_type = "text/html; charset=utf-8";

    // save the aselect-server-url parameter which is need to kill the ticket
    // but first strip any parameters from the url
    // Cookie path should be: pConfig->pCurrentApp->pcLocation
    pcASelectServerURL = aselect_filter_strip_param(pPool, pcASUrl);
//    pcCookie = ap_psprintf(pPool, "aselectserverurl=%s; version=1; path=%s;%s", pcASelectServerURL, cookiePath, addedSecurity);
    pcCookie = ap_psprintf(pPool, "aselectserverurl=%s; path=%s;%s", pcASelectServerURL, cookiePath, addedSecurity);
    ap_table_add(headers_out, "Set-Cookie", pcCookie);
    TRACE1("Set-Cookie: %s", pcCookie);

    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);

    pcRedirectURL = ap_psprintf(pPool, "%s&a-select-server=%s&rid=%s", pcASUrl, pcASelectServer, pcRID);
    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcRedirectURL, pcRedirectURL);

    return DONE;
}

//
// 20110129, Bauke added public apps
//
int XXXaselect_filter_is_public_app(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri)
{
    int i;
    for (i = 0; i < pConfig->iPublicAppCount; i++) {
        TRACE3("aselect_filter_is_public_app::comparing directory(%d):\"%s\" to URI: \"%s\"", 
					i, pConfig->pPublicApps[i], pcUri);
        if (strstr(pcUri, pConfig->pPublicApps[i]) != NULL) {
			TRACE("aselect_filter_is_public_app::match"); 
			return ASELECT_FILTER_ERROR_OK;
        }
    }
    return ASELECT_FILTER_ERROR_FAILED;
}

//
// Checks the config for the URI and if it exists return the corresponding App ID
//
int XXXaselect_filter_verify_directory(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri)
{
    int i;
    for (i = 0; i < pConfig->iAppCount; i++) {
        TRACE4("aselect_filter_verify_directory::comparing directory(%d):\"%s\" to URI: \"%s\", enabled=%d", 
					i, pConfig->pApplications[i].pcLocation, pcUri, pConfig->pApplications[i].bEnabled);
        if (strstr(pcUri, pConfig->pApplications[i].pcLocation) != NULL) {
            if (pConfig->pApplications[i].bEnabled) {
                pConfig->pCurrentApp = &pConfig->pApplications[i];
                i = pConfig->iAppCount;
                return ASELECT_FILTER_ERROR_OK;
            }
            // App found, but protection was disabled
        }
    }
    return ASELECT_FILTER_ERROR_FAILED;
}

// Find the longest regular expression match in a string.
// NOTE: there can be multiple matches.
int longest_re_match(char *pcRegexp, char *pcString)
{
	ap_regex_t regex;
	ap_regmatch_t regpm;
	int retval, offset, i, longest = 0;
	char msgbuf[200];

	// Find all substrings in a string that match the pattern.
	// Compile regular expression.
	retval = ap_regcomp(&regex, pcRegexp, 0);
	if (retval) {
		TRACE1("longest_re_match:: Could not compile regex:%s", pcRegexp);
		return -2;
	}
	/* This call to regexec() finds the first match on the line. */
	retval = ap_regexec(&regex, pcString, 1, &regpm, 0);
	if (retval != 0 && retval != AP_REG_NOMATCH) {
		ap_regerror(retval, &regex, msgbuf, sizeof(msgbuf));
		TRACE1("longest_re_match:: Regex match failed: %s", msgbuf);
		return -2;
	}
	for (i=0, offset=0; i<20 && retval==0; i++) {  /* While matches found. */
		/* Substring found between regpm.rm_so and regpm.rm_eo. */
		TRACE5("longest_re_match:: Match: >%.*s<, %d:%d-%d", regpm.rm_eo-regpm.rm_so,
						pcString+offset+regpm.rm_so, offset, regpm.rm_so, regpm.rm_eo);
		if (regpm.rm_eo-regpm.rm_so > longest)
			longest = regpm.rm_eo-regpm.rm_so;
		offset += regpm.rm_eo;
		if (regpm.rm_eo == 0)  // we need to make progress
			offset++;
		if (offset >= strlen(pcString))  // nothing left
			break;
		/* This call to regexec() finds the next match. */
		retval = ap_regexec(&regex, pcString+offset, 1, &regpm, 0); //AP_REG_NOTBOL);
		if (retval != 0 && retval != AP_REG_NOMATCH) {
			ap_regerror(retval, &regex, msgbuf, sizeof(msgbuf));
			TRACE1("longest_re_match:: Regex match failed: %s", msgbuf);
			return -2;
		}
	}
	ap_regfree(&regex);
	return longest;
}

// Just perform a simple length compare
int longest_cmp_match(char *pcRegexp, char *pcString)
{
	int len = strlen(pcRegexp);
	if (len > 0 && len <= strlen(pcString) && strncmp(pcString, pcRegexp, len) == 0) {  // a match
		return len;
	}
	return -1;
}

/*
 * The cockpit wil use the first 'aselect_filter_add_secure_app' line as default for "protected" apps
    aselect_filter_add_secure_app "/" "app1" "uid=siam_user,language=NL,country=NL"
 * The same holds for public apps:
    aselect_filter_add_public_app "/web/"
    aselect_filter_add_public_app "/html/"
 * Disabled rules will simply be ignored
    aselect_filter_add_secure_app "/" "app1" "disabled,language=NL,country=NL"
*/
//
// Checks the uri to decide whether it's a public or a secure application
//
// int aselect_filter_check_app_uri(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri)
int aselect_filter_check_app_uri(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri, char *pcForceAppid)
{
    int i, len;
	//int uriLen = strlen(pcUri);
    int iBestSec = -1, iBestPub = -1;
    int lenBestSec = 0, lenBestPub = 0;
    int iForcedSec = -1;

    TRACE1("aselect_filter_check_app_uri:: pcForceAppid=%s", pcForceAppid); 

    
    for (i = 0; i < pConfig->iAppCount; i++) {
        TRACE4("aselect_filter_check_app_uri::comparing directory(%d):\"%s\" to URI: \"%s\", enabled=%d", 
					i, pConfig->pApplications[i].pcLocation, pcUri, pConfig->pApplications[i].bEnabled);
        if (pConfig->bUseRegexp == TRUE)
                len = longest_re_match(pConfig->pApplications[i].pcLocation, pcUri);
        else
                len = longest_cmp_match(pConfig->pApplications[i].pcLocation, pcUri);
        TRACE1("aselect_filter_check_app_uri:: secure match_len=%d", len); 
        //len = strlen(pConfig->pApplications[i].pcLocation);
        //if (len > 0 && len <= uriLen && strncmp(pcUri, pConfig->pApplications[i].pcLocation, len) == 0) {  // a match
	if (len > 0) {
            if (pConfig->pApplications[i].bEnabled) {  // skip disabled apps
                            if (len > lenBestSec) {
                                    TRACE2("aselect_filter_check_app_uri::better match secure[%d] len=%d", i, len); 
                                    iBestSec = i;
                                    lenBestSec = len;
                                    iForcedSec = -1;    // RH, 20190715, n  // we found a better application match so reset force_app_id
                                    // RH, 20190712, sn
                                    TRACE1("aselect_filter_check_app_uri:: found a better application match, comparing pcForceAppid with:%s", pConfig->pApplications[i].pcAppId); 
                                    if (pcForceAppid && !strcmp(pConfig->pApplications[i].pcAppId, pcForceAppid)) {
                                        TRACE1("aselect_filter_check_app_uri:: better application match, found app_id for pcForceAppid=%s", pcForceAppid); 
                                        iForcedSec = i;
                                    }
                                    // RH, 20190712, en
//                            } RH, 20190715, o
                            } else if (len == lenBestSec) {// RH, 20190715, sn
                                    TRACE1("aselect_filter_check_app_uri:: found an equal application match, comparing pcForceAppid with:%s", pConfig->pApplications[i].pcAppId); 
                                    if (pcForceAppid && !strcmp(pConfig->pApplications[i].pcAppId, pcForceAppid)) {
                                        TRACE1("aselect_filter_check_app_uri:: equal application match, found app_id for pcForceAppid=%s", pcForceAppid); 
                                        iForcedSec = i;
                                    }
                                    // RH, 20190715, en
                            }
            }
            // else: App found, but the rule was disabled
        }
    }
    for (i = 0; i < pConfig->iPublicAppCount; i++) {
        TRACE3("aselect_filter_check_app_uri::comparing directory[%d]:\"%s\" to URI: \"%s\"", i, pConfig->pPublicApps[i], pcUri);
		if (pConfig->bUseRegexp == TRUE)
			len = longest_re_match(pConfig->pPublicApps[i], pcUri);
		else
			len = longest_cmp_match(pConfig->pPublicApps[i], pcUri);
		TRACE1("aselect_filter_check_app_uri:: public match_len=%d", len); 
		//len = strlen(pConfig->pPublicApps[i]);
		//if (len > 0 && len <= uriLen && strncmp(pcUri, pConfig->pPublicApps[i], len) == 0) {  // a match
		if (len > 0) {
			//if (strncmp(pcUri, pConfig->pPublicApps[i], len) == 0) {
				if (len > lenBestPub) {
					TRACE2("aselect_filter_check_app_uri::better match public[%d] len=%d", i, len); 
					iBestPub = i;
					lenBestPub = len;
				}
			//}
		}
    }
    TRACE4("aselect_filter_check_app_uri::Secure: index=%d len=%d Public: index=%d len=%d", iBestSec, lenBestSec, iBestPub, lenBestPub);
//    if (iBestSec < 0 && iBestPub < 0) {   // RH, 20190715, o
//    if (iBestSec < 0 && iBestPub < 0 || (iBestSec >= 0 && pcForceAppid && iForcedSec < 0)) {   // RH, 20190715, n    // if there is a froce_app_id, there must be a match	 // RH, 20210429, o, more lenient now
    if (iBestSec < 0 && iBestPub < 0) {   // RH, 20210429, n
		return -1;  // no match at all
    }

    if (lenBestSec >= lenBestPub) {
//		pConfig->pCurrentApp = &pConfig->pApplications[iBestSec];    // RH, 20190712, o
		pConfig->pCurrentApp = &pConfig->pApplications[(iForcedSec >= 0 ? iForcedSec : iBestSec)];    // RH, 20190712, n
		return 1;  // secure ok
    }
    return 0;  // public app ok
}

//
// aselect_filter_get_cookie retrieves the request cookie and returns the cookie as a string
//
char *aselect_filter_get_cookie(pool *pPool, table *headers_in, char *pcAttribute)
{
    char        *pcValues;
    char        *pcValue = NULL;

    //TRACE1("GET-Cookie: %s", pcAttribute);
    pcValues = (char *)ap_table_get(headers_in, "Cookie");
    if (pcValues) {
		//TRACE1("GET-Cookie: CookieValues=%s", pcValues);
        pcValue = aselect_filter_get_param(pPool, pcValues, pcAttribute, ";", FALSE);
        if (pcValue) {
            TRACE3("Get-Cookie: %s=%.30s%s", pcAttribute, pcValue, (strlen(pcValue)>30)? "...": "");
        }
        else {
			TRACE1("Get-Cookie: %s not found", pcAttribute);
            pcValue = NULL;
        }
    }
    else {
		TRACE("GET-Cookie: No Cookies");
        pcValue = NULL;
    }
    return pcValue;
}

// RH, 20161107, sn
// aselect_filter_get_header retrieves the request header and returns the value as a string
char *aselect_filter_get_header(pool *pPool, table *headers_in, char *pcHeaderName )
//
//
//char *aselect_filter_get_cookie(pool *pPool, table *headers_in, char *pcAttribute)
{
//    char        *pcValues;
    char        *pcValue = NULL;

    //TRACE1("GET-Cookie: %s", pcAttribute);
    pcValue = (char *)ap_table_get(headers_in, pcHeaderName);
    if (pcValue) {
        TRACE2("HeaderName: %s, found, value: %s", pcHeaderName, pcValue);
//        pcValue = aselect_filter_get_param(pPool, pcValues, pcAttribute, ";", FALSE);
//        if (pcValue) {
//            TRACE3("Get-Cookie: %s=%.30s%s", pcAttribute, pcValue, (strlen(pcValue)>30)? "...": "");
//        }
//        else {
//			TRACE1("Get-Cookie: %s not found", pcAttribute);
//            pcValue = NULL;
//        }
    }
    else {
	TRACE1("HeaderName: %s, not found", pcHeaderName);
        pcValue = NULL;
    }
    return pcValue;
}
// RH, 20161107, en



int aselect_filter_show_barhtml(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig, char *pcASelectAppURL)
{
    table *headers_out = pRequest->headers_out;
    char *slash;

    // Expect /?apparg=bla in url
    TRACE2("aselect_filter_show_barhtml: loc=%s url=%s", pConfig->pCurrentApp->pcLocation, pcASelectAppURL);
    pRequest->content_type = "text/html; charset=utf-8";
    aselect_filter_add_nocache_headers(headers_out);

    ap_send_http_header(pRequest);
    slash = (*pcASelectAppURL == '/')? "": "/";
    ap_rprintf(pRequest, ASELECT_LOGOUT_BAR_FRAME, pConfig->pCurrentApp->pcLocation, slash, pcASelectAppURL);
    return DONE;
}

/*
 * Decode a base64-encoded string into a byte array (allocated
 * by this function).
 * Returns the decoded byte array, or NULL on error
 */
char *aselect_filter_base64_decode(pool *pPool, const char *pszValue)
{
    static const char *_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *szDest;
    int iDest, iDestCount;
    int state;
    char *pPos;
    int iPos;

    iDestCount = strlen(pszValue);
    if ((iDestCount & 0x3) != 0)
        return NULL;        // Source length must be multiple of 4
    iDestCount = (iDestCount * 3) / 4;
    szDest = (char *)pszValue;
    pszValue = ap_pstrdup(pPool, pszValue);    
    memset(szDest, 0, iDestCount+1);

    TRACE2("decoding %.50s... into %d bytes", pszValue, iDestCount);
    for (state = iDest = 0; *pszValue; ++pszValue) {
        if (*pszValue == '=')
            break;              // We're done

        pPos = strchr(_base64, *pszValue);
        if (pPos == 0)          // Illegal character in source
            return NULL;
        iPos = pPos - _base64;

        switch (state) {
        case 0:                             // b0: xxxxxx00
            szDest[iDest] = iPos << 2;
            break;
        case 1:                             // b0: 000000xx
            szDest[iDest++] |= iPos >> 4;
            szDest[iDest] =                 // b1: xxxx0000
                (iPos & 0x0f) << 4;
            break;
        case 2:
            szDest[iDest++] |=              // b1: 0000xxxx
                iPos >> 2;
            szDest[iDest] =                 // b2: xx000000
                (iPos & 0x03) << 6;
            break;
        case 3:                             // b2: 00xxxxxx
            szDest[iDest++] |= iPos;
            break;
        }
		state++;
        state = state & 0x3;
    }

    TRACE2("decoded %d bytes: %.50s...", iDest, szDest);
    return szDest;
}

// Bauke, 20080703: added
char *aselect_filter_base64_encode(pool *pPool, const char *pszValue)
{
    static char *base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *retBuf, *pRet;
    int i = 0, j = 0;
    unsigned int len;
    unsigned char code3[3], code4[4];

    const char *porig = pszValue;
    len = strlen(pszValue);
    pRet = retBuf = (char *)ap_palloc(pPool, (4*len+12)/3);
    while (len--) {
		code3[i++] = *(pszValue++);
		if (i == 3) {
			code4[0] = (code3[0] & 0xfc) >> 2;
			code4[1] = ((code3[0] & 0x03) << 4) + ((code3[1] & 0xf0) >> 4);
			code4[2] = ((code3[1] & 0x0f) << 2) + ((code3[2] & 0xc0) >> 6);
			code4[3] = code3[2] & 0x3f;

			for(i = 0; (i <4) ; i++)
			*pRet++ = base64Chars[code4[i]];
			i = 0;
		}
    }

    if (i) {
		for(j = i; j < 3; j++)
			code3[j] = '\0';

		code4[0] = (code3[0] & 0xfc) >> 2;
		code4[1] = ((code3[0] & 0x03) << 4) + ((code3[1] & 0xf0) >> 4);
		code4[2] = ((code3[1] & 0x0f) << 2) + ((code3[2] & 0xc0) >> 6);
		code4[3] = code3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			*pRet++ = base64Chars[code4[j]];

		while((i++ < 3))
			*pRet++ = '=';
    }
    *pRet++ = '\0';
    TRACE2("base64_encoded: %s --> %s", porig, retBuf);
    return retBuf;
}

// Bauke: added debugging info
char *filter_action_text(ASELECT_FILTER_ACTION action)
{
    switch(action) {
    case ASELECT_FILTER_ACTION_ACCESS_GRANTED: return("ACCESS_GRANTED");
    case ASELECT_FILTER_ACTION_ACCESS_DENIED: return("ACCESS_DENIED");
    case ASELECT_FILTER_ACTION_AUTH_USER: return("AUTH_USER");
    case ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS: return("VERIFY_CREDENTIALS");
    case ASELECT_FILTER_ACTION_SET_TICKET: return("SET_TICKET");
    default: return "INVALID_ACTION";
    }
}

// Bauke: added debugging info
char *filter_return_text(int iRet)
{
    switch(iRet) {
    case OK: return "OK";
    case DONE: return "DONE";
    case DECLINED: return "DECLINED";
    case FORBIDDEN: return "FORBIDDEN";
    default: return "INVALID_RETURN";
    }
}

static struct timeval timer_zero()
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    return tv;
}

static struct timeval timer_plus(struct timeval p1, struct timeval p2)
{
    struct timeval tv;

    tv.tv_sec = p1.tv_sec + p2.tv_sec;
    tv.tv_usec = p1.tv_usec + p2.tv_usec;

    if (tv.tv_usec > 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
    }
    return tv;
}

static struct timeval timer_minus(struct timeval p1, struct timeval p2)
{
    struct timeval tv;

    tv.tv_sec = p1.tv_sec - p2.tv_sec;
    tv.tv_usec = p1.tv_usec - p2.tv_usec;
    if (tv.tv_usec < 0) {
		tv.tv_sec--;
		tv.tv_usec += 1000000;
    }
    return tv;
}

char *timer_usi(pool *pPool, TIMER_DATA *pTimer)
{
    static char buf[60];

    if (!pTimer)
		return "0";
    sprintf(buf, "%ld.%06ld", pTimer->td_start.tv_sec, pTimer->td_start.tv_usec);
    return buf;
}

void timer_start(TIMER_DATA *pTimer)
{
    if (!pTimer)
		return;
    pTimer->td_type = 1;  // initially
    pTimer->td_spent = timer_zero();
    gettimeofday(&pTimer->td_start, 0);
    pTimer->td_finish = timer_zero();
    TRACE3("TM_%d start: st=%d.%06d", getpid(), pTimer->td_start.tv_sec, pTimer->td_start.tv_usec);
}

void timer_pause(TIMER_DATA *pTimer)
{
    if (!pTimer)
		return;
    gettimeofday(&pTimer->td_finish, 0);
    TRACE3("TM_%d pause: fi=%d.%06d", getpid(), pTimer->td_finish.tv_sec, pTimer->td_finish.tv_usec);
}

// Must be called after timer_pause()
void timer_resume(TIMER_DATA *pTimer)
{
    struct timeval tvNow, tvDiff;
    if (!pTimer) return;
    gettimeofday(&tvNow, 0);

    // spent += now - finish;
    tvDiff = timer_minus(tvNow, pTimer->td_finish);
    pTimer->td_spent = timer_plus(pTimer->td_spent, tvDiff);
    pTimer->td_finish = timer_zero();
    TRACE7("TM_%d resume: nw=%d.%06d df=%d.%06d sp=%d.%06d", getpid(), tvNow.tv_sec, tvNow.tv_usec, tvDiff.tv_sec,
			tvDiff.tv_usec, pTimer->td_spent.tv_sec, pTimer->td_spent.tv_usec);
}

// round: (tv.tv_usec+500)/1000
void timer_finish(TIMER_DATA *pTimer)
{
    struct timeval tvNow, tvDiff;
    if (!pTimer) return;
    gettimeofday(&tvNow, 0);

    // TotalSpent = (now - start) - spent;
    tvDiff = timer_minus(tvNow, pTimer->td_start);
    pTimer->td_spent = timer_minus(tvDiff, pTimer->td_spent);
    pTimer->td_finish = tvNow;
    TRACE7("TM_%d finish: %d.%06d %d.%06d %d.%06d", getpid(), pTimer->td_start.tv_sec, pTimer->td_start.tv_usec,
			pTimer->td_spent.tv_sec, pTimer->td_spent.tv_usec, pTimer->td_finish.tv_sec, pTimer->td_finish.tv_usec);
}

char *timer_pack(pool *pPool, TIMER_DATA *pTimer, char *senderId, char *sAppId, int ok)
{
    char buf1[50], buf2[50], buf3[50];
    char *result;

    sprintf(buf1, "%ld.%06ld", pTimer->td_start.tv_sec, pTimer->td_start.tv_usec);
    sprintf(buf2, "%ld.%06ld", pTimer->td_finish.tv_sec, pTimer->td_finish.tv_usec);
    sprintf(buf3, "%ld.%06ld", pTimer->td_spent.tv_sec, pTimer->td_spent.tv_usec);
    result = ap_psprintf(pPool, "%s,%s,%s,%d,%d,%d,%s,%s,%s,%s,,",
		    senderId, buf1, sAppId, 1/*level*/, 1/*type*/,
		    getpid()/*thread*/, buf1, buf2, buf3, ok? "true": "false");
    return result;
}

