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
 */
// Marked Parts:
// Author: Bauke Hiemstra - www.anoigo.nl
//
// 20130629, Bauke, corrected indentation and solved compilation warnings on 64 bits
//   NOTE tab stops have to be set to 4 positions.
//   In vi use ":set tabstop=4"
//
// 20120526, Bauke: removed Apache 1.3 code
// 20081108, Bauke:
// - boolean "aselect_filter_secure_url" to activate URL escape sequence removal
//   default is 1.
// 20080928, Bauke:
// - added configurable Logout Bar
// - aselect_filter_trace() calls all replaced by TRACE()

/* 
 * $Id: mod_aselect_filter.c,v 1.10 2006/03/01 08:56:39 remco Exp $
 * 
 * Changelog:
 * $Log: mod_aselect_filter.c,v $
 * Revision 1.10  2006/03/01 08:56:39  remco
 * Added option "url=..." in aselect_filter_add_secure_app, which forces the A-Select Server and filter to redirect to a fixed url after a succesful authentication.
 *
 * Revision 1.9  2005/09/13 14:15:31  remco
 * Fixed small bugs found during system test:
 * - verify_ticket uri is now sent according to API
 * - if rule upload failes filter does not start
 *
 * Revision 1.8  2005/09/12 13:50:49  remco
 * Added authorization support (untested)
 *
 * Revision 1.7  2005/05/23 15:40:42  leon
 * html logout button changed in logout bar template
 *
 * Revision 1.5  2005/05/11 08:20:50  remco
 * Fixed bug with option "remote-organization"
 *
 * Revision 1.4  2005/05/04 13:20:02  remco
 * - Added "remote_organization" config directive
 * - Changed directive "extra" to "extra_parameters"
 *
 * Revision 1.3  2005/05/04 08:55:00  remco
 * - Added application config directive "extra="
 * - Filter now logs if incoming message from Agent is too large
 *
 * Revision 1.2  2005/05/02 09:21:15  remco
 * - Changed parsing of application options
 * - Added 3 new application options: uid, language, and country
 * - Changed internal application storage
 * - Fixed handling of errors: some errors incorrectly resulted in re-authentication. Error response is now the same as in the ISAPI filter.
 *
 * Revision 1.1  2005/04/13 09:44:29  remco
 * RC1 of integrated apache 1.3 & 2.0 filter
 *
 */

#include "asf_common.h"

// -----------------------------------------------------
// Exports
// -----------------------------------------------------
module AP_MODULE_DECLARE_DATA aselect_filter_module;

//static handler_rec      aselect_filter_handlers[];
static const command_rec    aselect_filter_cmds[];

char *version_number = "====subversion_741M====";

// -----------------------------------------------------
// Functions 
// -----------------------------------------------------
int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, TIMER_DATA *pt);
int  aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp, TIMER_DATA *pt);
char *aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket,
				    char *pcAttributes, char *language, TIMER_DATA *pt);
char *aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt);
char *aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl, TIMER_DATA *pt);
char *aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcRID,
					char *pcCredentials, char *applicationArguments, TIMER_DATA *pt);
static int      aselect_filter_handler(request_rec *pRequest);
//static void *   aselect_filter_create_config(pool *pPool, server_rec *pServer);
static int      aselect_filter_verify_config(request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig);
static const char * aselect_filter_set_agent_address(cmd_parms *parms, void *mconfig, const char *arg);
static const char * aselect_filter_set_agent_port(cmd_parms *parms, void *mconfig, const char *arg);
static const char * aselect_filter_add_secure_app(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3);
static const char * aselect_filter_add_authz_rule(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3);
static const char * aselect_filter_set_html_error_template(cmd_parms *parms, void *mconfig, const char *arg);
static const char * aselect_filter_set_html_logout_template(cmd_parms *parms, void *mconfig, const char *arg);
static const char * aselect_filter_set_redirection_mode(cmd_parms *parms, void *mconfig, const char *arg);
static const char * aselect_filter_set_use_aselect_bar(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_secure_url(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_pass_attributes(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_add_attribute(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_add_public_app(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_set_logfile(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_added_security(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_set_sensor_address(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_set_sensor_port(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_set_sensor_opts(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_cookie_path(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_special_settings(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_add_app_regexp(cmd_parms *parms, void *mconfig, const char *arg);

static char * aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt);
static int aselect_filter_passAttributesInUrl(int iError, char *pcAttributes, char *usiAttr, pool *pPool, request_rec *pRequest,
	PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcRequestLanguage, table *headers_in, TIMER_DATA *pt);
static void aselect_filter_removeUnwantedCharacters(char *args);
static char *aselect_filter_findNoCasePattern(const char *text, const char *pattern);
static void splitAttrFilter(char *attrFilter, char *condName, int condLen,
			    char *attrValue, int ldapLen, char *applAttrName, int attrLen);
static char *replaceAttributeValues(pool *pPool, char *pcAttributes, char *text, int bUrlDecode);
static int conditionIsTrue(pool *pPool, char *pcAttributes, char *condName);
static char *extractAttributeNames(pool *pPool, char *text, char *paramNames);
static char *getRequestedAttributes(pool *pPool, PASELECT_FILTER_CONFIG pConfig);
static char *extractValueFromList(pool *pPool, char *pSpecial, char *keyName);

static int purgeApplAttributes(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig);

static char *evaluateHTTPResultCode(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig);// RH, 20161108, n

//
// Called once during the module initialization phase.
// can be used to setup the filter configuration 
//
int aselect_filter_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *pPool, server_rec *pServer)
{
	TRACE1("aselect_filter_init: { %x", pServer);
	TRACE3("aselect_filter_init: %s|%s|%s", pServer->error_fname, pServer->server_hostname, pServer->server_scheme);
	PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG)ap_get_module_config(pServer->module_config, &aselect_filter_module);

	TRACE1("aselect_filter_init: %x read", pServer);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer, "ASELECT_FILTER:: initializing");

	if (pConfig->pcAddedSecurity[0] == '\0')
	strcat(pConfig->pcAddedSecurity, "c");  // add Secure & HttpOnly to cookies
	TRACE1("aselect_filter_init: added_security=%s", pConfig->pcAddedSecurity);

	if (pConfig) { // 20091223: Bauke, added
		aselect_filter_trace_logfilename(pConfig->pcLogFileName);

		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
				"ASELECT_FILTER:: A-Select Agent running on: %s:%d", pConfig->pcASAIP, pConfig->iASAPort);

		if (pConfig->bUseASelectBar)
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
				"ASELECT_FILTER:: configured to use the a-select bar");

		if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_TO_APP)
			ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
				"ASELECT_FILTER:: configured to redirect to application entry point");
		else if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL)
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
				"ASELECT_FILTER:: configured to redirect to user entry point");

		if (!aselect_filter_upload_all_rules(pConfig, pServer, pPool, NULL))
			return -1;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
				"ASELECT_FILTER:: secure apps: %d, public apps: %d, attributes: %d", 
				pConfig->iAppCount, pConfig->iPublicAppCount, pConfig->iAttrCount);
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer, "ASELECT_FILTER:: done");
	TRACE1("aselect_filter_init: } %x done", pServer);
	TRACE1("aselect_filter_init: filter_version=%s", version_number);
	return 0;
}

//
// Bauke: needed this stuff to be able to send the rules again
//
int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, TIMER_DATA *pt)
{
	int i;
	PASELECT_APPLICATION pApp;

	TRACE1("upload_all_rules:: AppCount=%d", pConfig->iAppCount);
	for (i=0; i<pConfig->iAppCount; i++) {
		pApp = &pConfig->pApplications[i];
		TRACE4("upload_all_rules:: added %s at %s %s%s", pApp->pcAppId, pApp->pcLocation,
				pApp->bEnabled ? "" : "(disabled)", pApp->bForcedLogon ? "(forced logon)" : "");

		if (aselect_filter_upload_authz_rules(pConfig, pServer, pPool, pApp, pt)) {
			TRACE2("upload_all_rules:: registered %d authz rules for %s", pApp->iRuleCount, pApp->pcAppId);
		}
		else
			return 0; // not ok
	}
	return 1; // ok
}

// Upload authorization rule for a single application
int aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp, TIMER_DATA *pt)
{
    int i, length;
    char *pRequest;
    char *pAppId;
    char pRuleId[16];
    char *pcResponse;
    int iRet;
    
    if (pApp->iRuleCount == 0) {
        TRACE1("upload_authz_rules: NO RULES sent for app=%s", pApp->pcAppId);
		return 1;
	}
    
    // Calculate size of request
    pAppId = aselect_filter_url_encode(pPool, pApp->pcAppId);
    length = 100 + strlen(pAppId);
    for (i=0; i<pApp->iRuleCount; i++) {
        length += 32 + strlen(pApp->pTargets[i]) + strlen(pApp->pConditions[i]);
    }
    
    // Create request
    pRequest = (char *)ap_palloc(pPool, length);
    if (pRequest) {
        strcpy(pRequest, "request=set_authorization_rules&app_id=");
        strcat(pRequest, pAppId);
        strcat(pRequest, "&usi=");
        strcat(pRequest, timer_usi(pPool, pt));
        for (i=0; i<pApp->iRuleCount; i++) {
            ap_snprintf(pRuleId, sizeof(pRuleId), "r%d", i);
            strcat(pRequest, "&rules%5B%5D=");  // []
            strcat(pRequest, pRuleId);
            strcat(pRequest, "%3B");  // ;
            strcat(pRequest, pApp->pTargets[i]);
            strcat(pRequest, "%3B");  // ;
            strcat(pRequest, pApp->pConditions[i]);
        }
        strcat(pRequest, "\r\n");
        
        TRACE1("upload_authz_rules: sending: %s", pRequest);
        pcResponse = aselect_filter_send_request(pServer, pPool, pConfig->pcASAIP, pConfig->iASAPort, pRequest, strlen(pRequest), pt, 1);
        if (pcResponse == NULL) {
            // Could not send request, error already logged
            return 0;
        }
        //TRACE1("upload_authz_rules: response: %s", pcResponse);
        iRet = aselect_filter_get_error(pPool, pcResponse);
        if (iRet != 0) {
			TRACE1("upload_authz_rules:: Agent returned error %s while uploading authorization rules", pcResponse);
            return 0;
        }
    }
    else {
        TRACE("upload_authz_rules: Out of memory");
        return 0;
    }
    return 1;
}

//
// Request validation of a ticket
//
char *aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig,
			char *pcTicket, char *pcAttributes, char *language, TIMER_DATA *pt)
{
    char *pcSendMessage;
    int ccSendMessage;
    char *pcResponse;
    AP_SHA1_CTX ctxSHA1;
    unsigned char cSHA1[SHA_DIGESTSIZE]; // 20
    char pcSHA1[64];  // 2* SHA_DIGESTSIZE
    char *pcURI;
    char langBuf[40];
    
    TRACE1("aselect_filter_verify_ticket: pcAttributes=%s", (pcAttributes)?pcAttributes:"NULL");
    // Create the message
    // Bauke: added
    *pcSHA1 = 0;
    if (pcAttributes && *pcAttributes) {
        ap_SHA1Init(&ctxSHA1);
        ap_SHA1Update(&ctxSHA1, pcAttributes, strlen(pcAttributes));
        ap_SHA1Final(cSHA1, &ctxSHA1);
        aselect_filter_bytes_to_hex(cSHA1, sizeof(cSHA1), pcSHA1);
    }
    pcURI = pRequest->uri + strlen(pConfig->pCurrentApp->pcLocation);
    pcURI = aselect_filter_url_encode(pPool, pcURI);
    
    langBuf[0] = '\0';
    if (language)
		sprintf(langBuf, "&language=%s", language);
    if (*pcSHA1) {
		pcSendMessage = ap_psprintf(pPool, "request=verify_ticket&ticket=%s&app_id=%s&attributes_hash=%s&request_uri=%s&ip=%s%s&usi=%s\r\n", 
			pcTicket, pConfig->pCurrentApp->pcAppId, pcSHA1, pcURI, pRequest->connection->remote_ip, langBuf, timer_usi(pPool, pt));
//			pcTicket, pConfig->pCurrentApp->pcAppId, pcSHA1, pcURI, pRequest->useragent_ip, langBuf, timer_usi(pPool, pt));
//			pcTicket, pConfig->pCurrentApp->pcAppId, pcSHA1, pcURI, pRequest->connection->client_ip, langBuf, timer_usi(pPool, pt));
	}
    else { // No attribute hash available, so don't ask for an attribute check
		pcSendMessage = ap_psprintf(pPool, "request=verify_ticket&ticket=%s&app_id=%s&request_uri=%s&ip=%s%s&usi=%s\r\n", 
				pcTicket, pConfig->pCurrentApp->pcAppId, pcURI, pRequest->connection->remote_ip, langBuf, timer_usi(pPool, pt));
	}
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
			pcSendMessage, ccSendMessage, pt, 1);
    return pcResponse;
}

//
// Kills the ticket
//
char *aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt)
{
    char *pcSendMessage;
    int ccSendMessage;
    char *pcResponse;

    // Create the message
    TRACE("aselect_filter_kill_ticket");
//    pcSendMessage = ap_psprintf(pPool, "request=kill_ticket&ticket=%s&app_id=%s&usi=%s\r\n",
//	    aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId), timer_usi(pPool, pt));
    pcSendMessage = ap_psprintf(pPool, "request=kill_ticket&ticket=%s&app_id=%s&ip=%s&usi=%s\r\n",
	    aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId), pRequest->connection->remote_ip, timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
		    pcSendMessage, ccSendMessage, pt, 1);
    return pcResponse;
}

//
// Request an authentication of a user
//
char *aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl, TIMER_DATA *pt)
{
    char *pcSendMessage;
    int ccSendMessage;
    char *pcResponse;

    // Create the message
    TRACE("aselect_filter_auth_user");
    pcSendMessage = ap_psprintf(pPool, "request=authenticate&app_url=%s&app_id=%s&forced_logon=%s%s%s%s%s%s%s&ip=%s&usi=%s\r\n",
        aselect_filter_url_encode(pPool, pcAppUrl), 
        aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId),
        pConfig->pCurrentApp->bForcedLogon ? "true" : "false",
        pConfig->pCurrentApp->pcUid,
        pConfig->pCurrentApp->pcAuthsp,
        pConfig->pCurrentApp->pcCountry,
        pConfig->pCurrentApp->pcLanguage,
        pConfig->pCurrentApp->pcRemoteOrg,
        pConfig->pCurrentApp->pcExtra,
        pRequest->connection->remote_ip, timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);
    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);

    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1))) {
        //TRACE1("response message: %s", pcResponse);
    }
    else { // socket error occured, take appropiate action
        pcResponse = NULL;
    }
    return pcResponse;
}

// Bauke 20081201: added to support Saml token in a header
//
static char *getRequestedAttributes(pool *pPool, PASELECT_FILTER_CONFIG pConfig)
{
	char *paramNames = ",";
	char condName[1200], attrValue[400], applAttrName[200]; // check with other buffers with the same name
	int i;

	for (i = 0; i < pConfig->iAttrCount; i++) {
		//TRACE2("getRequestedAttributes:: %d: %s", i, pConfig->pAttrFilter[i]);
		splitAttrFilter(pConfig->pAttrFilter[i], condName,sizeof(condName), attrValue,sizeof(attrValue), NULL,0);

		// Look in condName and attrValue for [attr,<name>] constructs
		if (attrValue[0] != '\0') {
			// Decent attrValue present, extract attributes from expression
			if (attrValue[0] == '\'' && attrValue[strlen(attrValue)-1] == '\'')
				paramNames = extractAttributeNames(pPool, attrValue, paramNames);
			else {
				// Add attrValue itself, if not present yet
				sprintf(applAttrName, ",%s,", attrValue);
				if (strstr(paramNames, applAttrName) == 0)
					paramNames = ap_psprintf(pPool, "%s%s,", paramNames, attrValue);
			}
		}
		if (condName[0] != '\0') {
			paramNames = extractAttributeNames(pPool, condName, paramNames);
		}
	}

	// Remove comma's
	paramNames[strlen(paramNames)-1] = '\0';
	TRACE1("getRequestedAttributes:: %s", paramNames+1);
	return paramNames+1;
}

//  RH, 20161108, sn
static char *evaluateHTTPResultCode(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig)
{
        char *result = NULL;
	int i;
	for (i = 0; i < pConfig->iHeaderHandlerCount; i++) {
        	char resultCode[5], headerName[400], headerValue[400]; // check with other buffers with the same name
		TRACE2("evaluateHTTPResultCode:: %d: %s", i, pConfig->pHeaderHandler[i]);
		splitAttrFilter(pConfig->pHeaderHandler[i], resultCode,sizeof(resultCode), headerName,sizeof(headerName), headerValue,sizeof(headerValue));

		// Look in headerName and headerValue matching headerName, headerValue pair
		if (headerName[0] != '\0') {

                        char *value = aselect_filter_get_header(pPool, pRequest->headers_in, headerName);
        		TRACE2("evaluateHTTPResultCode::Found headerValue:: %d: %s", i, value == NULL ? "NULL" : value);
                        if (value && !strcmp(headerValue,value)) { // only if specific header with value found
                            result = ap_psprintf(pPool, "%s", resultCode);
                            break;  // find first
                        }
		}
	}
        TRACE1("evaluateHTTPResultCode::Returning  resultCode: %s", result);
	return result;
}
//  RH, 20161108, en


static char *extractAttributeNames(pool *pPool, char *text, char *paramNames)
{
	int len;
	char *begin, *end;
	char *param;

	TRACE1("extractAttributeNames text=%s", text);
	begin = strstr(text, "[attr,");
	for ( ; begin != NULL; begin = strstr(end, "[attr,")) {
		begin += 6;
		end = strchr(begin, ']');
		if (!end)
			return paramNames;
		len = end - begin;
		if (len < 1)
			continue;

		// Does the parameter already occur?
		param = ap_psprintf(pPool, ",%.*s,", len, begin);
		if (strstr(paramNames, param) == 0)
			paramNames = ap_psprintf(pPool, "%s%.*s,", paramNames, len, begin);
	}
	//TRACE1("extractAttributeNames params=%s", paramNames);
	return paramNames;
}

//
// Verify the credentials
// sends the RID and the credentials to the Aselect Agent for verification
// Bauke 20081201: added saml_attributes
// Bauke 20100521: added aselect_app_args
//
char *aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool,
	    PASELECT_FILTER_CONFIG pConfig, char *pcRID, char *pcCredentials,
	    char *applicationArguments, TIMER_DATA *pt)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;
    char *attrNames = NULL;

    //
    // Create the message
    //
    TRACE("aselect_filter_verify_credentials");
    if (strchr(pConfig->pcPassAttributes,'t')!=0) {
		// Need token later on, pass the attribute names we need
		attrNames = getRequestedAttributes(pPool, pConfig);
    }
    // 20100521, Bauke: added, application args secured by Agent
    pcSendMessage = ap_psprintf(pPool, "request=verify_credentials&aselect_app_args=%s&rid=%s&aselect_credentials=%s%s%s&ip=%s&usi=%s\r\n",
			aselect_filter_url_encode(pPool, applicationArguments),
			aselect_filter_url_encode(pPool, pcRID),
			aselect_filter_url_encode(pPool, pcCredentials),
			(attrNames)? "&saml_attributes=": "", (attrNames)? attrNames: "", pRequest->connection->remote_ip, timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP,
                            pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1);
    return pcResponse;
}

//
// Bauke: Added:
// Retrieve Attribute values from the Agent
//
char *aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;

    //TRACE("aselect_filter_attributes");
    //
    // Create the message
    //
    //pcSendMessage = ap_psprintf(pPool, "request=attributes&ticket=%s&uid=%s&organization=%s&usi=%s\r\n", 
    pcSendMessage = ap_psprintf(pPool, "request=attributes&ticket=%s&ip=%s&usi=%s\r\n", aselect_filter_url_encode(pPool, pcTicket), pRequest->connection->remote_ip, timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1))) {
        //TRACE1("response message: %s", pcResponse);
    }
    else { // could not send request to A-Select Agent
        pcResponse = NULL;
    }
    return pcResponse;
}


static int aselect_filter_verify_config(request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig)
{
    if (!pConfig) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no config at all");
		return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (pConfig->bConfigError) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: config error detected (old)");
		return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (!pConfig->pcASAIP) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no agent_address");
		return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (strlen(pConfig->pcASAIP) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no agent_address value");
		return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (pConfig->iASAPort == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no agent_port");
		return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (pConfig->iAppCount == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no applications specified (warning)");
		//return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (!pConfig->pcErrorTemplate || strlen(pConfig->pcErrorTemplate) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no error_template");
		return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (!pConfig->pcLogoutTemplate || strlen(pConfig->pcLogoutTemplate) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: no logout_template");
		return ASELECT_FILTER_ERROR_CONFIG;
    }
    return ASELECT_FILTER_ERROR_OK;
}

// Extract parameters that must be passed to the application from all arguments
//
char *extractApplicationParameters(pool *pPool, char *arguments)
{
    char *pcStrippedParams  = NULL;
    char *pcTmp2;
    int bFirstParam = TRUE;
	// 20130627, Bauke: make a copy, strtok() modifies its first argument
	char *pcTmp = ap_pstrdup(pPool, arguments);

    pcTmp = strtok(pcTmp, "?&");
    while (pcTmp != NULL) {
		// Skip these parameters:
		if ((pcTmp2 = strstr(pcTmp, "aselect_credentials")) == NULL) {
			if ((pcTmp2 = strstr(pcTmp, "rid")) == NULL) {
				if ((pcTmp2 = strstr(pcTmp, "a-select-server")) == NULL) {
					// The rest will pass
					if (bFirstParam) {
						pcStrippedParams = ap_psprintf(pPool, "?%s", pcTmp);
						bFirstParam = FALSE;
					}
					else
						pcStrippedParams = ap_psprintf(pPool, "%s&%s", pcStrippedParams, pcTmp);
				 }
			 }
		}
		pcTmp = strtok(NULL, "?&");
    }
    return (pcStrippedParams != NULL)? pcStrippedParams: "";
}

//
// Main handler, will handle cookie checking and redirection
//
static int aselect_filter_handler(request_rec *pRequest)
{
    int ok;
    int iRet = FORBIDDEN; // 401
    int iError = ASELECT_FILTER_ERROR_OK;
    int iAction = ASELECT_FILTER_ACTION_ACCESS_DENIED;
    table *headers_in = pRequest->headers_in;
    table *headers_out = pRequest->headers_out;
    PASELECT_FILTER_CONFIG  pConfig = NULL;
    char *pcTicketIn, *pcTicketOut = NULL;
    char *pcUIDIn, *pcUIDOut = NULL;
    char *pcOrganizationIn, *pcOrganizationOut = NULL;
    char *pcAttributesIn = NULL;
    char *pcTicket;
    char *pcCredentials;
    char *pcRID;
    char *pcAppUrl;
    char *pcCookie, *pcCookie2, *pcCookie4;
    char *pcASUrl;
    char *pcASelectServer;
    char *pcResponseVT, *pcResponseAU;
    char *pcResponseCred;
    pool *pPool = NULL;
    char *pcUrl;
    char *pcRequest;
    char *pcASelectServerURL;
    char *pcResponseKill;
    char *pcTmp, *pcTmp2;
    char *pcAttributes = NULL;
    char *pcRequestLanguage = NULL;
    char *addedSecurity = "";
    char *securedAselectAppArgs = NULL;
    char *passUsiAttribute = NULL; 
	char *pcCookiePath = NULL;
    char *pcForceAppid;

    int try, rc;
	char *p, sep;
    TIMER_DATA timer_data;
    table *subprocess_env = pRequest->subprocess_env;   // RH, 20170926, n

    
    TRACE2("---- { GET %s %s", pRequest->uri, pRequest->args);
    // START TIMER
    timer_data.td_type = 0;
    timer_start(&timer_data);

    // Create the pool
    if ((apr_pool_create(&pPool, pRequest->pool)) != APR_SUCCESS) {
		// Could not allocate pool
		TRACE("aselect_filter_handler: Could not allocate memory pool");
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: could not allocate memory pool");
		goto finish_filter_handler;  // only goto's to routine exit point
    }
	TRACE("aselect_filter_handler: MEMORY POOL created");
	// Create the pool first!
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, pRequest->server,
		/*ap_psprintf(pRequest->pool,*/ "SIAM:: URI - %s %s", pRequest->uri, pRequest->args);

    // 20120610, Bauke: Default usi is my own, could be modified by the Agent (verify_credentials or verify_ticket)
    passUsiAttribute = timer_usi(pPool, &timer_data);


	aselect_filter_print_table(pRequest, pRequest->headers_in, "headers_in (to application)");
	aselect_filter_print_table(pRequest, pRequest->headers_out, "headers_out (to user's browser)");



    // NOTE: the application ticket is a cookie, check if the browser can handle cookies else we run into a loop
    // check cookie, no cookie, validate_user, set cookie, check cookie, no cookie.... and so on
    
    // Read config data
    pConfig = (PASELECT_FILTER_CONFIG)ap_get_module_config(pRequest->server->module_config, &aselect_filter_module);
    if (!pConfig) {
		// Something went wrong, access denied
		TRACE("Could not get module config data");
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: could not retrieve configuration data");
		goto finish_filter_handler;
    }
    else { // Verify configuration
		TRACE2("IP=%s Port=%d", (pConfig->pcASAIP)? pConfig->pcASAIP: "NULL", pConfig->iASAPort);
		if (aselect_filter_verify_config(pRequest, pConfig) != ASELECT_FILTER_ERROR_OK) {
			TRACE("Invalid configuration data");
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, pRequest, "SIAM:: invalid configuration data");
			goto finish_filter_handler;
		}
    }

    /* Return codes are:
       DECLINED -1 **< Module declines to handle
       DONE -2     **< Module has served the response completely, it's safe to die() with no more output
       OK 0        **< Module has handled this stage */

    // 20110129, Bauke added public directories
    // Code uses 'secure' as default (all public directories must be enumerated)

    // 20120530, Bauke: new mechanism to choose public/secure using match length
    // 20120608: default is secure
    pcForceAppid = aselect_filter_get_param(pPool, pRequest->args, "force_app_id", "&", TRUE);

    rc = aselect_filter_check_app_uri(pPool, pConfig, pRequest->uri, pcForceAppid);
    if (rc == 0) {  // public
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, pRequest->server,
			/*ap_psprintf(pRequest->pool, */"SIAM:: Public - %s", pRequest->uri);
		TRACE1("\"%s\" is a public directory", pRequest->uri);
		iRet = OK;
		goto finish_filter_handler; // we don't want to do anything with this request, let it pass
    }
    else if (rc < 0) {  // not found
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, pRequest->server,
			/*ap_psprintf(pRequest->pool, */"SIAM:: Not configured - %s", pRequest->uri);
		TRACE1("\"%s\" is not configured", pRequest->uri);
		iRet = HTTP_NOT_FOUND;
		goto finish_filter_handler; // we don't want to do anything with this request
    }
    // else 1="secure"
    // 20120530 end

    /*
    if (aselect_filter_is_public_app(pPool, pConfig, pRequest->uri) == ASELECT_FILTER_ERROR_OK) {
        TRACE1("\"%s\" is a public directory", pRequest->uri);
		iRet = OK;
		goto finish_filter_handler; // we don't want to do anything with this request
    }

    // Check if we are in a protected dir
    // This function points the global pConfig->pCurrentApp to the requested app
    //
    if (aselect_filter_verify_directory(pPool, pConfig, pRequest->uri) == ASELECT_FILTER_ERROR_FAILED) {
        // Not in a protected dir, this should not be possible, but we let the request through anyway
        TRACE1("\"%s\" is not a protected dir (or is disabled)", pRequest->uri);
        iRet = DECLINED;
		goto finish_filter_handler;
    }
    */

    // Serious action, so use a serious type :-)
    timer_data.td_type = 1;
    
    // RH, 20170102, sn
    // implement request filter_alive here
    pcRequest = aselect_filter_get_param(pPool, pRequest->args, "request", "&", TRUE);
    if (pcRequest != NULL && strstr(pcRequest, "filter_alive") != 0) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, pRequest->server,
                    /*ap_psprintf(pRequest->pool, */"SIAM:: Request filter_alive - %s", pRequest->uri);
            TRACE1("\"%s\" requested filter_alive", pRequest->uri);
            // return output
            pRequest->content_type = "text/html; charset=utf-8";
            
            // RH, 20170926, sn
            TRACE2("Set env %s: %s", "dontlog", "1");
            if (subprocess_env) {
                ap_table_set(subprocess_env, "dontlog", "1");
            } else {
                TRACE1("Creating table for subprocess_env with size %s", "1");
                subprocess_env = ap_make_table(pPool, 1);
                ap_table_set(subprocess_env, "dontlog", "1");
                pRequest->subprocess_env = ap_overlay_tables(pPool, pRequest->subprocess_env, subprocess_env );
            }
            // RH, 20170926, sn

            ap_send_http_header(pRequest);
            ap_rprintf(pRequest, "%s\n", "<html><body>Filter is ALIVE</body></html>");
            iRet = DONE;
            goto finish_filter_handler; // we're done
    }
    //
    // RH, 20170102, en

    // 20091114, Bauke: report application language back to the Server
    // RM_12_01
    // Currently callers have to specify the language as an URL parameter
    pcRequestLanguage = aselect_filter_get_param(pPool, pRequest->args, "language", "&", TRUE);

    //
    // Retrieve the remote_addr
    //
	TRACE2("\"%s\" is a protected dir, app_id: %s", pRequest->uri, pConfig->pCurrentApp->pcAppId);
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, pRequest->server,
		/*ap_psprintf(pRequest->pool, */"SIAM:: Secure - %s app=%s", pRequest->uri, pConfig->pCurrentApp->pcAppId);
	if (pRequest->connection->remote_ip) {
		TRACE1("remote_ip: %s", pRequest->connection->remote_ip);
	}

    TRACE3("==== 1. Start iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));
    TRACE4("     (DECLINED=%d DONE=%d FORBIDDEN=%d OK=%d)", DECLINED, DONE, FORBIDDEN, OK);
//    addedSecurity = (strchr(pConfig->pcAddedSecurity, 'c')!=NULL)? " secure; HttpOnly": "";   // RH, 20200812, o
//    addedSecurity = (strchr(pConfig->pcAddedSecurity, 'c')!=NULL)? " Secure; HttpOnly; SameSite=None": "";
       // RH, 20200812, sn
    addedSecurity = (strchr(pConfig->pcAddedSecurity, 'c')!=NULL)? " Secure; HttpOnly; SameSite=None": 
        (strchr(pConfig->pcAddedSecurity, 's')!=NULL)? " Secure; HttpOnly; SameSite=Lax":
            (strchr(pConfig->pcAddedSecurity, 'S')!=NULL)? " Secure; HttpOnly; SameSite=Strict": "";
       // RH, 20200812, en
    
	//
	// Set Cookie Path for all cookies
	//
	pcCookiePath = pConfig->pcCookiePath;
	if (!pcCookiePath || !*pcCookiePath) pcCookiePath = pConfig->pCurrentApp->pcLocation;

    //
    // Check for application ticket
    //
    pcTicketIn = aselect_filter_get_cookie(pPool, headers_in, "aselectticket");
    if (pcTicketIn) {
        //
        // Look for a valid ticket
        //
        TRACE1("aselect_filter_handler: found ticket: %s", pcTicketIn);
        //pcUIDIn = aselect_filter_get_cookie(pPool, headers_in, "aselectuid");
		pcUIDIn = "-1";
        if (1==1 /*pcUIDIn*/) {
            TRACE1("aselect_filter_handler: found uid: %s", pcUIDIn);
			//
            // Check for Organization 
            //
            //pcOrganizationIn = aselect_filter_get_cookie(pPool, headers_in, "aselectorganization");
			pcOrganizationIn = "---";
            if (1==1 /*pcOrganizationIn*/) {
                TRACE3("aselect_filter_handler: found organization: %s, bSecureUrl=%d PassAttributes=%s",
				pcOrganizationIn, pConfig->bSecureUrl, pConfig->pcPassAttributes);
                //
                // Check cookie attributes
                //
				pcAttributesIn = NULL;
				if (strchr(pConfig->pcPassAttributes,'c')!=0 || strchr(pConfig->pcPassAttributes,'C')!=0) {
					pcAttributesIn = aselect_filter_get_cookie(pPool, headers_in, "aselectattributes");
					if (pcAttributesIn && strncmp(pcAttributesIn, "usi=", 4) == 0) {
						char *p = strchr(pcAttributesIn, '&');
						pcAttributesIn = (p)? p+1: NULL;
						TRACE1("Stripped usi from cookie %.30s...", pcAttributesIn);
					}
					//TRACE1("aselect_filter_handler: attributes from cookie: %s", pcAttributesIn? pcAttributesIn: "NULL");
				}
				// Bauke: changed
				// If attributes are not stored in a cookie,
				// the value will not be checked with the A-Select server.
//if (1 == 1) {
				// Validate ticket
				// Bauke: added, always send rules
				//aselect_filter_upload_all_rules(pConfig, pRequest->server, pPool, &timer_data);
				// 20120527, Bauke: no longer uploading the rules in advance, but upon error message from Agent
				for (try = 0; try < 2; try++) {
					pcResponseVT = aselect_filter_verify_ticket(pRequest, pPool, pConfig,
									pcTicketIn, pcAttributesIn, pcRequestLanguage, &timer_data);
					// if batch_size < 0, no Agent configuration, ignore Agent
					iError = aselect_filter_get_error(pPool, pcResponseVT);
					pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "batch_size", "&", TRUE);
					if (pcTmp != NULL) {  // new Agent too
						int iBatchSize = atoi(pcTmp);
						if (iBatchSize >= 0)
							pConfig->iBatchSize = iBatchSize;
					}
					else { // older Agent, does not report batch_size
						if (iError == ASELECT_FILTER_ASAGENT_ERROR_NOT_AUTHORIZED) // could be caused by absent rules
							iError = ASELECT_FILTER_ASAGENT_ERROR_NO_RULES;  // force rule sending
					}
					if (iError == ASELECT_FILTER_ASAGENT_ERROR_NO_RULES) {
						aselect_filter_upload_all_rules(pConfig, pRequest->server, pPool, &timer_data);
						// and try again
					}
					else break;
				}
				if (iError == ASELECT_FILTER_ASAGENT_ERROR_NO_RULES)
					iError = ASELECT_FILTER_ASAGENT_ERROR_NOT_AUTHORIZED; // 140

				if (pcResponseVT) {
					// 20120527, Bauke: use the Agent setting for sending data to LbSensor
					// if batch_size < 0, no Agent configuration, ignore Agent
					pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "batch_size", "&", TRUE);
					if (pcTmp != NULL) {
						int iBatchSize = atoi(pcTmp);
						if (iBatchSize >= 0)
							pConfig->iBatchSize = iBatchSize;
					}
					if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
						// User has ticket, ACCESS GRANTED
						// 20091114, Bauke: Possibly a server language was passed back
						pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "language", "&", TRUE);
						if (pcTmp != NULL) {
							TRACE1("Return language=%s", pcTmp);
							pcRequestLanguage = pcTmp;
						}
						// 20100521, Bauke: added, application args secured by Agent
						pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "aselect_app_args", "&", TRUE);
						if (pcTmp != NULL) {
							TRACE1("Return aselect_app_args=%s", pcTmp);
							securedAselectAppArgs = pcTmp;
						}
						pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "usi", "&", TRUE);
						if (pcTmp != NULL) {
							TRACE1("From Agent(verify_ticket): passUsi=%s", pcTmp);
							passUsiAttribute = pcTmp;
						}
						iAction = ASELECT_FILTER_ACTION_ACCESS_GRANTED;
						TRACE("aselect_filter_handler: User has ticket: ACCESS_GRANTED");
					}
					else {
						pRequest->content_type = "text/html; charset=utf-8";
//						pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectticket", pcCookiePath, addedSecurity);
						pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectticket", pcCookiePath, addedSecurity);
						TRACE1("Delete cookie: %s", pcCookie);
						ap_table_add(headers_out, "Set-Cookie", pcCookie);

//						pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
						pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
						TRACE1("Delete cookie: %s", pcCookie);
						ap_table_add(headers_out, "Set-Cookie", pcCookie);

						if (strchr(pConfig->pcPassAttributes,'c')!=0 || strchr(pConfig->pcPassAttributes,'C')!=0) {  // Bauke: added
//							pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
							pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
							TRACE1("Delete cookie: %s", pcCookie);
							ap_table_add(headers_out, "Set-Cookie", pcCookie);
						}
						ap_send_http_header(pRequest);

						if (iError == ASELECT_FILTER_ASAGENT_ERROR_DIFFERENT_APPID) {
							iError = ASELECT_FILTER_ERROR_OK;
							iAction = ASELECT_FILTER_ACTION_AUTH_USER;
						}
						else if (iError == ASELECT_SERVER_ERROR_TGT_NOT_VALID ||
							iError == ASELECT_SERVER_ERROR_TGT_EXPIRED ||
							iError == ASELECT_SERVER_ERROR_TGT_TOO_LOW ||
							iError == ASELECT_SERVER_ERROR_UNKNOWN_TGT ||  // Bauke, 20080928 added
							iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_INVALID ||
							iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_EXPIRED ||
							iError == ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_TICKET)
						{
							iError = ASELECT_FILTER_ERROR_OK;
							iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
							TRACE("aselect_filter_handler: Invalid ticket: VERIFY_CREDENTIALS");
						}
						else {
							TRACE1("aselect_filter_verify_ticket FAILED (%d)", iError);
							ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
								/*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_verify_ticket FAILED (%d)", iError);
						}
					}
				}
//}
//else { // Ticket verification failed, check if credentials is valid (if credentials is present)
//    iError = ASELECT_FILTER_ASAGENT_ERROR_CORRUPT_ATTRIBUTES;
//}
			}
            else { // Could not find a inst-id, check if the user has credentials 
                iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
            }
        }
        else { // Could not find a user-id, check if the user has credentials 
            iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
        }
    }
    else { // Could not find a application ticket, check if the user has credentials
        iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
    }

    TRACE3("==== 2. Verify iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));
    if (iAction == ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS) {
        //
        // Check for user credentials 
        //
        TRACE1("Verify Credentials, ARGUMENTS: %s", pRequest->args);
        pcCredentials = aselect_filter_get_param(pPool, pRequest->args, "aselect_credentials", "&", TRUE);
        if (pcCredentials) {
            TRACE1("aselect_credentials: %s", pcCredentials);
            pcRID = aselect_filter_get_param(pPool, pRequest->args, "rid", "&", TRUE);
            if (pcRID) {
                // Found credentials, now verify them, if ok it returns a ticket
				securedAselectAppArgs = extractApplicationParameters(pPool, pRequest->args);
				// 20100521, Bauke: added, application args will be secured by Agent
				TRACE1("Verify Credentials, SecuredArgs: %s", securedAselectAppArgs);
                pcResponseCred = aselect_filter_verify_credentials(pRequest, pPool, pConfig, pcRID,
										pcCredentials, securedAselectAppArgs, &timer_data);
                if (pcResponseCred) {
                    iError = aselect_filter_get_error(pPool, pcResponseCred);
                    if (iError == ASELECT_FILTER_ERROR_INTERNAL)
                        iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;

                    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
                        // User credentials are ok, set application ticket and let user through
						TRACE1("aselect_credentials, response [%.50s...]", pcResponseCred?pcResponseCred:"NULL");
                        pcTicketOut = aselect_filter_get_param(pPool, pcResponseCred, "ticket", "&", TRUE);
                        if (pcTicketOut != NULL) {
                            // Save Uid
                            if ((pcUIDOut = aselect_filter_get_param(pPool, pcResponseCred, "uid", "&", TRUE))) {
                                if ((pcOrganizationOut = aselect_filter_get_param(pPool, pcResponseCred, "organization", "&", TRUE))) {
                                    pcTmp = aselect_filter_get_param(pPool, pcResponseCred, "usi", "&", TRUE);
                                    if (pcTmp) {
                                        passUsiAttribute = pcTmp;
										TRACE1("From Agent(verify_credentials), usi=%s", passUsiAttribute);
									}
									// Will overwrite value from cookie (if it was present anyway)
                                    pcAttributes = aselect_filter_get_param(pPool, pcResponseCred, "attributes", "&", TRUE);
                                    if (pcAttributes)
                                        pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);
									if (passUsiAttribute != NULL) {  // add "usi" 
										if (pcAttributes != NULL)
											pcAttributes = ap_psprintf(pPool, "usi=%s&%s", passUsiAttribute, pcAttributes);
										else
											pcAttributes = ap_psprintf(pPool, "usi=%s", passUsiAttribute);
									}
									TRACE2("ver_cred:: passUsi=%s attributes=%s", passUsiAttribute, pcAttributes);
                                    iAction = ASELECT_FILTER_ACTION_SET_TICKET;
                                }
                                else {
                                    TRACE1("could not find organization in response: %s", pcResponseCred);
                                    iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                }
                            }
                            else {
                                TRACE1("could not find uid in response: %s", pcResponseCred);
                                iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                            }
                        }
                        else { // Could not find ticket in response
                            TRACE1("could not find ticket in response: %s", pcResponseCred);
                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                        }
                    }
                    else {
                        TRACE1("aselect_filter_verify_tgt FAILED (%d)", iError);
                        if (iError == ASELECT_SERVER_ERROR_TGT_NOT_VALID ||
                            iError == ASELECT_SERVER_ERROR_TGT_EXPIRED ||
                            iError == ASELECT_SERVER_ERROR_TGT_TOO_LOW ||
							iError == ASELECT_SERVER_ERROR_UNKNOWN_TGT ||  // Bauke, 20080928 added
                            iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_INVALID ||
                            iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_EXPIRED ||
                            iError == ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_TICKET)
                        {
                            iAction = ASELECT_FILTER_ACTION_AUTH_USER;
                            iError = ASELECT_FILTER_ERROR_OK;
                        }
                    }
                }
                else {
                    iError = ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;
                }
            }
            else { // Could not find a RID, authenticate user
                iAction = ASELECT_FILTER_ACTION_AUTH_USER;
            }
        }
        else { // No Credentials present, authenticate user
            iAction = ASELECT_FILTER_ACTION_AUTH_USER;
        }
    }
	//TRACE1("==== 3. ARGUMENTS: %s", pRequest->args);
    TRACE3("==== 3. Action iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));

    // If we do not have an error then act according to iAction
    if (iError == ASELECT_FILTER_ERROR_OK) {
		// Handle special case, user wants to log out but was not logged in
		if (iAction == ASELECT_FILTER_ACTION_AUTH_USER && pRequest->args) {
			pcRequest = aselect_filter_get_param(pPool, pRequest->args, "request", "&", TRUE);
			if (pcRequest != NULL && strstr(pcRequest, "kill_ticket") != 0) {
				TRACE1("action=%s", filter_action_text(iAction));
				iAction = ASELECT_FILTER_ACTION_ACCESS_GRANTED;
			}
		}

        // Act according to action
		switch(iAction) {
		case ASELECT_FILTER_ACTION_ACCESS_GRANTED:
			// User was granted access
			// Check for known requests such as show_aselect_bar and kill_ticket
			TRACE1("Action: ASELECT_FILTER_ACTION_ACCESS_GRANTED, args=%s", pRequest->args);
			if (pRequest->args) {
				pcRequest = aselect_filter_get_param(pPool, pRequest->args, "request", "&", TRUE);
				if (pcRequest) {
					TRACE1("pcRequest=%s", pcRequest);
					if (strstr(pcRequest, "aselect_show_bar") && pConfig->bUseASelectBar) {
						// Return the frame around the logout_bar and the application
						//Old needs 'aselect_app_url' to pass app parameters
						//if ((pcASelectAppURL = aselect_filter_get_param(pPool, pRequest->args, "aselect_app_url", "&", TRUE))) 
						//	aselect_filter_removeUnwantedCharacters(pcASelectAppURL);
						//end Old
						if (securedAselectAppArgs != NULL)
							iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, securedAselectAppArgs);
						else
							iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, pConfig->pCurrentApp->pcLocation);
						// iRet is now set to DONE
					}
					else if (strstr(pcRequest, "aselect_generate_bar")) {
						// Return the logout_bar content, containing the logout button
						char *pcLogoutHTML = pConfig->pcLogoutTemplate;  // configurable logout template

						TRACE1("aselect_generate_bar, logout loc=%s", pConfig->pCurrentApp->pcLocation);
						pRequest->content_type = "text/html; charset=utf-8";
						ap_send_http_header(pRequest);

						// Bauke 20080928: added configurable Logout Bar
						while (pcLogoutHTML && (strstr(pcLogoutHTML, "[action]") != NULL)) {
							pcLogoutHTML = aselect_filter_replace_tag(pPool, "[action]", pConfig->pCurrentApp->pcLocation, pcLogoutHTML);
						}
						ap_rprintf(pRequest, "%s\n", (pcLogoutHTML)? pcLogoutHTML: "");
						iRet = DONE;
					}
					else if (strstr(pcRequest, "aselect_kill_ticket") || strstr(pcRequest, "kill_ticket")) {
						// Kill the user ticket
						if ((pcTicket = aselect_filter_get_cookie(pPool, headers_in, "aselectticket"))) {
							if ((pcResponseKill = aselect_filter_kill_ticket(pRequest, pPool, pConfig, pcTicket, &timer_data))) {
								//TRACE1("Agent response: %s", pcResponseKill);
								iError = aselect_filter_get_error(pPool, pcResponseKill);
								if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
									// Successfully killed the ticket, now redirect to the aselect-server
									if ((pcASelectServerURL = aselect_filter_get_cookie(pPool, headers_in, "aselectserverurl"))) {
										pRequest->content_type = "text/html; charset=utf-8";
//										pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectticket", pcCookiePath, addedSecurity);
										pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectticket", pcCookiePath, addedSecurity);
										TRACE1("Delete cookie: %s", pcCookie);
										ap_table_add(headers_out, "Set-Cookie", pcCookie);
										if (strchr(pConfig->pcPassAttributes,'C')!=0) {  // 20120703: Bauke: added
//											pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectuid", pcCookiePath, addedSecurity);
											pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectuid", pcCookiePath, addedSecurity);
											TRACE1("Delete cookie: %s", pcCookie);
											ap_table_add(headers_out, "Set-Cookie", pcCookie);
										}
										//pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectorganization",
										//		pcCookiePath, addedSecurity);
										//TRACE1("Delete cookie: %s", pcCookie);
										//ap_table_add(headers_out, "Set-Cookie", pcCookie);
//										pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectserverurl", pcCookiePath, addedSecurity);
										pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectserverurl", pcCookiePath, addedSecurity);
										TRACE1("Delete cookie: %s", pcCookie);
										ap_table_add(headers_out, "Set-Cookie", pcCookie);
										if (strchr(pConfig->pcPassAttributes,'c')!=0 || strchr(pConfig->pcPassAttributes,'C')!=0) {  // Bauke: added
//											pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
											pcCookie = ap_psprintf(pPool, "%s=; max-age=0; path=%s;%s", "aselectattributes", pcCookiePath, addedSecurity);
											TRACE1("Delete cookie: %s", pcCookie);
											ap_table_add(headers_out, "Set-Cookie", pcCookie);
										}
										// else: no aselectattributes cookie needed
										ap_send_http_header(pRequest);

										// Example:
										// https://siam.plains.nl/aselectserver/server?request=logout&a-select-server=plains&logout_return_url=...
										pcTmp = aselect_filter_get_param(pPool, pcResponseKill, "a-select-server", "&", TRUE);
										if (!pcTmp)
											pcTmp = "";
										pcTmp2 = aselect_filter_get_param(pPool, pRequest->args, "logout_return_url", "&", TRUE);
										if (pcTmp2 && *pcTmp2) {
											pcASelectServerURL = ap_psprintf(pPool, "%s?request=logout&a-select-server=%s&logout_return_url=%s",
												pcASelectServerURL, aselect_filter_url_encode(pPool, pcTmp),
												aselect_filter_url_encode(pPool, pcTmp2));
										}
										else {
											pcASelectServerURL = ap_psprintf(pPool, "%s?request=logout&a-select-server=%s",
												pcASelectServerURL, aselect_filter_url_encode(pPool, pcTmp));
										}
										TRACE1("Redirect to '%s'", pcASelectServerURL);
										ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcASelectServerURL, pcASelectServerURL);
										iRet = DONE;
									}
									else {
										iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
										TRACE1("aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError);
										ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
											/*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError);
									}
								}
								else {
									TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
									ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
										/*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_kill_ticket FAILED: %d", iError);
								}
							}
							else {
							iError = ASELECT_FILTER_ERROR_INTERNAL;
							TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
							ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
								/*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_kill_ticket FAILED: %d", iError);
							}
						}
						else { // Could not find ticket to kill
							iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
							TRACE1("aselect_filter_get_cookie(aselectticket) FAILED: %d", iError);
							ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
								/*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_get_cookie(aselectticket) FAILED: %d", iError);
						}
					}
					else { // Nothing interesting in the request=param, so continue as normal
						TRACE("No recognized request given");
						iRet = DECLINED;
					}
				}
				else { // No arguments we are interested in, so continue as normal
					TRACE("No request given");
					iRet = DECLINED;
				}
			}
			else {
				iRet = DECLINED;
			}
			break;

		case ASELECT_FILTER_ACTION_AUTH_USER:
			// User does not have valid CREDENTIALS and must be authenticated by the Server
			// Contact the Agent to find the user's Server

			TRACE("Action: ASELECT_FILTER_ACTION_AUTH_USER");
			TRACE2("iRedirectMode: %d redirectURL=%s", pConfig->iRedirectMode, pConfig->pCurrentApp->pcRedirectURL);
			if (*pConfig->pCurrentApp->pcRedirectURL) {
				TRACE1("Using fixed app_url: %s", pConfig->pCurrentApp->pcRedirectURL);
				if (pRequest->args != NULL) {
					if (strchr(pConfig->pCurrentApp->pcRedirectURL, '?'))
						pcAppUrl = ap_psprintf(pPool, "%s&%s", pConfig->pCurrentApp->pcRedirectURL, pRequest->args);
					else
						pcAppUrl = ap_psprintf(pPool, "%s?%s", pConfig->pCurrentApp->pcRedirectURL, pRequest->args);
				}
				else
					pcAppUrl = pConfig->pCurrentApp->pcRedirectURL;
			}
			else {
				if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL) {
					if (pRequest->args != NULL) {
						pcUrl = ap_psprintf(pPool, "%s?%s", pRequest->uri, pRequest->args);
						pcAppUrl = ap_construct_url(pPool, pcUrl, pRequest);
					}
					else
						pcAppUrl = ap_construct_url(pPool, pRequest->uri, pRequest);
				}
				else
					pcAppUrl = ap_construct_url(pPool, pConfig->pCurrentApp->pcLocation, pRequest);
			}
			
			// Remove: request=aselect_show_bar if present, otherwise we would get 2 of them
			if (pConfig->bUseASelectBar) {
				char *req = "request=aselect_show_bar";
				char *p = strstr(pcAppUrl, req);
				int len = strlen(req);
				if (p) {
					TRACE1("Removed: %s", req);
					if (p > pcAppUrl && *(p-1) == '&') {
						p--; len++;
					}
					pcAppUrl = ap_psprintf(pPool, "%.*s%s", (int)(p-pcAppUrl), pcAppUrl, p+len);
				}
			}

                        
                        // RH, 20161107, sn
//                        char *headerName = "X-Requested-With";
//                        char *headerValue = NULL;
//                        headerValue = aselect_filter_get_header(pPool, headers_in, headerName);
                        // RH, 20161107, sn
                        char *res = evaluateHTTPResultCode(pRequest, pPool, pConfig);
                        if (res) { // only if specific header found
                            // we'll leave iError=ASELECT_FILTER_ASAGENT_ERROR_OK and set iRet to resultcode from config
//                                iRet=HTTP_UNAUTHORIZED;
                            iRet=atoi(res);
                            TRACE1("iRet is now: %d", iRet);
                        }
                        else {  // we didn't find specific header, do like we used to
                        // RH, 20161107, en
                            TRACE1("Redirect for authentication to app_url: %s", pcAppUrl);
                            if ((pcResponseAU = aselect_filter_auth_user(pRequest, pPool, pConfig, pcAppUrl, &timer_data))) {
                                    iError = aselect_filter_get_error(pPool, pcResponseAU);
                            }

                            if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {    // do something with specific header for XmlHttpRequest here
                                    TRACE1("response: %s", pcResponseAU);
                                    //
                                    // build the redirection URL from the response
                                    //
                                    if ((pcRID = aselect_filter_get_param(pPool, pcResponseAU, "rid", "&", TRUE))) {
                                            if ((pcASelectServer = aselect_filter_get_param(pPool, pcResponseAU, "a-select-server", "&", TRUE))) {
                                                    if ((pcASUrl = aselect_filter_get_param(pPool, pcResponseAU, "as_url", "&", TRUE))) {
                                                            iRet = aselect_filter_gen_top_redirect(pPool, addedSecurity, pRequest, pcASUrl,
                                                                                    pcASelectServer, pcRID, pConfig->pCurrentApp->pcLocation);
                                                    }
                                                    else {
                                                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                                    }
                                            }
                                            else {
                                                    iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                            }
                                    }
                                    else {
                                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                    }
                            }
                            else {
                                    TRACE1("aselect_filter_auth_user FAILED (%d)", iError);
                                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, pRequest,
                                            /*ap_psprintf(pPool, */"ASELECT_FILTER:: aselect_filter_auth_user FAILED (%d)", iError);
                            }
                        }   // RH, 20161107, n
			break;

		case ASELECT_FILTER_ACTION_SET_TICKET:
			//
			// Generate & set A-Select cookies
			//
			TRACE3("Action: ASELECT_FILTER_ACTION_SET_TICKET: %s - %s - %s", pcTicketOut, pcUIDOut, pcOrganizationOut);
			// Bauke: added: Pass attributes in a cookie
			if (strchr(pConfig->pcPassAttributes,'c')!=0 || strchr(pConfig->pcPassAttributes,'C')!=0) {
//				pcCookie4 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectattributes", 
				pcCookie4 = ap_psprintf(pPool, "%s=%s; path=%s;%s", "aselectattributes", 
					(pcAttributes == NULL) ? "" : pcAttributes, pcCookiePath, addedSecurity);
				TRACE1("Set-Cookie: %s", pcCookie4);
				ap_table_add(headers_out, "Set-Cookie", pcCookie4); 
			}
			else if (strchr(pConfig->pcPassAttributes,'q')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0 ||
					strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'H')!=0) {  // Bauke: added 'H'
				// Pass attributes in the html header and/or query string
				iError = aselect_filter_passAttributesInUrl(iError, pcAttributes, passUsiAttribute, pPool,
						pRequest, pConfig, pcTicketOut, pcRequestLanguage, headers_in, &timer_data);
			}
//			pcCookie = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectticket", pcTicketOut, pcCookiePath, addedSecurity);
			pcCookie = ap_psprintf(pPool, "%s=%s; path=%s;%s", "aselectticket", pcTicketOut, pcCookiePath, addedSecurity);
			TRACE1("Set-Cookie: %s", pcCookie);
			ap_table_add(headers_out, "Set-Cookie", pcCookie); 
			if (strchr(pConfig->pcPassAttributes,'C')!=0) {  // 20120703: Bauke: added for backward compatibility
//				pcCookie2 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectuid", pcUIDOut, pcCookiePath, addedSecurity);
				pcCookie2 = ap_psprintf(pPool, "%s=%s; path=%s;%s", "aselectuid", pcUIDOut, pcCookiePath, addedSecurity);
				TRACE1("Set-Cookie: %s", pcCookie2);
				ap_table_add(headers_out, "Set-Cookie", pcCookie2); 
			}
			//pcCookie3 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectorganization",
			//		pcOrganizationOut, pcCookiePath, addedSecurity);
			//TRACE1("Set-Cookie: %s", pcCookie3);
			//ap_table_add(headers_out, "Set-Cookie", pcCookie3); 

			// Filter out application parameters
			TRACE2("SecureUrl=%d RequestArgs: '%s'", pConfig->bSecureUrl, pRequest->args);
			pRequest->args = extractApplicationParameters(pPool, pRequest->args);
			TRACE1("Ticket SET --> pRequest->args='%s'",pRequest->args);

			iRet = aselect_filter_gen_authcomplete_redirect(pPool, pRequest, pConfig);
			// always returns DONE
			break;

		case ASELECT_FILTER_ACTION_ACCESS_DENIED:
			TRACE("Action: ACCESS_DENIED");
			break;

		default:
			// Access is denied or unknown action: ACCESS DENIED
			break;
		}
    }
    if (iError != ASELECT_FILTER_ERROR_OK) {
        if (aselect_filter_gen_error_page(pPool, pRequest, iError, pConfig->pcErrorTemplate) == ASELECT_FILTER_ERROR_OK)
            iRet = DONE;
    }

    // Bauke: added
    TRACE4("==== 4. Attributes iError=%d iAction=%s iRet=%s attrs=%.30s", iError, filter_action_text(iAction),
		    filter_return_text(iRet), pcAttributes);
    // Bauke, 20100520, added: iRet != DONE
    if (iRet != DONE && iError == ASELECT_FILTER_ERROR_OK && iAction == ASELECT_FILTER_ACTION_ACCESS_GRANTED) {
		// not for cookies
		if (strchr(pConfig->pcPassAttributes,'q')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0 ||
				strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'H')!=0) { // Bauke: added 'H'
			iError = aselect_filter_passAttributesInUrl(iError, pcAttributes, passUsiAttribute, pPool,
					pRequest, pConfig, pcTicketIn, pcRequestLanguage, headers_in, &timer_data);

			// Option to set overwrite attribute in aselectuid cookie
			// only when parameter values are passed in headers, because we need the X-A-aselectuid-cookie in the headers_in
			if (strchr(pConfig->pcPassAttributes,'C')!=0 && (ap_table_get(headers_in, "X-A-aselectuid-cookie") != NULL) ) {  // 20150417: Remy: added
				// TRACE1("X-A-aselectuid-cookie: %s", ap_table_get(headers_in, "X-A-aselectuid-cookie"));
				// overwrite the cookie
//				pcCookie2 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectuid",
				pcCookie2 = ap_psprintf(pPool, "%s=%s; path=%s;%s", "aselectuid",
						ap_table_get(headers_in, "X-A-aselectuid-cookie"), pcCookiePath, addedSecurity);
				TRACE1("Set-Cookie: %s", pcCookie2);
				ap_table_add(headers_out, "Set-Cookie", pcCookie2);
				ap_table_unset(headers_in, "X-A-aselectuid-cookie"); // remove from headers
			}
		}

		//iRet = DONE;
    }

    TRACE4("==== 5. Finish iError=%d iAction=%s, iRet=%s, bs=%d", iError, filter_action_text(iAction),
		    filter_return_text(iRet),pConfig->iBatchSize);

finish_filter_handler:
    // FINISH TIMER
    ok = (iRet == DONE || iAction == ASELECT_FILTER_ACTION_ACCESS_GRANTED);
    if (pConfig && pConfig->pCurrentApp) {
		char *pData, buf[1000], *pcResponse;
		int iSensorOpts = (pConfig->pcSensorOpts != NULL);

		timer_finish(&timer_data);
		strcpy(buf, pConfig->pCurrentApp->pcAppId);
		if (iSensorOpts) {
			sep = '_';
			p = strchr(pConfig->pcSensorOpts, 's');
			if (p && *(p+1) != '\0')
				sep = *(p+1);
			if (strchr(pConfig->pcSensorOpts, 'e'))
				sprintf(buf, "%s%c%s%c%s", pConfig->pCurrentApp->pcAppId, sep, pRequest->uri, sep, pConfig->pCurrentApp->pcLocation);
			else if (iSensorOpts && strchr(pConfig->pcSensorOpts, 'd'))
				sprintf(buf, "%s%c%s", pConfig->pCurrentApp->pcAppId, sep, pRequest->uri);
		}

		pData = timer_pack(pPool, &timer_data, "flt_all", buf, ok);
		if (pConfig->iBatchSize > 0 && pConfig->iSensorPort > 0 && *pConfig->pcSensorIP) {
			sprintf(buf, "GET /?request=store&data=%s HTTP/1.1\r\n", pData);
			pcResponse = aselect_filter_send_request(pRequest->server, pPool,
					pConfig->pcSensorIP, pConfig->iSensorPort, buf, strlen(buf), NULL, 0);
			if (!pcResponse) {  // disable connection
				// Does not work however, the worker is killed!
				pConfig->iSensorPort = 0;
				TRACE("Disable LbSensor");
			}
		}
		else
			TRACE1("Sensor data [%s] not sent", pData);
    }
    TRACE4("==== 6. Returning %s, ok=%d %s ? %s", filter_return_text(iRet), ok, pRequest->uri, pRequest->args);

	aselect_filter_print_table(pRequest, pRequest->headers_in, "headers_in (to application)");
	aselect_filter_print_table(pRequest, pRequest->headers_out, "headers_out (to user's browser)");

    TRACE("---- }\n====");

    // Cleanup
    if (pPool != NULL)
        ap_destroy_pool(pPool);

    return iRet;
}

// Expect trailing '=' in keyName
static char *extractValueFromList(pool *pPool, char *pSpecial, char *keyName)
{
	char *pComma, *pValue, *pResult;
	int saveS;

	if (!pSpecial)
		return NULL;

	pValue = strstr(pSpecial, keyName);
	if (!pValue)
		return NULL;

	pValue += strlen(keyName);
	pComma = strchr(pValue, ',');
	if (pComma) { saveS = *pComma; *pComma = '\0'; }
    pResult = (char *)ap_palloc(pPool, strlen(pValue)+1);
	strcpy(pResult, pValue);
	if (pComma) { *pComma = saveS; }
	return pResult;
}

/**
 * 		cleanup filter defined headers to application //
 *
 */
static int purgeApplAttributes(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig)
{
	int i, iError = 0;
    char *p, *q = NULL;

    TRACE1("purgeApplAttributes-> pRequest->args:%s", (pRequest->args)? pRequest->args: "NULL");
	aselect_filter_print_table(pRequest, pRequest->headers_in, "purgeApplAttributes->headers_in (to application)");

	for (i = 0; i < pConfig->iAttrCount; i++) {
		char condName[1200], attrValue[400], applAttrName[200];
		int purge;


		TRACE2("purgeApplAttributes->Splitting attribute filter, Attribute [%d] %s", i, pConfig->pAttrFilter[i]);
		splitAttrFilter(pConfig->pAttrFilter[i], condName, sizeof(condName),
				attrValue, sizeof(attrValue), applAttrName, sizeof(applAttrName));

		if (applAttrName[0] == '\0')  // no HTTP header name
			continue;
		TRACE3("purgeApplAttributes->Attr[%s|%s|%s]", condName, attrValue, applAttrName);

		ap_table_unset(pRequest->headers_in, applAttrName); // remove from headers to application

		// Remove the same attribute from the original attributes query string (if present), can occur more than once
		//TRACE2("Purge: name=%s request=%s", applAttrName, pRequest->args);
		for (purge=1; purge; ) {
			purge = 0;
			for (p = pRequest->args; p != NULL; p = q+1) {
				q = strstr(p, applAttrName);
				if (!q)
					break;
				// Example args: my_uid=9876&uid2=0000&uid=1234&uid=9876
				if (q==pRequest->args || *(q-1) == '&' || *(q-1) == ' ') {
					int nextChar = *(q+strlen(applAttrName));
					if (nextChar == '=' || nextChar  == '&' || nextChar == '\0') {
						purge = 1;
						break;  // handle this one
					}
				}
			}
			if (purge) {  // found, purge attribute from Request args
				char *r;
				for (r=q; *r && *r != '&'; r++)
					;
				if (*r == '&')
					r++;
				//TRACE2("Purge: %.*s", r-q, q);
				// r on begin of next attribute
				for ( ; *r; )
					*q++ = *r++;
				*q = '\0';
				TRACE2("purgeApplAttributes->Purged name=%s request=%s", applAttrName, pRequest->args);
				if (q > pRequest->args && *(q-1) == '&')  // 't was the last
					*(q-1) = '\0';
			}
	}

	}
    TRACE1("purgeApplAttributes->Finished purgeApplAttributes, pRequest->args:%s", (pRequest->args)? pRequest->args: "NULL");
	aselect_filter_print_table(pRequest, pRequest->headers_in, "purgeApplAttributes->headers_in (to application)");
	return iError;
}


//
// Bauke added: Pass attributes in the query string and/or in the header and/or in a Saml token
//
static int aselect_filter_passAttributesInUrl(int iError, char *pcAttributes, char *passUsiAttribute, pool *pPool, request_rec *pRequest,
	    PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcRequestLanguage, table *headers_in, TIMER_DATA *pt)
{
    int i, purge;
    char *pcResponse, *newArgs;

    TRACE4("passAttributesinUrl:%s iError=%d, TicketIn=%.20s..., attrs=%.30s...", pConfig->pcPassAttributes,
		iError, pcTicketIn?pcTicketIn:"NULL", pcAttributes);
    if (pcAttributes != NULL) // already got them
		return iError;

    TRACE("Attributes not available yet");
    pcResponse = aselect_filter_attributes(pRequest, pPool, pConfig, pcTicketIn, pt);
    if (!pcResponse)
		return ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;

    TRACE1("Response from Agent=[%.40s]", pcResponse);
    iError = aselect_filter_get_error(pPool, pcResponse);
    if (iError != ASELECT_FILTER_ASAGENT_ERROR_OK)
		return ASELECT_FILTER_ERROR_FAILED;

    // OK
    newArgs = "";  // Start with no args at all
    pcAttributes = aselect_filter_get_param(pPool, pcResponse, "attributes", "&", TRUE);
    if (pcAttributes || passUsiAttribute) {
		if (pcAttributes)
			pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);
		if (passUsiAttribute != NULL) { 
			if (pcAttributes != NULL)
				pcAttributes = ap_psprintf(pPool, "usi=%s&%s", passUsiAttribute, pcAttributes);
			else
				pcAttributes = ap_psprintf(pPool, "usi=%s", passUsiAttribute);
		}

		TRACE2("Start: SecureUrl=%d pRequestArgs=%s", pConfig->bSecureUrl, (pRequest->args)? pRequest->args: "NULL");
		TRACE1("Attributes from Agent: %s", pcAttributes);
		// Filter out unwanted characters in the URL
		if (pConfig->bSecureUrl && pRequest->args) {
//			aselect_filter_removeUnwantedCharacters(pRequest->args);    // RH, 20200925, o
                        TRACE("aselect_filter_removeUnwantedCharacters2");    // RH, 20200925, n
			aselect_filter_removeUnwantedCharacters2(pRequest->args);    // RH, 20200925, n
		}
		TRACE2("End: %s, AttrCount=%d", (pRequest->args)? pRequest->args: "NULL", pConfig->iAttrCount);

		// Perform attribute filtering!
		// First handle the special Saml attribute token (if present)
		if (strchr(pConfig->pcPassAttributes,'t')!=0) {  // Pass Saml token in header
			char *p, *q = NULL, hdrName[60], *pValue;
			int i, len, save = '\0';
			char *pSpecial = pConfig->pcSpecialSettings;

			p = aselect_filter_get_param(pPool, pcAttributes, "saml_attribute_token", "&", TRUE/*UrlDecode*/);
			TRACE2("token=%.100s%s", p, (strlen(p)>100)?"...": "");
			// We have a base64 encoded Saml token, pass it in a custom header
			// Note the minus signs in the header name instead of underscores
			len = (p)? strlen(p): 0;
			for (i = 1; p && *p && len > 0; i++) {
				if (len > ASELECT_FILTER_MAX_HEADER_SIZE) {
					q = p + ASELECT_FILTER_MAX_HEADER_SIZE;
					save = *q;
					*q = '\0';
				}
				sprintf(hdrName, "X-saml-attribute-token%d", i);

				pValue = extractValueFromList(pPool, pSpecial, "saml_token=");
				if (!pValue)
					pValue = p;

				TRACE2("Set HDR %s: %.100s", hdrName, pValue);
				ap_table_set(headers_in, hdrName, pValue);

				if (len > ASELECT_FILTER_MAX_HEADER_SIZE) {  // restore
					*q = save;
					p = q;
				}
				len -= ASELECT_FILTER_MAX_HEADER_SIZE;
			}
			pValue = extractValueFromList(pPool, pSpecial, "referer=");
			if (pValue) {
				TRACE2("Set HDR %s: %.100s", "Referer", pValue);
				ap_table_set(headers_in, "Referer", pValue);
			}
			if (pSpecial && strstr(pSpecial, "rewrite=")) {
				pValue = (char *)ap_table_get(headers_in, "referer");
				if (pValue) {
					TRACE2("Set HDR %s: %.100s", "Referer", pValue);
					ap_table_set(headers_in, "Referer", pValue);
				}
			}
		}

		// The config file tells us which attributes to pass on and from which source
		// Three fields separted by a comma: <condition>,<attribute_value>,<attribute_name>
		// If <condition> is empty or it evaluates to 'true' the header is written,
		// otherwise it's not.
		// <attribute_value> can be an expression (it must be enclosed by single quotes)
		// <condition> and <attribute_value> can contain attribute expressions [attr,...]
		// <attribute_name> is the name passed to the application behind the filter
		//
		for (i = 0; i < pConfig->iAttrCount; i++) {
			char *p, *q;
			int urlEncodeHdr = (strchr(pConfig->pcPassAttributes,'h')!=0);  // 'H' does not encode
			char condName[1200], attrValue[400], applAttrName[200];
			int constant = 0, override = 0;
			int searchPos = 0;  // start searching in pcAttributes

			TRACE4("Try Attribute [%d] %s ReqLng=%s EncodeHdr=%d", i, pConfig->pAttrFilter[i], pcRequestLanguage, urlEncodeHdr);
			splitAttrFilter(pConfig->pAttrFilter[i], condName, sizeof(condName),
					attrValue, sizeof(attrValue), applAttrName, sizeof(applAttrName));

			if (applAttrName[0] == '\0')  // no HTTP header name
				continue;
			//TRACE3("Attr[%s|%s|%s]", condName, attrValue, applAttrName);

			// Check condition
			if (!conditionIsTrue(pPool, pcAttributes, condName)) {
				TRACE("Do NOT include in header");
				continue;
			}


			// applAttrName has a value
			if (strcmp(applAttrName, "language")==0) {
				char *p = (pRequest->args)? strstr(pRequest->args, "language="): NULL;
				if (pcRequestLanguage != NULL) {
					// Server has a language for us, must be passed, don't skip
				}
				else if (p != NULL && (p == pRequest->args || *(p-1) == '&' || *(p-1) == ' ')) {
					// No server language, but language in application parameters, it takes precedence
					// over the A-Select attribute, leave application parameter in place
					TRACE1("Request: skip attr language: %s", p);
					continue; 
				}
			}

			// RH, 20160802, sn
			// If above particular conditions are met, headers are left untouched due to 'continue' statement
			// otherwise we'll first purge the header
			if (strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'H')!=0) {
				TRACE1("Purging HDR:%s", applAttrName);
				ap_table_unset(pRequest->headers_in, applAttrName); // remove from headers to application
			}
			// RH, 20160802, en


			// Pass this attribute, either in the Query string or in the HTTP-header
			p = NULL;
			// Handle constants first
			if (attrValue[0] != '\0') {  // try to use Attribute Value
				// Can also be a constant, e.g. 'I am a constant' (no quote escapes possible)
				if (attrValue[0] == '\'' && attrValue[strlen(attrValue)-1] == '\'') {
					p = attrValue + 1;
					attrValue[strlen(attrValue)-1] = '\0';
					// 20160320: moved here:
					// pcAttributes are URL encoded, therefore decode them
					p = replaceAttributeValues(pPool, pcAttributes, p, TRUE/*urlDecode*/);
					constant = 1;  // Allows a value of '' (empty string)
				}
			}

			if (strcmp(applAttrName, "language")==0 && pcRequestLanguage != NULL) {
				p = pcRequestLanguage; // replace any attribute value
				override = 1;  // language override
			}
			//if (p && (*p||constant)) {
			while (searchPos >= 0) {
				char *unEncoded;

				if (constant || override) {  // 20160320: moved here, override added
					// p points to the attribute value (which can be empty)
					TRACE4("attrName=%s constant=%d override=%d value=%s", applAttrName, constant, override, p);
					searchPos = -1;  // no more searching needed
				}
				else {
					// Extract the requested parameter from pcAttributes, could be multi-valued!!!
					p = aselect_filter_get_param_multi(pPool, pcAttributes, attrValue, "&", TRUE/*urlDecode*/, &searchPos);
					// Result is not URL encoded
					TRACE3("attrName=%s value=%s searchPos=%d", applAttrName, p, searchPos);
				}
				if (!p)  // no value found
					break;

				unEncoded = p;
				if (strcmp(applAttrName, "AuthHeader") != 0) { // 20111128: not for the AuthHeader
					// Add encoded parameter to URL
					p = aselect_filter_url_encode(pPool, p); // 20111206: URL encode
					if (newArgs[0])
						newArgs = ap_psprintf(pPool, "%s&%s=%s", newArgs, applAttrName, p);
					else
						newArgs = ap_psprintf(pPool, "%s=%s", applAttrName, p);
				}
				TRACE1("UrlArgs: %s", newArgs);  // URL arguments so far, always URL encoded

				// 20111206: p is no longer url encoded
				if (strcmp(applAttrName, "AuthHeader") == 0) {
					char *base64enc, *authValue;

					// Assemble a Basic authorization header
					// If 'p' already contains a colon, this is an AuthHeader expression, otherwise it's simply a username
					if (strchr(p, ':') != 0)
						authValue = ap_psprintf(pPool, "%s", p);  // <username>:<password>
					else
						authValue = ap_psprintf(pPool, "%s:", p);  // <username>:<no password>
					base64enc = aselect_filter_base64_encode(pPool, authValue);
					TRACE2("Set HDR %s: Basic %s", "Authorization", base64enc);
					ap_table_set(headers_in, "Authorization", ap_psprintf(pPool, "Basic %s", base64enc));
				}
				else if (strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'H')!=0) {  // Bauke: added 'H'
					// Pass value in the header
					TRACE2("Add HDR X-%s: %.100s", applAttrName, (urlEncodeHdr)? p: unEncoded);
					ap_table_add(headers_in, ap_psprintf(pPool, "X-%s", applAttrName), (urlEncodeHdr)? p: unEncoded);  // 20111206 decoded);
					// 20160319: TRACE2("Set HDR X-%s: %.100s", applAttrName, p);
					// 20160319, was: ap_table_set(headers_in, ap_psprintf(pPool, "X-%s", applAttrName), p);  // 20111206 decoded);
				}

			}	// RH, 20160802, moved } above purge to always purge applAttrName from pRequest->args
				// A value for 'applAttrName' was added
				// Remove the same attribute from the original attributes (if present), can occur more than once
				//TRACE2("Purge: name=%s request=%s", applAttrName, pRequest->args);
				for (purge=1; purge; ) {
					purge = 0;
					for (p = pRequest->args; p != NULL; p = q+1) {
						q = strstr(p, applAttrName);
						if (!q)
							break;
						// Example args: my_uid=9876&uid2=0000&uid=1234&uid=9876
						if (q==pRequest->args || *(q-1) == '&' || *(q-1) == ' ') {
							int nextChar = *(q+strlen(applAttrName));
							if (nextChar == '=' || nextChar  == '&' || nextChar == '\0') {
								purge = 1;
								break;  // handle this one
							}
						}
					}
					if (purge) {  // found, purge attribute from Request args
						char *r;
						for (r=q; *r && *r != '&'; r++)
							;
						if (*r == '&')
							r++;
						//TRACE2("Purge: %.*s", r-q, q);
						// r on begin of next attribute
						for ( ; *r; )
							*q++ = *r++;
						*q = '\0';
						TRACE2("Purged name=%s request=%s", applAttrName, pRequest->args);
						if (q > pRequest->args && *(q-1) == '&')  // 't was the last
							*(q-1) = '\0';
					}
//				}	// RH, 20160802, moved } above purge to always purge applAttrName from pRequest->args
			}  // handle a single argument

			TRACE3("New Arguments [%d]: %s, Request=%s", i, newArgs, pRequest->args);
		}
    }
    else {
		TRACE("No attributes in response");
		//pRequest->args = "";
		// RH, 20160802, sn
		// We still have to purge configured applAttrName(s)
		int purgeResult = purgeApplAttributes(pPool, pRequest, pConfig);
		TRACE1("==== 0. purgeApplAttributes: %s", purgeResult == 0 ? "Success" : "Failure" );
		// RH, 20160802, en

    }
    TRACE1("PassAttributes=%s", pConfig->pcPassAttributes);
    if (strchr(pConfig->pcPassAttributes,'q')!=0) {
		// Add the new args in front of the original ones, newArgs contains URL encoded values (20111206)
		if (pRequest->args && pRequest->args[0])
			pRequest->args = ap_psprintf(pPool, "%s&%s", newArgs, pRequest->args);
		else
			pRequest->args = newArgs;
		// If we want to do this, do-not encode the = and & signs!!!
		//pRequest->args = aselect_filter_url_encode(pPool, pRequest->args); // no longer needed 20111206
		TRACE1("Query args modified to [%s]", pRequest->args);
    }
    return iError;
}

//
// Split 'aselect_filter_add_attribute' value in three
//
static void splitAttrFilter(char *attrFilter, char *condName, int condLen,
		char *attrValue, int ldapLen, char *applAttrName, int attrLen)
{
	char *p, *q, buf[40];
	int len;

    p = attrFilter;
    if (condName) condName[0] = '\0';
    if (attrValue) attrValue[0] = '\0';
    if (applAttrName) applAttrName[0] = '\0';

    if (*p == ',')  // empty condName
		q = p;
    else {  // parse condition
		q = strchr(p, '(');  // e.g. contains(
		if (q) {
			sprintf(buf, ")%.*s", (int)(q-p), p);
			q = strstr(p, buf);  // e.g. )contains
			if (q) 
				q = strchr(q, ',');
			else
				TRACE2("No match '%s' found from: %s", buf, p);
		}
		if (!q) {
			q = strchr(p, ',');
		}
    }
    if (!q)  // condName
		return;

    if (condName) {
		len = (q-p < condLen)? q-p: condLen-1;
		strncpy(condName, p, len);
		condName[len] = '\0';
    }
    p = q+1;
    // p points to start of <attribute_value>
    q = strrchr(p, ',');  // 20111128: find last comma
    if (!q)  // attrValue
		return;
    if (attrValue) {
		len = (q-p < ldapLen)? q-p: ldapLen-1;
		strncpy(attrValue, p, len);
		attrValue[len] = '\0';
    }
    p = q+1;
    for (q=p; *q; q++)
		;

    //applAttrName
    if (applAttrName) {
		len = (q-p < attrLen)? q-p: attrLen-1;
		strncpy(applAttrName, p, len);
		applAttrName[len] = '\0';
    }
}

//
// Replace in 'text' all occurrences of [attr,<attr_name>]
// by the value of attribute <attr_name>
// If something goes wrong no replacement (or partial replacement) takes place
//
static char *replaceAttributeValues(pool *pPool, char *pcAttributes, char *text, int bUrlDecode)
{
    // cn=[attr,uid],org=o transforms into cn=33400056,org=o
    char *newValue = text;
    char *begin, *end, *val, buf[120];

    if (!text)
		return NULL;

    begin = strstr(newValue, "[attr,");
    for ( ; begin != NULL; begin = strstr(newValue, "[attr,")) {
		end = strchr(begin, ']');
		if (end == NULL) { // syntax error
			TRACE1("Attribute, no matching ] from: %.30s...", begin);
			break;
		}
		sprintf(buf, "%.*s", (int)(end-(begin+6)), begin+6);
		val = aselect_filter_get_param(pPool, pcAttributes, buf, "&", bUrlDecode);  // single-valued parameters only
		// substitute some
		if (val == NULL) {  // no real value has been set
			TRACE2("Parameter '%.*s' not found", strlen(buf)-1, buf);
			val = "";
		}
		//TRACE3("Replace attribute '%.*s' by '%s'", strlen(buf)-1, buf, val);
		newValue = ap_psprintf(pPool, "%.*s%s%s", (int)(begin-newValue), newValue, val, end+1);
    }
    return newValue;
}

//
// Replace function by the string "true" of "false"
// Looks like: <beginToken>value1<septoken>value2<endToken>
//             begin       arg1  end1      arg2  end2      pend
//
static char *evaluateFunction(pool *pPool, char *condValue, char *funcName)
{
    char *p, *begin, *arg1, *arg2, *end1, *end2, *pend;
    char beginToken[40], endToken[40], *sepToken = "[~]";
    char *substValue, *fun;
    int finalLen, len, not;

    if (!condValue)
		return NULL;
    sprintf(beginToken, "%s(", funcName);
    sprintf(endToken, ")%s", funcName);

    fun = funcName;
    not = (strncmp(funcName, "not_", 4) == 0)? 1: 0;
    if (not) funcName += 4;

    p = strstr(condValue, beginToken);
    for ( ; p != NULL; ) {
		end1 = arg2 = end2 = pend = NULL;
		begin = p;
		//TRACE1("evaluate=[%s]", begin);
		arg1 = begin + strlen(beginToken);
		end1 = strstr(arg1, sepToken);
		if (end1) arg2 = end1 + strlen(sepToken);
		if (arg2) end2 = strstr(arg2, endToken);
		if (end2) pend = end2 + strlen(endToken);
		//TRACE5("function=%s arg1=[%.*s] arg2=[%.*s]", fun, end1-arg1, arg1, end2-arg2, arg2);
		if (!(end1 && arg2 && end2)) {
			// must replace something to prevent loops
			TRACE1("Syntax error at: %s", begin);
			strncpy(begin, "____________________", arg1-begin-1);  // invalidate begintoken
			p = strstr(arg1, beginToken);
			return NULL; // continue;
		}

		// substitute from 'begin' to 'pend', both have a value here
		substValue = "false";

		if (strcmp(funcName, "equals") == 0) {
			if (end1-arg1 == end2-arg2 && strncmp(arg1, arg2, end1-arg1)==0)
			substValue = "true";
		}
		else if (strcmp(funcName, "contains") == 0) {
			int sav1 = *end1;
			int sav2 = *end2;
			*end1 = *end2 = '\0';
			if (strstr(arg1, arg2) != NULL)
				substValue = "true";
			*end1 = sav1;
			*end2 = sav2;
		}
		else if (strcmp(funcName, "and") == 0) {
			if (end1-arg1 == 4 && strncmp(arg1, "true", 4)==0 &&
					end2-arg2 == 4 && strncmp(arg2, "true", 4)==0)
				substValue = "true";
		}
		else if (strcmp(funcName, "or") == 0) {
			if ((end1-arg1 == 4 && strncmp(arg1, "true", 4)==0) || (end2-arg2 == 4 && strncmp(arg2, "true", 4)==0))
				substValue = "true";
		}
		// negations
		if (not) {
			if (strcmp(substValue, "true") == 0)
				substValue = "false";
			else
				substValue = "true";
		}

		finalLen = strlen(pend);
		condValue = ap_psprintf(pPool, "%.*s%s%s", (int)(begin-condValue), condValue, substValue, pend);
		len = strlen(condValue) - finalLen;  // that's where we were
		p = strstr(condValue+len, beginToken);  // and advance
		TRACE1("evaluated=[%s]", condValue);
    }
    return condValue;  // the new value
}

// Return 1 for true, 0 for false
static int conditionIsTrue(pool *pPool, char *pcAttributes, char *condValue)
{
    if (!condValue[0])
		return 1;  // true

    // Replace all [attr,<attr_name>] constructions
    TRACE1("condition=[%s]", condValue);
    condValue = replaceAttributeValues(pPool, pcAttributes, condValue, TRUE/*urlDecode*/);
    TRACE1("replaced =[%s]", condValue);

    // Next evaluate, first contains and equals
    condValue = evaluateFunction(pPool, condValue, "not_contains");
    condValue = evaluateFunction(pPool, condValue, "contains");
    condValue = evaluateFunction(pPool, condValue, "not_equals");
    condValue = evaluateFunction(pPool, condValue, "equals");
    condValue = evaluateFunction(pPool, condValue, "not_and");
    condValue = evaluateFunction(pPool, condValue, "and");
    condValue = evaluateFunction(pPool, condValue, "not_or");
    condValue = evaluateFunction(pPool, condValue, "or");

    return (condValue!=NULL && strcmp(condValue,"true")==0)?1 : 0;
}

static char *aselect_filter_findNoCasePattern(const char *text, const char *pattern)
{
	char *pptr, *sptr, *start;

	for (start = (char *)text; *start != '\0'; start++) {
		/* find start of pattern in string */
		for ( ; ((*start!='\0') && (toupper(*start) != toupper(*pattern))); start++)
			;
		if (*start == '\0')
			return NULL;

		pptr = (char *)pattern;
		sptr = (char *)start;
		while (toupper(*sptr) == toupper(*pptr)) {
			sptr++;
			pptr++;
			/* if end of pattern then pattern was found */
			if (*pptr == '\0')
				return (start);
		}
	}
	return NULL;
}

static void aselect_filter_removeUnwantedCharacters(char *args)
{
    int stop, len;
    char *p, *q;

    for (stop=0 ; !stop; ) {
		len = strlen(args);
		aselect_filter_url_decode(args);
		TRACE1("Loop: %s", (args)? args: "NULL");
		if (len == strlen(args)) {
			for (p = q = args; *q; ) {
				// 20100521, Bauke: " added to the list below
				if (*q == '%' || *q == '\r' || *q == '\n' || *q == '>' || *q == '<' || *q == '"')
					q++;
				else
					*p++ = *q++;
			}
			*p++ = '\0';
			stop = 1;
		}
    }
    for (stop=0 ; !stop; ) {
		len = strlen(args);
		p = aselect_filter_findNoCasePattern(args, "script:");
		if (p) {
			q = p + strlen("script:");
			*p++ = '_';
			for ( ; *q; ) {
				*p++ = *q++;
			}
			*p++ = *q++;  // null-byte too
		}
		if (len == strlen(args))
			break;
    }
}


//
// Use to create the per server configuration data
//
/*static void *aselect_filter_create_config(pool *pPool, server_rec *pServer)
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    TRACE("aselect_filter_create_config");
    if ((pConfig = (PASELECT_FILTER_CONFIG) ap_palloc(pPool, sizeof(ASELECT_FILTER_CONFIG))))
    {
        memset(pConfig, 0, sizeof(ASELECT_FILTER_CONFIG));
    }
    else {
	TRACE("aselect_filter_create_config::ERROR:: could not allocate memory for pConfig");
    }
    return pConfig;
}*/

static const char *aselect_filter_set_agent_address(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select IP";
    if (!(pConfig->pcASAIP = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting A-Select IP";

    TRACE1("aselect_filter_set_agent_address:: ip: %s", pConfig->pcASAIP);
    return NULL;
}

static const char *aselect_filter_set_agent_port(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcASAPort;

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select port";
    if (!(pcASAPort = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting A-Select port";

    TRACE1("aselect_filter_set_agent_port:: port: %s", pcASAPort);
    pConfig->iASAPort = atoi(pcASAPort);
    return NULL;
}

static const char *aselect_filter_set_sensor_address(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select IP";
    if (!(pConfig->pcSensorIP = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting A-Select IP";

    TRACE1("aselect_filter_set_sensor_address:: ip: %s", pConfig->pcSensorIP);
    return NULL;
}

static const char *aselect_filter_set_sensor_opts(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig || !(pConfig->pcSensorOpts = ap_pstrdup(parms->pool, (!arg)? "": arg)))
		return "A-Select ERROR: Internal error when setting Sensor Options";

    TRACE1("aselect_filter_set_sensor_opts:: %s", pConfig->pcSensorOpts);
    return NULL;
}

static const char *aselect_filter_cookie_path(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig || !(pConfig->pcCookiePath = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting CookiePath";

    TRACE1("aselect_filter_cookie_path:: %s", pConfig->pcCookiePath);
    return NULL;
}

static const char *aselect_filter_special_settings(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig || !(pConfig->pcSpecialSettings = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting SpecialSettings";

    TRACE1("aselect_filter_special_settings:: %s", pConfig->pcSpecialSettings);
    return NULL;
}

static const char *aselect_filter_set_sensor_port(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcPort;

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select port";
    if (!(pcPort = ap_pstrdup(parms->pool, arg)))
		return "A-Select ERROR: Internal error when setting A-Select port";

    TRACE1("aselect_filter_set_sensor_port:: port: %s", pcPort);
    pConfig->iSensorPort = atoi(pcPort);
    pConfig->iBatchSize = 1;  // default, send data to LbSensor
    return NULL;
}

static const char *aselect_filter_add_authz_rule(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
    int i;
    PASELECT_APPLICATION pApp;
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (pConfig) {
        for (i=0; i<pConfig->iAppCount; i++) {
            if (strcmp(pConfig->pApplications[i].pcAppId, arg1) == 0)
                break;
        }
        if (i >= pConfig->iAppCount) {
            TRACE1("aselect_filter_add_authz_rule: Unknown app_id \"%s\"", arg1);
            return "A-Select ERROR: Unknown application ID in authorization rule";
        }
        pApp = &pConfig->pApplications[i];
        if (pApp->iRuleCount == ASELECT_FILTER_MAX_RULES_PER_APP)
            return "A-Select ERROR: Maximum amount of authorization rules per application exceeded";
        pApp->pTargets[pApp->iRuleCount] = aselect_filter_url_encode(parms->pool, arg2);
        pApp->pConditions[pApp->iRuleCount] = aselect_filter_url_encode(parms->pool, arg3);
        TRACE3("aselect_filter_add_authz_rule: app=%s, target=%s, added condition \"%s\"", arg1, arg2, arg3);
        ++(pApp->iRuleCount);
    }
    else {
        return "A-Select ERROR: Internal error: missing configuration object";
    }
    return NULL;
}

// 20140422, Bauke added
// Boolean to use regular expressions in the add_public_app and add_secure_app handling
//
static const char *aselect_filter_add_app_regexp(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG)ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *p;

    if (!pConfig)
		return "A-Select ERROR: Internal error when setting add_app_regexp";

	p = ap_pstrdup(parms->pool, arg);
	if (!p)
		return "A-Select ERROR: Internal error when setting add_app_regexp";

	TRACE1("aselect_filter_add_app_regexp:: %s", p);
	pConfig->bUseRegexp = TRUE;  // the default
	if (strcmp(p, "0") == 0) {
		pConfig->bUseRegexp = FALSE;
	}
    return NULL;
}

static const char *aselect_filter_add_secure_app(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
    static char *_empty = "";
    const char *pcTok, *pcEnd;
    PASELECT_APPLICATION pApp;
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig) {
        return "A-Select ERROR: Internal error: missing configuration object";
    }
    if (pConfig->iAppCount >= ASELECT_FILTER_MAX_APP) {
		return "A-Select ERROR: Reached max possible application IDs";
    }
    pApp = &pConfig->pApplications[pConfig->iAppCount];
    memset(pApp, 0, sizeof(ASELECT_APPLICATION));
    pApp->bEnabled = 1;
    pApp->pcUid = _empty;
    pApp->pcAuthsp = _empty;
    pApp->pcLanguage = _empty;
    pApp->pcCountry = _empty;
    pApp->pcExtra = _empty;
    pApp->pcRemoteOrg = _empty;
    pApp->pcRedirectURL = _empty;
    if (!((pApp->pcLocation = ap_pstrdup(parms->pool, arg1)) && (pApp->pcAppId = ap_pstrdup(parms->pool, arg2)))) {
		return "A-Select ERROR: Out of memory while adding applications";
    }
    if (strcmp(arg3, "none") != 0 && strcmp(arg3, "default") != 0) {
		pcTok = arg3;
		while (*pcTok) {
			TRACE1("Parsing application options token %s", pcTok);
			if (strncmp(pcTok, "forced-logon", 12) == 0 || strncmp(pcTok, "forced_logon", 12) == 0) {
				pcTok += 12;
				pApp->bForcedLogon = 1;
			}
			else if (strncmp(pcTok, "disabled", 8) == 0) {
				pcTok += 8;
				pApp->bEnabled = 0;
			}
			else if (strncmp(pcTok, "uid=", 4) == 0) {
				pcTok += 4;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcUid = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcUid = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcUid);
				pApp->pcUid = ap_psprintf(parms->pool, "&uid=%s",
					aselect_filter_url_encode(parms->pool, pApp->pcUid));
			}
			/* Bauke: added to force the AuthSP choice */
			else if (strncmp(pcTok, "authsp=", 7) == 0) {
				pcTok += 7;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcAuthsp = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcAuthsp = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcAuthsp);
				pApp->pcAuthsp = ap_psprintf(parms->pool, "&authsp=%s",
					aselect_filter_url_encode(parms->pool, pApp->pcAuthsp));
			}
			else if (strncmp(pcTok, "language=", 9) == 0) {
				pcTok += 9;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcLanguage = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcLanguage = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcLanguage);
				pApp->pcLanguage = ap_psprintf(parms->pool, "&language=%s",
					aselect_filter_url_encode(parms->pool, pApp->pcLanguage));
			}
			else if (strncmp(pcTok, "country=", 8) == 0) {
				pcTok += 8;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcCountry = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcCountry = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcCountry);
				pApp->pcCountry = ap_psprintf(parms->pool, "&country=%s",
					aselect_filter_url_encode(parms->pool, pApp->pcCountry));
			}
			else if (strncmp(pcTok, "remote_organization=", 20) == 0 || strncmp(pcTok, "remote-organization=", 20) == 0) {
				pcTok += 20;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcRemoteOrg = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcRemoteOrg = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcRemoteOrg);
				pApp->pcRemoteOrg = ap_psprintf(parms->pool, "&remote_organization=%s",
					aselect_filter_url_encode(parms->pool, pApp->pcRemoteOrg));
			}
			else if (strncmp(pcTok, "url=", 4) == 0) {
				pcTok += 4;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcRedirectURL = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcRedirectURL = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcRedirectURL);
			}
			else if (strncmp(pcTok, "extra_parameters=", 17) == 0 || strncmp(pcTok, "extra-parameters=", 17) == 0) {
				pcTok += 17;
				if ((pcEnd = strchr(pcTok, ',')))
					pApp->pcExtra = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
				else
					pApp->pcExtra = ap_pstrdup(parms->pool, pcTok);
				pcTok += strlen(pApp->pcExtra);
				pApp->pcExtra = ap_psprintf(parms->pool, "&%s",
					pApp->pcExtra);
			}
			else { // Unknown option
				return ap_psprintf(parms->pool, "A-Select ERROR: Unknown option in application %s near \"%s\"", pApp->pcAppId, pcTok);
			}
			if (*pcTok) {
				if (*pcTok != ',')
					return ap_psprintf(parms->pool, "A-Select ERROR: Error in application %s options, near \"%s\"", pApp->pcAppId, pcTok);
				++pcTok;
			}                        
		}
    }
    // Success!
    pConfig->iAppCount++;
    return NULL;
}

// 20091223: Bauke, added
// Allow to switch off the Secure and HttpOnly mechanism
//
static const char *aselect_filter_added_security(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    TRACE1("aselect_filter_added_security:: arg=%s", arg);
    if (!pConfig) {
		return "A-Select ERROR: Internal error during added_security";
    }
    strcpy(pConfig->pcAddedSecurity, "");
    // RH, 20200812, so
    if (!arg || strstr(arg, "cookies") != NULL)  // It's the default as well
		strcat(pConfig->pcAddedSecurity, "c");  // add Secure & HttpOnly to cookies
    // RH, 20200812, eo
    // RH, 20200812, sn
    if (!arg || strstr(arg, "cookies") != NULL || strstr(arg, "samesitenone") != NULL)  // It's the default as well
		strcat(pConfig->pcAddedSecurity, "c");  // add Secure & HttpOnly to cookies
    else
    {
    if (arg && strstr(arg, "samesitelax") != NULL)  // It's the default as well
		strcat(pConfig->pcAddedSecurity, "s");  // add Secure & HttpOnly to cookies
    else 
    if (arg && strstr(arg, "samesitestrict") != NULL)  // It's the default as well
		strcat(pConfig->pcAddedSecurity, "S");  // add Secure & HttpOnly to cookies
    }
    // RH, 20200812, en

    TRACE1("aselect_filter_added_security:: %s", pConfig->pcAddedSecurity);
    return NULL;
}

// 20091223: Bauke, added
// Specify the name and location of the log file (not mandatory)
//
static const char *aselect_filter_set_logfile(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

	if (!pConfig) {
		return "A-Select ERROR: Internal error when setting log_file";
	}
    // goes to stdout: ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, parms->server, "ASELECT_FILTER:: logfile set");
    pConfig->pcLogFileName = (arg)? ap_pstrdup(parms->pool, arg): NULL;
    aselect_filter_trace_logfilename(pConfig->pcLogFileName);
    TRACE1("aselect_filter_set_logfile:: %s", pConfig->pcLogFileName);
    return NULL;
}

// Bauke: added
// Read all attributes that must be passed in the HTML header from the config file
//
static const char *aselect_filter_add_attribute(cmd_parms *parms, void *mconfig, const char *arg)
{
    char **pAttr;
    PASELECT_FILTER_CONFIG pConfig;

    pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    if (!pConfig) {
		return "A-Select ERROR: Internal error when setting add_attribute";
    }
    if (pConfig->iAttrCount >= ASELECT_FILTER_MAX_ATTR) {
		return "A-Select ERROR: Reached max possible Attribute Filters";
    }
    pAttr = &pConfig->pAttrFilter[pConfig->iAttrCount];
    *pAttr = ap_pstrdup(parms->pool, arg);
    // Use Apache logging only
    TRACE2("aselect_filter_add_attribute:: [%d] %s", pConfig->iAttrCount, *pAttr);
    // Goes to stdout:
    //ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, parms->server,
	//       "aselect_filter_add_attribute:: [%d] %s", pConfig->iAttrCount, *pAttr);
    pConfig->iAttrCount++;
    return NULL;
}

// Bauke: 20110129: added
// Define public applications
//
static const char *aselect_filter_add_public_app(cmd_parms *parms, void *mconfig, const char *arg)
{
    char **pPublic;
    PASELECT_FILTER_CONFIG pConfig;

    pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    if (!pConfig) {
		return "A-Select ERROR: Internal error when setting add_public app";
    }
    if (pConfig->iPublicAppCount >= ASELECT_FILTER_MAX_APP) {
		return "A-Select ERROR: Reached max possible Applications";
    }
    pPublic = &pConfig->pPublicApps[pConfig->iPublicAppCount];
    *pPublic = ap_pstrdup(parms->pool, arg);
    TRACE2("aselect_filter_add_public_app:: [%d] %s", pConfig->iPublicAppCount, *pPublic);
    pConfig->iPublicAppCount++;
    return NULL;
}

static const char *aselect_filter_set_redirection_mode(cmd_parms *parms, void *mconfig, const char *arg)
{
	PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
	char *pcMode;
	if (pConfig) {
		if ((pcMode = ap_pstrdup(parms->pool, arg))) {
			if (strcasecmp(pcMode, "app") == 0) {
				pConfig->iRedirectMode = ASELECT_FILTER_REDIRECT_TO_APP;
			}
			else if (strcasecmp(pcMode, "full") == 0) {
				pConfig->iRedirectMode = ASELECT_FILTER_REDIRECT_FULL;
			}
			else {
				return "A-Select ERROR: Invalid argument to aselect_filter_set_redirect_mode";
			}
			TRACE2("aselect_filter_set_redirect_mode:: %d (%s)", pConfig->iRedirectMode,
					(pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_TO_APP) ? "app" : "full");
		}
		else{
			return "A-Select ERROR: Internal error while setting redirect_mode";
		}
	}
	return NULL;
}

static const char *
aselect_filter_set_html_error_template(cmd_parms *parms, void *mconfig, const char *arg)
{
	PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
	FILE    *file;
	fpos_t  fpos;
	int     ipos;
	char    cLine[100];
	char    *pcFile;

	if (pConfig) {
		if ((pcFile = ap_pstrdup(parms->pool, arg))) {
			TRACE1("aselect_filter_set_html_error_template:: %s", pcFile);
			if ((file = fopen(pcFile, "r"))) {
				if (fseek(file, 0, SEEK_END) == 0) {
						if (fgetpos(file, &fpos) == 0) {
							memcpy(&ipos, &fpos, sizeof(ipos));
							TRACE1("aselect_filter_set_html_error_template:: size of template: %d", ipos);
							if (fseek(file, 0, SEEK_SET) == 0) {
								if ((pConfig->pcErrorTemplate = (char*) ap_palloc(parms->pool, ipos))) {
									memset(pConfig->pcErrorTemplate, 0, sizeof(ipos));
									while (fgets(cLine, sizeof(cLine), file) != NULL)
										strcat(pConfig->pcErrorTemplate, cLine);
								}
								else {
									TRACE("aselect_filter_set_html_error_template:: failed to allocate mem for pConfig->pcErrorTemplate");
									fclose(file);
									return "A-Select ERROR: Internal error when setting html_error_template file";
								}
							}
							else {
								TRACE("aselect_filter_set_html_error_template:: fseek(SEEK_SET) failed");
								fclose(file);
								return "A-Select ERROR: Internal error when setting html_error_template file";
							}
						}
						else {
							fclose(file);
							TRACE("aselect_filter_set_html_error_template:: fgetpos failed");
							return "A-Select ERROR: Internal error when setting html_error_template file";
						}
				}
				else {
						TRACE("aselect_filter_set_html_error_template:: fseek(SEEK_END) failed");
						fclose(file);
						return "A-Select ERROR: Internal error when setting html_error_template file";
				}
				fclose(file);
			}
			else {
					TRACE("aselect_filter_set_html_error_template:: fopen failed");
					return "A-Select ERROR: Could not open html_error_template";
			}
		}
		else {
			return "A-Select ERROR: Internal error when setting html_error_template file";
		}
	}
	else {
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	return NULL;
}

// Bauke, 20080928, Logout Template added
static const char *aselect_filter_set_html_logout_template(cmd_parms *parms, void *mconfig, const char *arg)
{
	char *funName = "aselect_filter_set_html_logout_template";
	PASELECT_FILTER_CONFIG pConfig;
	FILE    *file;
	fpos_t  fpos;
	int     ipos;
	char    cLine[100];
	char    *pcFile;

	pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
	if (!pConfig) {
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	pcFile = ap_pstrdup(parms->pool, arg);
	if (!pcFile) {
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	TRACE2("%s:: %s", funName, pcFile);
	file = fopen(pcFile, "r");
	if (!file) {
		TRACE1("%s:: fopen failed", funName);
		return "A-Select ERROR: Could not open html_error_template";
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		TRACE1("%s:: fseek(SEEK_END) failed", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	if (fgetpos(file, &fpos) != 0) {
		fclose(file);
		TRACE1("%s:: fgetpos failed", funName);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	memcpy(&ipos, &fpos, sizeof(ipos));
	TRACE2("%s:: size of template: %d", funName, ipos);
	if (fseek(file, 0, SEEK_SET) != 0) {
		TRACE1("%s:: fseek(SEEK_SET) failed", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	if ((pConfig->pcLogoutTemplate = (char*) ap_palloc(parms->pool, ipos))) {
		memset(pConfig->pcLogoutTemplate, 0, sizeof(ipos));
		while (fgets(cLine, sizeof(cLine), file) != NULL)
			strcat(pConfig->pcLogoutTemplate, cLine);
	}
	else {
		TRACE1("%s:: failed to allocate mem for pConfig->pcLogoutTemplate", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	fclose(file);
        return NULL;
}

static const char *aselect_filter_set_use_aselect_bar(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG)
	    ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcUseASelectBar;

    TRACE1("aselect_filter_set_use_aselect_bar:: arg=%s", arg);
    if (pConfig) {
		if ((pcUseASelectBar = ap_pstrdup(parms->pool, arg))) {
			TRACE1("aselect_filter_set_use_aselect_bar:: %s", pcUseASelectBar);
			pConfig->bUseASelectBar = FALSE;

			if (strcasecmp(pcUseASelectBar, "1") == 0)
				pConfig->bUseASelectBar = TRUE;
		}
		else {
			return "A-Select ERROR: Internal error when setting use_aselect_bar";
		}
    }
    else {
		return "A-Select ERROR: Internal error when setting use_aselect_bar";
    }
    return NULL;
}

// Bauke 20081108: added
// Boolean to activate URL escape sequence removal
//
static const char *aselect_filter_secure_url(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcSecureUrl;

    if (pConfig) {
		if ((pcSecureUrl = ap_pstrdup(parms->pool, arg))) {
			TRACE1("aselect_filter_secure_url:: %s", pcSecureUrl);
			pConfig->bSecureUrl = TRUE;  // the default
//			if (strcmp(pcSecureUrl, "0") == 0)  // RH, 20200929, o
			if (pcSecureUrl && strcmp(pcSecureUrl, "0") == 0)  // RH, 20200929, n
				pConfig->bSecureUrl = FALSE;
		}
		else {
			return "A-Select ERROR: Internal error when setting secure_url";
		}
    }
    else {
		return "A-Select ERROR: Internal error when setting secure_url";
    }
    return NULL;
}

static const char *aselect_filter_pass_attributes(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcPassAttr;

    if (pConfig) {
		if ((pcPassAttr = ap_pstrdup(parms->pool, arg))) {
			TRACE1("aselect_filter_pass_attributes:: %s", pcPassAttr);
			pConfig->pcPassAttributes[0] = '\0';
			if (strchr(pcPassAttr, 'c') != 0)  // pass attributes in a cookie: aselectattributes
				strcat(pConfig->pcPassAttributes,"c");
			if (strchr(pcPassAttr, 'C') != 0)  // pass attributes in a cookie: aselectattributes, aselectuid, also use header: X-A-aselectuid-cookie
				strcat(pConfig->pcPassAttributes,"C");
			if (strchr(pcPassAttr, 'q') != 0)  // attributes in the query string, URL encoded
				strcat(pConfig->pcPassAttributes,"q");
			if (strchr(pcPassAttr, 'h') != 0)  // attributes in headers, URL encode the value
				strcat(pConfig->pcPassAttributes,"h");
			if (strchr(pcPassAttr, 'H') != 0)  // attributes in headers but do not URL encode
				strcat(pConfig->pcPassAttributes,"H");
			if (strchr(pcPassAttr, 't') != 0)  // attributes as SAML token in a header
				strcat(pConfig->pcPassAttributes,"t");
		}
		else {
			return "A-Select ERROR: Internal error when setting pass_attributes";
		}
    }
    else {
		return "A-Select ERROR: Internal error when setting pass_attributes";
    }
    return NULL;
}

// Define all http headers that should be handled differently from the config file
//
static const char *aselect_filter_add_header_handling(cmd_parms *parms, void *mconfig, const char *arg)
{
    char **pHeader;
    PASELECT_FILTER_CONFIG pConfig;

    pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    if (!pConfig) {
		return "A-Select ERROR: Internal error when setting HTTP header handlers";
    }
    if (pConfig->iHeaderHandlerCount >= ASELECT_FILTER_MAX_HEADER_HANDLERS) {
		return "A-Select ERROR: Reached max possible HTTP header handlers";
    }
    pHeader = &pConfig->pHeaderHandler[pConfig->iHeaderHandlerCount];
    *pHeader = ap_pstrdup(parms->pool, arg);
    TRACE2("aselect_filter_add_header_handling:: [%d] %s", pConfig->iHeaderHandlerCount, *pHeader);
    pConfig->iHeaderHandlerCount++;
    return NULL;
}



//
// Registered cmds to call from httpd.conf
//
static const command_rec aselect_filter_cmds[] = 
{
    AP_INIT_TAKE1( "aselect_filter_set_agent_address", aselect_filter_set_agent_address, NULL, RSRC_CONF,
        "Usage aselect_filter_set_agent_address <ip or dns name of A-Select Agent>, example: aselect_filter_set_agent_address \"localhost\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_agent_port", aselect_filter_set_agent_port, NULL, RSRC_CONF,
        "Usage aselect_filter_set_agent_port <port of A-Select Agent>, example: aselect_filter_set_agent_port \"1495\"" ),

    AP_INIT_TAKE3( "aselect_filter_add_secure_app", aselect_filter_add_secure_app, NULL, RSRC_CONF,
        "Usage aselect_filter_add_secure_app <location> <application id> <flags>, example: aselect_filter_add_secure_app \"///secure///\" \"app1\" \"forced-logon\"" ),
    AP_INIT_TAKE3( "aselect_filter_add_authz_rule", aselect_filter_add_authz_rule, NULL, RSRC_CONF,
        "Usage aselect_filter_add_authz_rule <application id> <target uri> <condition>, example: aselect_filter_add_authz_rule \"app1\" \"*\" \"role=student\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_html_error_template", aselect_filter_set_html_error_template, NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_error_template <path to template html page>, example: aselect_filter_set_html_error_template \"///usr//local//apache//aselect//error.html\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_html_logout_template", aselect_filter_set_html_logout_template, NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_logout_template <path to template html page>, example: aselect_filter_set_html_logout_template \"///usr//local//apache//aselect//logout.html\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_use_aselect_bar", aselect_filter_set_use_aselect_bar, NULL, RSRC_CONF,
        "Usage aselect_filter_set_use_aselect_bar <on or off>, example: aselect_filter_set_use_aselect_bar on" ),
    AP_INIT_TAKE1("aselect_filter_set_redirect_mode", aselect_filter_set_redirection_mode, NULL, RSRC_CONF,
        "Usage aselect_filter_redirect_mode <app | full>, example: aselect_filter_redirect_mode \"app\""),

// Bauke: added entries
    AP_INIT_TAKE1("aselect_filter_secure_url", aselect_filter_secure_url, NULL, RSRC_CONF,
        "Usage: aselect_filter_secure_url < 0 | 1 >, example: aselect_filter_secure_url \"1\""),

    AP_INIT_TAKE1("aselect_filter_pass_attributes", aselect_filter_pass_attributes, NULL, RSRC_CONF,
        "Usage: aselect_filter_pass_attributes < c | q | h >, example: aselect_filter_pass_attributes \"ch\"" ),

    AP_INIT_TAKE1("aselect_filter_add_attribute", aselect_filter_add_attribute, NULL, RSRC_CONF,
        "Usage: aselect_filter_add_attribute <vaule>, example: aselect_filter_add_attribute \"0\""),

    AP_INIT_TAKE1("aselect_filter_add_public_app", aselect_filter_add_public_app, NULL, RSRC_CONF,
        "Usage: aselect_filter_add_public_app < app_url >, example: aselect_filter_add_public_app \"/website\""),

    AP_INIT_TAKE1("aselect_filter_added_security", aselect_filter_added_security, NULL, RSRC_CONF,
        "Usage: aselect_filter_added_security < cookies | >, example: aselect_filter_added_security \"cookies\"" ),

    AP_INIT_TAKE1("aselect_filter_set_logfile", aselect_filter_set_logfile, NULL, RSRC_CONF,
        "Usage: aselect_filter_set_logfile <filename>, example: aselect_filter_set_logfile \"/tmp/aselect_filter.log\""),

    AP_INIT_TAKE1("aselect_filter_set_sensor_address", aselect_filter_set_sensor_address, NULL, RSRC_CONF,
        "Usage aselect_filter_set_sensor_address <ip or dns name of a Sensor process>, example: aselect_filter_set_sensor_address \"localhost\""),

    AP_INIT_TAKE1( "aselect_filter_set_sensor_port", aselect_filter_set_sensor_port, NULL, RSRC_CONF,
        "Usage aselect_filter_set_sensor_port <port of a Sensor process>, example: aselect_filter_set_sensor_port \"1805\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_sensor_opts", aselect_filter_set_sensor_opts, NULL, RSRC_CONF,
        "Usage aselect_filter_set_sensor_opts <options>, example: aselect_filter_set_sensor_opts \"d\"" ),

    AP_INIT_TAKE1("aselect_filter_cookie_path", aselect_filter_cookie_path, NULL, RSRC_CONF,
        "Usage aselect_filter_cookie_path <value>"),

    AP_INIT_TAKE1("aselect_filter_special_settings", aselect_filter_special_settings, NULL, RSRC_CONF,
        "Usage aselect_filter_special_settings <value>"),

    AP_INIT_TAKE1("aselect_filter_add_app_regexp", aselect_filter_add_app_regexp, NULL, RSRC_CONF,
        "Usage aselect_filter_add_app_regexp < 0 | 1 >"),

    // RH, 20161108, sn
    AP_INIT_TAKE1("aselect_filter_add_header_handling", aselect_filter_add_header_handling, NULL, RSRC_CONF,
        "Usage aselect_filter_add_header_handling  <result_code>,<headername>,<headervalue>,<preserve_rfc>, example: aselect_filter_add_header_handling \"401,X-Requested-With,XMLHttpRequest,false\""),

    // RH, 20161108, sn
    
    { NULL }
};

// Called before logfile can be set, therefore use ap_log_error()
void *aselect_filter_create_server_config(apr_pool_t *pPool, server_rec *pServer)
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    // Logs on stdout
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer, "aselect_filter_create_server_config");
    pConfig = (PASELECT_FILTER_CONFIG) apr_palloc(pPool, sizeof(ASELECT_FILTER_CONFIG));
    if (!pConfig) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, pServer,
			"aselect_filter_create_server_config::ERROR:: could not allocate memory for pConfig");
		return NULL;
    }
    memset( pConfig, 0, sizeof( ASELECT_FILTER_CONFIG ) );
    pConfig->bSecureUrl = TRUE;  // RH, 20200928, only place to set it before config hooks
    return pConfig;
}

// Called before logfile can be set
void aselect_filter_register_hooks(apr_pool_t *p)
{
    //TRACE("aselect_filter_register_hooks");
    ap_hook_post_config( aselect_filter_init, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_access_checker( aselect_filter_handler, NULL, NULL, APR_HOOK_MIDDLE );
}

module AP_MODULE_DECLARE_DATA aselect_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   // per-directory config creator
    NULL,                   // dir config merger
    aselect_filter_create_server_config,    // server config creator
    NULL,                   // server config merger
    aselect_filter_cmds,            // command table
    aselect_filter_register_hooks,      //  set up other request processing hooks
};
