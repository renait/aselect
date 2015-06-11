/**
 * 
 */
package org.aselect.server.log.filter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

// import org.slf4j.MDC;
import org.apache.log4j.MDC;
import org.aselect.server.crypto.CryptoEngine;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.server.request.HandlerTools;
import org.aselect.server.tgt.TGTManager;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectCommunicationException;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.servlet.filter.BasicFilter;
import org.aselect.system.utils.Utils;

/**
 * @author RH
 */
public class SanityFilter extends BasicFilter
{
	private  static final String _MODULE = "SanityFilter";

	private HashMap htTGTContext;
	
	protected ASelectSystemLogger _logger;


	/*
	 * (non-Javadoc)
	 * @see javax.servlet.Filter#destroy()
	 */
	@Override
	public void destroy()
	{
	}

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 * javax.servlet.FilterChain)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
	throws IOException, ServletException
	{
		final String sMethod = "doFilter()";
		super.doFilter(request, response, chain);
		// Retrieves the session object from the current request.
		// HttpSession session =
		// ((HttpServletRequest)request).getSession(false);
		HttpSession session = ((HttpServletRequest) request).getSession(false);

		String remoteAddress =  request.getRemoteAddr();
		_logger.log(Level.FINEST, _MODULE, sMethod, "remoteAddress:" + remoteAddress + ", HttpSession:" + session.getId());
		String sTgT = null;

		Set<String> keys = requestParms.keySet();
		String aselectRequest = request.getParameter("request");
		_logger.log(Level.FINEST, _MODULE, sMethod, "aselectRequest:" + aselectRequest + ", Looking for request parameters:" + keys);
		for (String s : keys) {	// handle requestparms
			String parm = s;
			// Enumeration parms = requestParms.keys();
			// while (parms.hasMoreElements()) {
			// String parm = (String)parms.nextElement();
//			if ( "rid".equalsIgnoreCase(parm) ) {
//				// find in session
//			}
			if ( "aselect_credentials".equalsIgnoreCase(parm) ) {
				sTgT = request.getParameter(parm);
			}
			if ( "crypted_credentials".equalsIgnoreCase(parm) ) {
				sTgT = request.getParameter(parm);
				if ( sTgT != null ) {
					try {
						sTgT = org.aselect.server.utils.Utils.decodeCredentials(sTgT, _logger);
						if (sTgT == null) {
							_logger.log(Level.FINEST, _MODULE, sMethod, "Can not decode credentials");
							throw new ASelectException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
						}
					}
					catch (ASelectException e) {
						throw new ServletException(Errors.ERROR_ASELECT_SERVER_TGT_NOT_VALID);
					}
				}
			}
			if (sTgT != null) {
				_logger.log(Level.FINEST, _MODULE, sMethod, "Looking for request tgt key:" + sTgT);
				htTGTContext = TGTManager.getHandle().getTGT(sTgT);
				if (htTGTContext != null) {
					String requestParm = (String) requestParms.get(parm);
					// Enumeration cookieParms = tgtParms.keys();
					// while (cookieParms.hasMoreElements()) {
					// String cookieParm =
					// (String)cookieParms.nextElement();
					String parmVal = (String) htTGTContext.get(requestParm);
					if ( parmVal != null ) {
						_logger.log(Level.FINEST, _MODULE, sMethod, "In requestParm: " + parm  + " ,found: " + requestParm + ", with value: " + parmVal + " , does" +  ( remoteAddress.equalsIgnoreCase(parmVal) ? "" : " NOT" ) + " equal remoteAddress:" + remoteAddress);
						if ( true && !remoteAddress.equalsIgnoreCase(parmVal) ) {	// Maybe introduce init "reject" parameter for this
							// better to call errorrequesthanlder here through redirect
							_logger.log(Level.WARNING, _MODULE, sMethod, "In requestParm: " + parm  + " ,found: " + requestParm + ", with value: " + parmVal + " , does" +  ( remoteAddress.equalsIgnoreCase(parmVal) ? "" : " NOT" ) + " equal remoteAddress:" + remoteAddress);
							throw new ServletException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
					} else {
						_logger.log(Level.FINEST, _MODULE, sMethod, requestParm + ":" + parmVal + " NOT found in tgt context");
					}
//						MDC.put(tgtParms.get(cookieParm), parmVal == null ? "" : parmVal);
				} else {
					_logger.log(Level.FINEST, _MODULE, sMethod, "No tgt found for requestParm: " +parm + ", with value" + ":" + sTgT);
				}
			} else {
				_logger.log(Level.FINEST, _MODULE, sMethod, "No tgt parm value found in request for parm: " + parm);
			}

		}
		keys = cookies.keySet();
		for (String s : keys) {	// handle cookies
			String cookieName = s;
			// Enumeration logCookies = cookies.keys();
			// while (logCookies.hasMoreElements()) {
			// String cookieName = (String)logCookies.nextElement();
//			String cookieValue = HandlerTools.getCookieValue((HttpServletRequest) request, cookieName, null);
//			if ( "rid".equalsIgnoreCase(cookieName) ) {	// will normally not happen
//				// find in session
//			}
			if ( "aselect_credentials".equalsIgnoreCase(cookieName) ) {
				// find in tgt
				sTgT = HandlerTools.getCookieValue((HttpServletRequest) request, cookieName, _logger);
			}
			if (sTgT != null) {
				_logger.log(Level.FINEST, _MODULE, sMethod, "Looking for cookie tgt key:" + sTgT);
				htTGTContext = TGTManager.getHandle().getTGT(sTgT);
				if (htTGTContext != null) {
					String cookieParm = (String) cookies.get(cookieName);
					// Enumeration cookieParms = tgtParms.keys();
					// while (cookieParms.hasMoreElements()) {
					// String cookieParm =
					// (String)cookieParms.nextElement();
					String parmVal = (String) htTGTContext.get(cookieParm);
					if ( parmVal != null ) {
						_logger.log(Level.FINEST, _MODULE, sMethod, "In cookie: " + cookieName  + " ,found: " + cookieParm + ", with value: " + parmVal + " , does" +  ( remoteAddress.equalsIgnoreCase(parmVal) ? "" : " NOT" ) + " equal remoteAddress:" + remoteAddress);
						if ( true && !remoteAddress.equalsIgnoreCase(parmVal) ) {	// Maybe introduce init "reject" parameter for this
							// better to call errorrequesthanlder here through redirect
							_logger.log(Level.WARNING, _MODULE, sMethod, "In cookie: " + cookieName  + " ,found: " + cookieParm + ", with value: " + parmVal + " , does" +  ( remoteAddress.equalsIgnoreCase(parmVal) ? "" : " NOT" ) + " equal remoteAddress:" + remoteAddress);
							throw new ServletException(Errors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
						}
					} else {
						_logger.log(Level.FINEST, _MODULE, sMethod, cookieParm + ":" + parmVal + " NOT found in tgt context");
					}
//						MDC.put(tgtParms.get(cookieParm), parmVal == null ? "" : parmVal);
				} else {
					_logger.log(Level.FINEST, _MODULE, sMethod, "No tgt found for cookie: " +cookieName + ", with value" + ":" + sTgT);
				}
			} else {
				_logger.log(Level.FINEST, _MODULE, sMethod, "No tgt cookie value found in request for cookiename: " + cookieName);
			}
		}

		// Continue processing the rest of the filter chain.
		chain.doFilter(request, response);

	}

	/*
	 * (non-Javadoc)
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void init(FilterConfig filterConfig)
	throws ServletException
	{
		super.init(filterConfig);
		final String sMethod = "init()";
		_logger = ASelectSystemLogger.getHandle();
//		_logger = SystemLoggerAudit.getHandle();
		_logger.log(Level.FINEST, _MODULE, sMethod, "Filter started");
	}
}
