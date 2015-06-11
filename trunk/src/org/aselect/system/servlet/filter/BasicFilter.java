package org.aselect.system.servlet.filter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public class BasicFilter implements Filter
{

	private static final String _MODULE = "BasicFilter";
	protected static final String REQUEST_COOKIE = "cookie@";
	protected static final String REQUEST_PARM = "requestparm@";
	protected HashMap<String, String> requestParms = new HashMap<String, String>();
	protected HashMap<String, String> cookies = new HashMap<String, String>();

	public BasicFilter() {
		super();
	}

	public void destroy()
	{
		// TODO Auto-generated method stub
		
	}

	public void doFilter(ServletRequest arg0, ServletResponse arg1, FilterChain arg2)
		throws IOException, ServletException
	{
		// TODO Auto-generated method stub
		
	}

	public void init(FilterConfig filterConfig)
		throws ServletException
	{
		final String sMethod = "init()";
		// this.filterConfig = filterConfig;
		filterConfig.getFilterName(); // We probably want this later
		Enumeration filterParms = filterConfig.getInitParameterNames();
		while (filterParms.hasMoreElements()) {
			String fullParmName = (String) filterParms.nextElement();
			if (fullParmName.toLowerCase().startsWith(REQUEST_PARM)) {
				String name = fullParmName.substring(REQUEST_PARM.length());
				String val = filterConfig.getInitParameter(fullParmName);
				if (val != null && !"".equals(val)) {
					requestParms.put(name, val);
				}
			}
			if (fullParmName.toLowerCase().startsWith(REQUEST_COOKIE)) {
				String name = fullParmName.substring(REQUEST_COOKIE.length());
				String val = filterConfig.getInitParameter(fullParmName);
				if (val != null && !"".equals(val)) {
					cookies.put(name, val);
				}
			}
		}
		
	}

}