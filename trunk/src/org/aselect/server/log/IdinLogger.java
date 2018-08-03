package org.aselect.server.log;

import java.util.logging.Level;

import org.aselect.system.logging.ISystemLogger;

import net.bankid.merchant.library.Configuration;
import net.bankid.merchant.library.ILogger;

public class IdinLogger implements ILogger {

	private ISystemLogger logger;
	public IdinLogger(ISystemLogger logger) {
		this.logger = logger;
		this.logger.log(Level.FINEST, "--> IdinLogger instantiated");
	}

	@Override
	public void Log(Configuration arg0, String arg1, Object... arg2) {
		logger.log(Level.FINEST, "-->"  + arg1.toString());
		
	}

	@Override
	public void LogXmlMessage(Configuration arg0, String arg1) {
		logger.log(Level.FINEST, "-->"  + arg1);
		
	}

}
