package org.aselect.server.log;

import java.util.logging.Level;

import org.aselect.system.logging.ISystemLogger;

import net.bankid.merchant.library.ILogger;
import net.bankid.merchant.library.ILoggerFactory;

public class IdinLoggerFactory implements ILoggerFactory {

	ISystemLogger logger;
	public IdinLoggerFactory(ISystemLogger logger) {
		this.logger = logger;
		this.logger.log(Level.FINEST, "--> IdinLoggerFactory instantiated");
	}

	@Override
	public ILogger create() {
		
		return new IdinLogger(logger);
	}

}
