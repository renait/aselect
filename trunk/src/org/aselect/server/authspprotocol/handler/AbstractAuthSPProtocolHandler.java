package org.aselect.server.authspprotocol.handler;

import java.util.Map;

import org.aselect.server.authspprotocol.IAuthSPConditions;


public abstract class AbstractAuthSPProtocolHandler implements IAuthSPConditions
{
	private boolean outputAvailable = true;	// We assume output available presence per default


public synchronized boolean isOutputAvailable()
{
	return outputAvailable;
}

public synchronized void setOutputAvailable(boolean outputAvailable)
{
	this.outputAvailable = outputAvailable;
}

// default implementation
public String inquireSubselect(Map  map) {
	return null;
}

}