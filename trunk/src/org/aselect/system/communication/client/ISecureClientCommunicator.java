package org.aselect.system.communication.client;

import javax.net.ssl.SSLSocketFactory;

public interface ISecureClientCommunicator extends IClientCommunicator {

	public void set_sslSocketFactory(SSLSocketFactory sslfact);
	public SSLSocketFactory get_sslSocketFactory();
	
}
