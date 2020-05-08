package org.aselect.server.request.handler.xsaml20;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;

public class Saml20_PostEncoder extends HTTPPostSimpleSignEncoder {

	public Saml20_PostEncoder(VelocityEngine engine, String templateId) {
		super(engine, templateId);
		// TODO Auto-generated constructor stub
	}

	public Saml20_PostEncoder(VelocityEngine engine, String templateId, boolean signXMLProtocolMessage) {
		super(engine, templateId, signXMLProtocolMessage);
		// TODO Auto-generated constructor stub
	}

}
