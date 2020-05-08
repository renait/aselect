/*
 * * Copyright (c) Anoigo. All rights reserved.
 *
 * A-Select is a trademark registered by SURFnet bv.
 *
 * This program is distributed under the EUPL 1.0 (http://osor.eu/eupl)
 * See the included LICENSE file for details.
 *
 * If you did not receive a copy of the LICENSE
 * please contact Anoigo. (http://www.anoigo.nl) 
 */
package org.aselect.server.request.handler.xsaml20.sp;

import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.Xsaml20_BaseArtifactResolver;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;

//
// <handler id="sp.saml20_artifactresolver"
//    class="org.aselect.server.request.handler.xsaml20.sp.Xsaml20_ArtifactResolver"
//    target="/saml20_artifact_logout.*">
// </handler>
//
/**
 * SAML2.0 ArtifactResolver for A-Select (Service Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 ArtifactResolver for the A-Select Server (Service Provider side).<br/>
 * SOAP message containing a SAML ArtifactResolve.<br/>
 * <br/>
 * The Response message coupled to the artifact is returned as a SOAP message with a SAML ArtifactResponse. <br>
 */
public class Xsaml20_ArtifactResolver extends Xsaml20_BaseArtifactResolver
{
	private static final String MODULE = "sp.Xsaml20_ArtifactResolver";


	/**
	 * @param sMethod
	 * @param bSignAssertion
	 * @param bKeepOriginalTimestampAssertion
	 * @param samlResponse
	 * @param now
	 * @throws ASelectException
	 */
	protected void updateTimeStamps(String sMethod, boolean bSignAssertion, boolean bKeepOriginalTimestampAssertion,
			SignableSAMLObject samlMessage, DateTime now) throws ASelectException {
		// RH, 20200220, sn
		// We'll have to do nothing for the moment. samlMessage probably logout request for the Artifact logout	
		// RH, 20200220, en
	}

	// RH, 20200220, sn
	/**
	 * @return
	 * @throws ASelectException
	 */
	protected AbstractMetaDataManager getMetadataManager() throws ASelectException {
		AbstractMetaDataManager metadataManager = MetaDataManagerSp.getHandle();
		return metadataManager;
	}
	// RH, 20200220, en
}
