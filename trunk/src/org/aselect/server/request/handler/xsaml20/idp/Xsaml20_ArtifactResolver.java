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
package org.aselect.server.request.handler.xsaml20.idp;

import java.util.List;
import java.util.logging.Level;

import org.aselect.server.request.handler.xsaml20.AbstractMetaDataManager;
import org.aselect.server.request.handler.xsaml20.SamlTools;
import org.aselect.server.request.handler.xsaml20.Xsaml20_BaseArtifactResolver;
import org.aselect.system.exception.ASelectException;
import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;

//
// <handler id="saml20_artifactresolver"
//    class="org.aselect.server.request.handler.xsaml20.Xsaml20_ArtifactResolver"
//    target="/saml20_artifact.*">
// </handler>
//
/**
 * SAML2.0 ArtifactResolver for A-Select (Identity Provider side). <br>
 * <br>
 * <b>Description:</b><br>
 * The SAML2.0 ArtifactResolver for the A-Select Server (Identity Provider side).<br/>
 * SOAP message containing a SAML ArtifactResolve.<br/>
 * <br/>
 * The Response message coupled to the artifact is returned as a SOAP message with a SAML ArtifactResponse. <br>
 * 
 * @author Atos Origin
 */
public class Xsaml20_ArtifactResolver extends Xsaml20_BaseArtifactResolver
{
	private static final String MODULE = "idp.Xsaml20_ArtifactResolver";


	// true; // NEW opensaml20 library
	// RM_45_02
	// get from aselect.xml <applications require_signing="false | true">

	// RH, 20200218, sn
	/**
	 * @param sMethod
	 * @param bSignAssertion
	 * @param bKeepOriginalTimestampAssertion
	 * @param samlResponse
	 * @param now
	 * @throws ASelectException
	 */
	protected void updateTimeStamps(String sMethod, boolean bSignAssertion, boolean bKeepOriginalTimestampAssertion,
			SignableSAMLObject samlResponse, DateTime now) throws ASelectException {
		// RH, 20160108, sn
		//. We'll have to update the timestamp IssueInstant, NotBefore and NotOnOrAfter of the samlResponse here
		// RH, 20200218, so
//				if ( !bKeepOriginalTimestampAssertion && samlResponse.getAssertions()!= null && samlResponse.getAssertions().size()>0) {
//					samlResponse.setIssueInstant(now);
//					Assertion a = samlResponse.getAssertions().get(0); // There can be only one
		// RH, 20200218, so
		// RH, 20200218, sn
		if ( !bKeepOriginalTimestampAssertion && ((Response)samlResponse).getAssertions()!= null && ((Response)samlResponse).getAssertions().size()>0) {
			((Response)samlResponse).setIssueInstant(now);
			Assertion a = ((Response)samlResponse).getAssertions().get(0); // There can be only one
		// RH, 20200218, en
			if (a != null) {
				a.setIssueInstant(now);
				SamlTools.setValidityInterval(a, now, getMaxNotBefore(), getMaxNotOnOrAfter() );	// sets NotBefore and NotOnOrAfter on Conditions
				if (a.getSubject() != null) {
					List<SubjectConfirmation> subjconfs = a.getSubject().getSubjectConfirmations() ;
					if (subjconfs != null) {
						for (SubjectConfirmation s : subjconfs) {
							org.opensaml.saml2.core.SubjectConfirmationData sdata = s.getSubjectConfirmationData();
							if (sdata != null) {
								SamlTools.setValidityInterval(sdata, now, getMaxNotBefore(), getMaxNotOnOrAfter() );
							}
						}
					}
				}
				List<AuthnStatement> authnList = a.getAuthnStatements();
				if (authnList != null) {
					for (AuthnStatement as : authnList) {
						as.setAuthnInstant(now);
					}
				}
				if (a.isSigned() || bSignAssertion) {
//							a = (Assertion)SamlTools.signSamlObject(a, 
//									(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
//											(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
//													(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate));	// RH, 20180918, o
					a = (Assertion)SamlTools.signSamlObject(a, 
							(_sReqSigning != null) ?_sReqSigning: _sDefaultSigning ,
									(_sAddKeyName != null) ? "true".equals(_sAddKeyName): "true".equals(_sDefaultAddKeyname),
											(_sAddCertificate != null) ? "true".equals(_sAddCertificate): "true".equals(_sDefaultAddCertificate), null);	// RH, 20180918, n
					_systemLogger.log(Level.FINER, MODULE, sMethod, "Signed the assertion ======<");
				}
			}
		}
		// RH, 20160108, en
	}
	// RH, 20200218, nn

	// RH, 20200218, sn
	/**
	 * @return
	 * @throws ASelectException
	 */
	protected AbstractMetaDataManager getMetadataManager() throws ASelectException {
		AbstractMetaDataManager metadataManager = MetaDataManagerIdp.getHandle();
		return metadataManager;
	}
	// RH, 20200218, en
}
