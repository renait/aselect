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
package org.aselect.server.request.handler.xsaml20;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.NullLogChute;
import org.aselect.server.config.ASelectConfigManager;
import org.aselect.server.log.ASelectSystemLogger;
import org.aselect.system.error.Errors;
import org.aselect.system.exception.ASelectException;
import org.aselect.system.utils.crypto.Auxiliary;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap.SAMLArtifactMapEntry;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactBuilder;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Node;

public class LogoutRequestSender
{
	private final static String MODULE = "LogoutRequestSender";
	private ASelectConfigManager _configManager; // RH, 20200110, n
	private ASelectSystemLogger _systemLogger;
	private PrivateKey privateKey;
	
	private String binding = null;
	
	public static String LOGGER_NAME = "vel_logger";

	/**
	 * Instantiates a new logout request sender.
	 */
	public LogoutRequestSender()
	{
//		ASelectConfigManager _configManager = ASelectConfigManager.getHandle(); // RH, 20200110, o
		_configManager = ASelectConfigManager.getHandle(); // RH, 20200110, n
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = _configManager.getDefaultPrivateKey();
	}

	// RH, 20180918, sn
	/**
	 * Instantiates a new logout response sender.
	 */
	public LogoutRequestSender(PartnerData.Crypto specificCrypto) {
		_configManager = ASelectConfigManager.getHandle(); // RH, 20200110, n
		_systemLogger = ASelectSystemLogger.getHandle();
		privateKey = specificCrypto.getPrivateKey();
	}
	// RH, 20180918, en

	/**
	 * Sends a LogoutRequest.
	 * 
	 * @param sServiceProviderUrl
	 *            the service provider url
	 * @param sNameID
	 *            the name id
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @param sTgT
	 *            the TGT
	 * @param sIssuerUrl
	 *            the issuer url
	 * @param reason
	 *            the reason
	 * @param sLogoutReturnUrl
	 *            the logout return url
	 * @param  List<String>sessionindexes
	 * 				optional list of sessionindexes to kill
	 * @param  PartnerData paretnerData
	 * 				optional partnerdata to be used for special settings
	 * @throws ASelectException
	 *             the A-select exception
	 */
	

	public void sendLogoutRequest(HttpServletRequest request, HttpServletResponse response, String sTgT,
			String sServiceProviderUrl, String sIssuerUrl, String sNameID, String reason, String sLogoutReturnUrl)
	throws ASelectException
	{	// for backward compatibility
		sendLogoutRequest(request, response, sTgT, sServiceProviderUrl, sIssuerUrl, sNameID, reason, sLogoutReturnUrl, null);
	}
	
	public void sendLogoutRequest(HttpServletRequest request, HttpServletResponse response, String sTgT,
			String sServiceProviderUrl, String sIssuerUrl, String sNameID, String reason, String sLogoutReturnUrl, List<String>sessionindexes)
	throws ASelectException
	{	// for backward compatibility
		sendLogoutRequest(request, response, sTgT, sServiceProviderUrl, sIssuerUrl, sNameID, reason, sLogoutReturnUrl, sessionindexes, null);
	}
		
	@SuppressWarnings("unchecked")
	public void sendLogoutRequest(HttpServletRequest request, HttpServletResponse response, String sTgT,
			String sServiceProviderUrl, String sIssuerUrl, String sNameID, String reason, String sLogoutReturnUrl,
			List<String>sessionindexes, PartnerData partnerData)
	throws ASelectException
	{
		String sMethod = "sendLogoutRequest";
		
		// velocity logging quickfix
		org.apache.log4j.BasicConfigurator.configure();
		org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger( LOGGER_NAME );
		
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Send LogoutRequest to: " + sServiceProviderUrl);
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

//		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID, sIssuerUrl, reason);
		// RH, 20120307, sn
		LogoutRequest logoutRequest = null;
		if (partnerData != null && partnerData.getTestdata4partner() != null) {
			String issueinstant = partnerData.getTestdata4partner().getIssueInstantLogout();
			DateTime dtIssueinstant = null;
			if (issueinstant != null) {
				dtIssueinstant = new DateTime().plus(1000*Long.parseLong(issueinstant));
				// RM_48_01
			}

			String issuer = partnerData.getTestdata4partner().getIssuerLogout();
			String destination =  partnerData.getTestdata4partner().getDestinationLogout();
			logoutRequest = SamlTools.buildLogoutRequest(
					destination != null ? destination : sServiceProviderUrl,
					sTgT, sNameID, issuer != null ? issuer: sIssuerUrl, 
					reason, sessionindexes, dtIssueinstant);
		}
		else {
			logoutRequest = SamlTools.buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID, sIssuerUrl, reason, sessionindexes);
		}
		// RH, 20120307, en
//		LogoutRequest logoutRequest = SamlTools.buildLogoutRequest(sServiceProviderUrl, sTgT, sNameID, sIssuerUrl, reason, sessionindexes);	// RH, 20120307, o

		// RM_48_02
		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		// samlEndpoint.setBinding(HTTPPostEncoder.BINDING_URI);
		samlEndpoint.setLocation(sServiceProviderUrl);
		String sAppUrl = request.getRequestURL().toString();
		samlEndpoint.setResponseLocation(sAppUrl);

		HttpServletResponseAdapter outTransport = SamlTools.createHttpServletResponseAdapter(response, sServiceProviderUrl);
		// 20090627, Bauke: need headers too
		outTransport.setHeader("Pragma", "no-cache");
		outTransport.setHeader("Cache-Control", "no-cache, no-store");

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setOutboundSAMLMessage(logoutRequest);
		messageContext.setPeerEntityEndpoint(samlEndpoint);

		// 20090627, Bauke: pass return url, will be used by the Logout Response handler
		if (sLogoutReturnUrl != null) { // && !"".equals(sLogoutReturnUrl))
			messageContext.setRelayState(sLogoutReturnUrl);
			_systemLogger.log(Level.FINER, MODULE, sMethod, "Set RelayState=" + sLogoutReturnUrl);
		}
		BasicX509Credential credential = new BasicX509Credential();

		credential.setPrivateKey(privateKey);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);

		MarshallerFactory factory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = factory.getMarshaller(messageContext.getOutboundSAMLMessage());
		Node node = null;
		try {
			node = marshaller.marshall(messageContext.getOutboundSAMLMessage());
		}
		catch (MarshallingException e) {
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception marshalling SAML message");
			throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
		}
		String msg = XMLHelper.prettyPrintXML(node);
		_systemLogger.log(Level.FINEST, MODULE, sMethod, "About to send:\n " + Auxiliary.obfuscate(msg, Auxiliary.REGEX_PATTERNS));

		// Store it in the history
		SamlHistoryManager history = SamlHistoryManager.getHandle();
		history.put(sTgT, logoutRequest.getDOM());

		////////////////////////////// Alternative	/////////////////////////
//        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
//        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
//        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        ////////////////////////////////////////////////////////////////////////

//		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();	// RH, 20190426, o
		
		// RH, 20200110, sn
		// POST binding
		if ("HTTP-POST".equalsIgnoreCase(getBinding())) {
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Send using: " + "HTTP-POST");

			VelocityEngine velocityEngine = new VelocityEngine();
//			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "file,class");
			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "class");
//			velocityEngine.setProperty("file.resource.loader.class", "org.apache.velocity.runtime.resource.loader.FileResourceLoader" );
//			velocityEngine.setProperty("file.resource.loader.cache", "false" );
//			velocityEngine.setProperty("file.resource.loader.path", _configManager.getWorkingdir() + File.separator + "conf" + File.separator + "vmtemplates" + File.separator);
//			
//			velocityEngine.setProperty("file.resource.loader.modificationCheckInterval", "0" );
			velocityEngine.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader" );
			
//			velocityEngine.setProperty("runtime.log.logsystem.class", NullLogChute.class.getName());
			velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, NullLogChute.class.getName());
//			velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
//		            "org.apache.velocity.runtime.log.Log4JLogChute");
//			velocityEngine.setProperty("runtime.log.logsystem.log4j.logger",
//		               LOGGER_NAME);
			velocityEngine.init();

			// Dirty trick
			final class myHTTPPostEncoder extends HTTPPostEncoder {
				myHTTPPostEncoder(VelocityEngine velocityEngine, String template) {
					super(velocityEngine, template);
				}
				
			    protected void signMessage(SAMLMessageContext messageContext) throws MessageEncodingException {
			        SAMLObject outboundSAML = messageContext.getOutboundSAMLMessage();
			        Credential signingCredential = messageContext.getOuboundSAMLMessageSigningCredential();

			        if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
			            SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

			            XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
			                    Signature.DEFAULT_ELEMENT_NAME);
			            Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
			            
			            signature.setSigningCredential(signingCredential);
			            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);	// RH, 20200113, n
			            
			            try {
			                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
			            } catch (SecurityException e) {
			    			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error preparing signature for signing: " + e.getMessage());
			                throw new MessageEncodingException("Error preparing signature for signing", e);
			            } catch (org.opensaml.xml.security.SecurityException e) {
			    			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error preparing signature for signing: " + e.getMessage());
			                throw new MessageEncodingException("Error preparing signature for signing", e);
						}
			            
			            signableMessage.setSignature(signature);

			            // RH, 20200113, sn
			            SAMLObjectContentReference contentReference = new SAMLObjectContentReference(signableMessage);
			            contentReference.setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
			            signature.getContentReferences().clear();  // must be done after setSignature() (it adds a default to the list)
			            signature.getContentReferences().add(contentReference);            
			            // RH, 20200113, en

			            try {
			                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
			                if (marshaller == null) {
			                    throw new MessageEncodingException("No marshaller registered for "
			                            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
			                }
			                marshaller.marshall(signableMessage);

			                Signer.signObject(signature);
			            } catch (MarshallingException e) {
			    			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to marshall protocol message in preparation for signing: " + e.getMessage());

			                throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
			            } catch (SignatureException e) {
			    			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Unable to marshall protocol message in preparation for signing: " + e.getMessage());
			                throw new MessageEncodingException("Unable to sign protocol message", e);
			            }
			        }
			    }
			};
			
//			HTTPPostEncoder encoder = new myHTTPPostEncoder(velocityEngine, "saml2-post-binding.vm");
			HTTPPostEncoder encoder = new myHTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
			
			try {
				encoder.encode(messageContext);
//				return;
			}
			catch (MessageEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		} else if ("HTTP-POST-SimpleSign".equalsIgnoreCase(getBinding())) {
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "Send using: " + "HTTP-POST-SimpleSign");

				VelocityEngine velocityEngine = new VelocityEngine();
//				velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "file,class");
				velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "class");
//				velocityEngine.setProperty("file.resource.loader.class", "org.apache.velocity.runtime.resource.loader.FileResourceLoader" );
//				velocityEngine.setProperty("file.resource.loader.cache", "false" );
//				velocityEngine.setProperty("file.resource.loader.path", _configManager.getWorkingdir() + File.separator + "conf" + File.separator + "vmtemplates" + File.separator);
//				velocityEngine.setProperty("file.resource.loader.modificationCheckInterval", "0" );
				velocityEngine.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader" );

//				velocityEngine.setProperty("runtime.log.logsystem.class", NullLogChute.class.getName());
				velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, NullLogChute.class.getName());
//				velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
//			            "org.apache.velocity.runtime.log.Log4JLogChute");
//				velocityEngine.setProperty("runtime.log.logsystem.log4j.logger",
//			               LOGGER_NAME);
				velocityEngine.init();

				// Dirty trick
				final class myHTTPPostSimpleSignEncoder extends HTTPPostSimpleSignEncoder {
					myHTTPPostSimpleSignEncoder(VelocityEngine velocityEngine, String template, boolean sign) {
						super(velocityEngine, template, sign);
					}
					protected String getSignatureAlgorithmURI(Credential credential, SecurityConfiguration config)
					        throws MessageEncodingException {
	/*
					    SecurityConfiguration secConfig;
					    if (config != null) {
					        secConfig = config;
					    } else {
					        secConfig = Configuration.getGlobalSecurityConfiguration();
					    }

					    String signAlgo = secConfig.getSignatureAlgorithmURI(credential);

					    if (signAlgo == null) {
					        throw new MessageEncodingException("The signing credential's algorithm URI could not be derived");
					    }
	*/
					    return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
					}
						
				};

//				HTTPPostSimpleSignEncoder encoder = new myHTTPPostSimpleSignEncoder(velocityEngine,  "saml2-post-simplesign-binding.vm", false);
				HTTPPostSimpleSignEncoder encoder = new myHTTPPostSimpleSignEncoder(velocityEngine,  "/templates/saml2-post-simplesign-binding.vm", false);

				try {
					encoder.encode(messageContext);
//					return;
				}
				catch (MessageEncodingException e) {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
					throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
				}
		} else if ("HTTP-Artifact".equalsIgnoreCase(getBinding())) { 	// RH, 20200217, sn
			_systemLogger.log(Level.FINEST, MODULE, sMethod, "Send using: " + "HTTP-Artifact");
			
//			VelocityEngine velocityEngine = new VelocityEngine();
//
//			velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "class");
////			velocityEngine.setProperty("file.resource.loader.class", "org.apache.velocity.runtime.resource.loader.FileResourceLoader" );
////			velocityEngine.setProperty("file.resource.loader.cache", "false" );
////			velocityEngine.setProperty("file.resource.loader.path", _configManager.getWorkingdir() + File.separator + "conf" + File.separator + "vmtemplates" + File.separator);
////			velocityEngine.setProperty("file.resource.loader.modificationCheckInterval", "0" );
//			velocityEngine.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader" );
//
//			velocityEngine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
//		            "org.apache.velocity.runtime.log.Log4JLogChute");
//			velocityEngine.setProperty("runtime.log.logsystem.log4j.logger",
//		               LOGGER_NAME);
//			velocityEngine.init();
//
//			final class myHTTPArtifactEncoder extends HTTPArtifactEncoder {
//				myHTTPArtifactEncoder(VelocityEngine velocityEngine, String template, SAMLArtifactMap artifactMap) {
//					super(velocityEngine, template, artifactMap);
//				}
//				private AbstractSAML2Artifact artifact;
//				
//				 protected AbstractSAML2Artifact buildArtifact(SAMLMessageContext artifactContext) throws MessageEncodingException {
//
//					 /*
//				        SAML2ArtifactBuilder artifactBuilder;
//				        if (artifactContext.getOutboundMessageArtifactType() != null) {
//				            artifactBuilder = Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(
//				                    artifactContext.getOutboundMessageArtifactType());
//				        } else {
//				            artifactBuilder = Configuration.getSAML2ArtifactBuilderFactory().getArtifactBuilder(SAML2ArtifactType0004.TYPE_CODE);
//				            artifactContext.setOutboundMessageArtifactType(SAML2ArtifactType0004.TYPE_CODE);
//				        }
//				       */
//					 
//						Saml20_ArtifactManager artifactManager;
//						try {
//							artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
//						} catch (ASelectException e) {
//							_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception retrieving Saml20_ArtifactManager: " + e.getMessage());
//							throw new MessageEncodingException("Exception retrieving Saml20_ArtifactManager", e);
//						}
////						AbstractSAML2Artifact artifact = artifactManager.buildRawArtifact(logoutRequest, logoutRequest.getIssuer().getValue(), logoutRequest.getID().substring(1));
////						AbstractSAML2Artifact artifact = artifactManager.buildRawArtifact(artifactContext.getOutboundSAMLMessage(), ((LogoutRequest)artifactContext.getOutboundSAMLMessage()).getIssuer().getValue(), ((LogoutRequest)artifactContext.getOutboundSAMLMessage()).getID().substring(1));
//						artifact = artifactManager.buildRawArtifact(artifactContext.getOutboundSAMLMessage(), ((LogoutRequest)artifactContext.getOutboundSAMLMessage()).getIssuer().getValue(), ((LogoutRequest)artifactContext.getOutboundSAMLMessage()).getID().substring(1));
//
//						/*
//						 * We still might to have to fix some things here
//				        SAML2ArtifactType0004.parseArtifact(artifact)
//				        AbstractSAML2Artifact artifact = artifactBuilder.buildArtifact(artifactContext);
//				        String encodedArtifact = artifact.base64Encode();
//				        try {
//				            artifactMap.put(encodedArtifact, artifactContext.getInboundMessageIssuer(), artifactContext
//				                    .getOutboundMessageIssuer(), artifactContext.getOutboundSAMLMessage());
//				        } catch (MarshallingException e) {
//				            log.error("Unable to marshall assertion to be represented as an artifact", e);
//				            throw new MessageEncodingException("Unable to marshall assertion to be represented as an artifact", e);
//				        }
//						*/
//				        return artifact;
//				    }
//					/**
//					 * @return the artifact
//					 */
//					public synchronized AbstractSAML2Artifact getArtifact() {
//						return artifact;
//					}
//
//					/**
//					 * @param artifact the artifact to set
//					 */
//					public synchronized void setArtifact(AbstractSAML2Artifact artifact) {
//						this.artifact = artifact;
//					}
//
//			};
			
			/*
			StorageService<String, SAMLArtifactMapEntry> storage = new MapBasedStorageService<String, SAMLArtifactMapEntry>();
			BasicParserPool parserPool = new BasicParserPool();
			parserPool.setNamespaceAware(true);
			SAMLArtifactMap artMap = new BasicSAMLArtifactMap(storage, null, Long.MAX_VALUE);	// Default storagePartition "artifact"

//			HTTPArtifactEncoder encoder = new myHTTPArtifactEncoder(velocityEngine,  "/templates/saml2-post-artifact-binding.vm", artMap);
			myHTTPArtifactEncoder encoder = new myHTTPArtifactEncoder(velocityEngine,  "/templates/saml2-post-artifact-binding.vm", artMap);
			try {
				encoder.setPostEncoding(false);	// for test, we should get this from configuration // post encoding still to test
				encoder.encode(messageContext);
				_systemLogger.log(Level.FINEST, MODULE, sMethod, "the artifact has been sent");
				
				Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
//				SAMLArtifactMapEntry artEntry = (SAMLArtifactMapEntry) Arrays.asList(artMap).get(0);	// casting exception
				// Unfortunately SAMLArtifactMap is not really a Map in the java sense.
				// It does not implement the Map interface so we cannot iterate over or retrieve an element if we do not know the key.
				// The encoder also does not fill the storage with the artifact and SAMLArtifactMapEntry
				Iterator<String> artifacts = storage.getKeys("artifact");
				if (artifacts != null && artifacts.hasNext()) {	// it should have
					String artifact = artifacts.next();
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "retrieved artifact from temp storage: " + artifact);
					artifactManager.put(artifact, storage.get("artifact", artifact));
					_systemLogger.log(Level.FINEST, MODULE, sMethod, "Put in storagemanager: " + storage.get("artifact", artifact));
				} else {
					_systemLogger.log(Level.WARNING, MODULE, sMethod, "Tempstorage did not contain the sent artifact");
				}
//				return;
			}
			catch (MessageEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
			*/

			// alternative without encoder
			Saml20_ArtifactManager artifactManager = Saml20_ArtifactManager.getTheArtifactManager();
			String sArtifact = artifactManager.buildArtifact(logoutRequest, logoutRequest.getIssuer().getValue(), logoutRequest.getID()
					.substring(1));

			try {
				artifactManager.sendArtifact(sArtifact, logoutRequest, sServiceProviderUrl,
							request, response, null /* sLogoutReturnUrl */ /* sRelayState */, null);
			} catch (IOException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception sending artifact: " + e.getMessage());
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}

		} 	// RH, 20200217, en
		else {	// like we did before
		//	RH, 20200110, en
		
			Saml20_RedirectEncoder encoder = new Saml20_RedirectEncoder();	// RH, 20190426, n
			try {
				encoder.encode(messageContext);
			}
			catch (MessageEncodingException e) {
				_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception encoding (and sending) SAML message");
				throw new ASelectException(Errors.ERROR_ASELECT_INTERNAL_ERROR, e);
			}
		}	//	RH, 20200110, n

	}

	public synchronized String getBinding() {
		return binding;
	}

	public synchronized void setBinding(String binding) {
		this.binding = binding;
	}

}
