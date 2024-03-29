package org.aselect.authspserver.authsp.openid;

import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.aselect.system.logging.SystemLogger;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;

/**
 * Consolidates business logic from the UI code for Registration activities.
 * 
 * Most of this code modeled after ConsumerServlet, part of the openid4java 
 * sample code available at 
 * http://code.google.com/p/openid4java/wiki/SampleConsumer.
 * Some of this code was outright copied :->.
 * 
 * @author J Steven Perry
 * @author http://makotoconsulting.com
 *
 */
public class RegistrationService {
	/** The name of this module, that is used in the system logging. */
	public static final String MODULE = "RegistrationService";

	
	/**
	 * Perform discovery on the User-Supplied identifier and return the
	 * DiscoveryInformation object that results from Association with the
	 * OP. This will probably be needed by the caller (stored in Session
	 * perhaps?).
	 * 
	 * I'm not thrilled about ConsumerManager being static, but it is
	 * very important to openid4java that the ConsumerManager object be the
	 * same instance all through a conversation (discovery, auth request, 
	 * auth response) with the OP. I didn't dig terribly deeply, but suspect
	 * that part of the key exchange or the nonce uses the ConsumerManager's
	 * hash, or some other instance-specific construct to do its thing.
	 * 
	 * @param userSuppliedIdentifier The User-Supplied identifier. It may already
	 *  be normalized.
	 *
	 *  @return DiscoveryInformation - The resulting DisoveryInformation object
	 *  returned by openid4java following successful association with the OP.
	 */
	@SuppressWarnings("unchecked")
	public static DiscoveryInformation performDiscoveryOnUserSuppliedIdentifier(String userSuppliedIdentifier, SystemLogger _systemLogger)
	{
		String sMethod = "performDiscoveryOnUserSuppliedIdentifier";

		DiscoveryInformation ret = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Starting performDiscoveryOnUserSuppliedIdentifier");

		//
		ConsumerManager consumerManager = getConsumerManager();
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieved consumermanager");

		try {
		// Perform discover on the User-Supplied Identifier
		List<DiscoveryInformation> discoveries = consumerManager.discover(userSuppliedIdentifier);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "# discoveries found:" + discoveries.size());

		// Pass the discoveries to the associate() method...
		ret = consumerManager.associate(discoveries);
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Associated using found discoveries");

		} catch (DiscoveryException e) {
			String message = "Error occurred during discovery!";
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Error occurred during discovery!", e);
			throw new RuntimeException(message, e);
		}
		return ret;
	}
	/**
	 * Create an OpenID Auth Request, using the DiscoveryInformation object
	 * return by the openid4java library.
	 * 
	 * This method also uses the Simple Registration Extension to grant
	 * the Relying Party (RP).
	 * 
	 * @param discoveryInformation The DiscoveryInformation that should have
	 *  been previously obtained from a call to 
	 *  performDiscoveryOnUserSuppliedIdentifier().
	 *  
	 *  @param returnToUrl The URL to which the OP will redirect once the
	 *   authentication call is complete.
	 *  
	 * @return AuthRequest - A "good-to-go" AuthRequest object packed with all
	 *  kinds of great OpenID goodies for the OpenID Provider (OP). The caller
	 *  must take this object and forward it on to the OP. Or call
	 *  processAuthRequest() - part of this Service Class.
	 */
	public static AuthRequest createOpenIdAuthRequest(DiscoveryInformation discoveryInformation, String returnToUrl)
	{
		AuthRequest ret = null;
		//
		try {
			// Create the AuthRequest object
			ret = getConsumerManager().authenticate(discoveryInformation, returnToUrl);
			// Create the Simple Registration Request
			SRegRequest sRegRequest = SRegRequest.createFetchRequest();
			sRegRequest.addAttribute("email", false);
//			sRegRequest.addAttribute("fullname", false);
//			sRegRequest.addAttribute("dob", false);
//			sRegRequest.addAttribute("postcode", false);
			ret.addExtension(sRegRequest);
			
		} catch (Exception e) {
			String message = "Exception occurred while building AuthRequest object!";
//			log.error(message, e);
			throw new RuntimeException(message, e);
		}
		return ret;
	}
	
	/**
	 * Processes the returned information from an authentication request
	 * from the OP.
	 * 
	 * @param discoveryInformation DiscoveryInformation that was created earlier
	 *  in the conversation (by openid4java). This will need to be verified with
	 *  openid4java to make sure everything went smoothly and there are no
	 *  possible problems. This object was probably stored in session and retrieved
	 *  for use in calling this method.
	 *  
	 * @param pageParameters PageParameters passed to the page handling the
	 *  return verificaion.
	 *  
	 * @param returnToUrl The "return to" URL that was passed to the OP. It must
	 *  match exactly, or openid4java will issue a verification failed message
	 *  in the logs.
	 *  
	 * @return RegistrationModel - null if there was a problem, or a RegistrationModel
	 *  object, with parameters filled in as compeletely as possible from the
	 *  information available from the OP. If you are using MyOpenID, most of the
	 *  time what is returned is from your "Default" profile, so if you need more 
	 *  information returned, make sure your Default profile is completely filled
	 *  out.
	 */
	public static RegistrationModel processReturn(DiscoveryInformation discoveryInformation, Map pageParameters, String returnToUrl, SystemLogger _systemLogger)
	{
		String sMethod = "processReturn";
		RegistrationModel ret = null;
		_systemLogger.log(Level.INFO, MODULE, sMethod, "Verify the Information returned from the OP");

		// Verify the Information returned from the OP
		/// This is required according to the spec
		ParameterList response = new ParameterList(pageParameters);
		try {
			VerificationResult verificationResult = getConsumerManager().verify(returnToUrl, response, discoveryInformation);
			Identifier verifiedIdentifier = verificationResult.getVerifiedId();
			if (verifiedIdentifier != null) {
				AuthSuccess authSuccess = (AuthSuccess)verificationResult.getAuthResponse();
				ret = new RegistrationModel();
//				_systemLogger.log(Level.FINEST, MODULE, sMethod, "--->verifiedIdentifier.getIdentifier():" + verifiedIdentifier.getIdentifier());
				ret.setOpenId(verifiedIdentifier.getIdentifier());
				if (authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG)) {
					MessageExtension extension = authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);
					if (extension instanceof SRegResponse) {
						_systemLogger.log(Level.INFO, MODULE, sMethod, "Retrieving sReg extension information");
						SRegResponse sRegResponse = (SRegResponse)extension;
						String value = null;
//						value = sRegResponse.getAttributeValue("dob");
//						if (value != null) {
//						  long millis = Long.valueOf(value).longValue();
////						  ret.setDateOfBirth(new YearMonthDay(value).toDateMidnight().toDate());
//						  ret.setDateOfBirth(new YearMonthDay(millis).toDateMidnight().toDate());
//						}
						value = sRegResponse.getAttributeValue("email");
						if (value != null) {
						  ret.setEmailAddress(value);
						}
//						value = sRegResponse.getAttributeValue("fullname");
//						if (value != null) {
//						  ret.setFullName(value);
//						}
//						value = sRegResponse.getAttributeValue("postcode");
//						if (value != null) {
//						  ret.setZipCode(value);
//						}
					}
				}
			}
		} catch (Exception e) {
			String message = "Exception occurred while verifying response!";
//			log.error(message, e);
			_systemLogger.log(Level.WARNING, MODULE, sMethod, "Exception occurred while verifying response!", e);
//			throw new RuntimeException(message, e);
			ret = null;
		}
		return ret;
	}

	private static ConsumerManager consumerManager;
	/**
	 * Retrieves an instance of the ConsumerManager object. It is static
	 * (see note in Class-level JavaDoc comments above) because openid4java
	 * likes it that way.
	 * 
	 * Note: if you are planning to debug the code, set the lifespan parameter
	 * of the InMemoryNonceVerifier high enough to outlive your debug cycle, or
	 * you may notice Nonce Verification errors. Depending on where you are
	 * debugging, this might pose an artificial problem for you (of your own
	 * making) that has nothing to do with either your code or openid4java.
	 * 
	 * @return ConsumerManager - The ConsumerManager object that handles
	 *  communication with the openid4java API.
	 */
	private static ConsumerManager getConsumerManager()
	{
		try {
			if (consumerManager == null) {
				consumerManager = new ConsumerManager();
				consumerManager.setAssociations(new InMemoryConsumerAssociationStore());
				consumerManager.setNonceVerifier(new InMemoryNonceVerifier(10000));
			}
		} catch (ConsumerException e) {
			String message = "Exception creating ConsumerManager!";
//			log.error(message, e);
			throw new RuntimeException(message, e);
		}
		return consumerManager;
	}
 }
