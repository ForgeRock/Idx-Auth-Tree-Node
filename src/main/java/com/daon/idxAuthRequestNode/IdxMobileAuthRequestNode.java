package com.daon.idxAuthRequestNode;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import org.apache.http.util.TextUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;

import com.daon.identityx.rest.model.pojo.Application;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.Policy;
import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = IdxMobileAuthRequestNode.Config.class, tags = {"marketplace", "trustnetwork", "multi-factor authentication"})
public class IdxMobileAuthRequestNode extends SingleOutcomeNode {

	private String loggerPrefix = "[IdentityX Mobile Auth Request Node][Partner] ";
	
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
		 * the IdentityX policy which should be used for authentication
		 *
		 * @return the policy name
		 */
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		String policyName();

		/**
		 * the IdentityX application to be used
		 *
		 * @return the application Id
		 */
		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		String applicationId();
		
		
		/**
		 * the IdentityX Description to be used
		 *
		 * @return the transactionDescription
		 */
		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		default String transactionDescription() {
			return "OpenAM has Requested an Authentication";
		}
	}

	private final Config config;
	private static LoggerWrapper logger = new LoggerWrapper();
	

	/**
	 * Create the node.
	 */
	@Inject
	public IdxMobileAuthRequestNode(@Assisted Config config) {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) {
		try {
			Optional<TextOutputCallback> textOutputCallbackOptional = context.getCallback(TextOutputCallback.class);
			Optional<TextInputCallback> textInputCallbackOptional = context.getCallback(TextInputCallback.class);
			
			JsonValue sharedState = context.sharedState;
			
			String authHref = sharedState.get(IdxCommon.IDX_HREF_KEY).asString();
			logger.debug(loggerPrefix + "AuthenticationRequestHref={}", authHref);
			
			if (context.hasCallbacks() && textOutputCallbackOptional.isPresent() && textInputCallbackOptional.isPresent()) {	
				logger.debug(loggerPrefix + "==> Going to Next State ==>");
				return goToNext()
					.replaceSharedState(sharedState.put(IdxCommon.IDX_AUTH_RESPONSE_KEY, textInputCallbackOptional.get().getText()))
					.build();
			}
			
			String userId = context.sharedState.get(IdxCommon.IDX_USER_ID_KEY).asString();
			
			if (TextUtils.isBlank(userId)) {
				throw new NodeProcessException(loggerPrefix + "UserId cannot be blank");
			}
			
			AuthenticationRequest finalRequest = null;
			
			if (TextUtils.isBlank(authHref)) {
				finalRequest = createAuthRequest(context, userId);
			} else {
				finalRequest = getAuthRequest(context, authHref);
			}
			
			List<Callback> callbacks = new ArrayList<>();
			String adosAuthResponse = sharedState.get(IdxCommon.IDX_AUTH_RESPONSE_KEY).asString();
			
			
			final JsonValue json = json(object(
					field("href", finalRequest.getHref()), 
					field("id", finalRequest.getId()),
					field("fidoChallenge", finalRequest.getFidoChallenge()),
					field("fidoAuthenticationRequest", finalRequest.getFidoAuthenticationRequest())));
			
			if (!(TextUtils.isEmpty(adosAuthResponse))) {
				logger.debug(loggerPrefix + "ADoS Tree Operation Adding fidoAuthenticationResponse to callback json");
				json.put("fidoAuthenticationResponse", adosAuthResponse);			
				json.put("fidoResponseCode", finalRequest.getFidoResponseCode());
				json.put("fidoResponseMsg", finalRequest.getFidoResponseMsg());
			}
			
			callbacks.add(new TextInputCallback("Please provide the Daon Fido Response", "{}"));
			callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION, json.toString()));
	
			return Action.send(callbacks)
					.replaceSharedState(context.sharedState.put(IdxCommon.IDX_HREF_KEY, finalRequest.getHref()))
					.build();
		}
		catch (Exception ex) {
            logger.error(loggerPrefix + "Exception occurred: " + ex.getMessage());
            ex.printStackTrace();
            context.sharedState.put("Exception", ex.toString());
            return Action.goTo("error").build();

		}
	}
	
	private AuthenticationRequest createAuthRequest(TreeContext context, String userId) throws Exception {
		
		logger.info(loggerPrefix + "Entering createAuthRequest");
		
		User user = new User();
		user.setUserId(userId);
		
		Application application = new Application();
		application.setApplicationId(config.applicationId());
		
		Policy policy = new Policy();
		policy.setPolicyId(config.policyName());
		policy.setApplication(application);
		
		AuthenticationRequest request = new AuthenticationRequest();
		
		request.setUser(user);
		request.setApplication(application);
		request.setPolicy(policy);
		request.setDescription(config.transactionDescription());
		request.setType(IdxCommon.IDX_AUTH_REQUEST_TYPE);
		request.setServerData(context.sharedState.get(SharedStateConstants.USERNAME).asString());
		
		logger.debug(loggerPrefix + "UserId={} ApplicationId={} Policy={}", request.getUser().getUserId(), request.getApplication().getApplicationId(), request.getPolicy().getPolicyId());
		
		TenantRepoFactory tenantRepoFactory = IdxCommon.getTenantRepoFactory(context);
		
		try {
			request = tenantRepoFactory.getAuthenticationRequestRepo().create(request);
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "createAuthRequest exception", ex);
			throw new NodeProcessException(ex);
		}
		
		logger.info(loggerPrefix + "Exiting createAuthRequest");
		return request;
	}
	
	private AuthenticationRequest getAuthRequest(TreeContext context, String authRequestHref) throws Exception {
		
		logger.info(loggerPrefix + "Entering getAuthRequest");
		
		TenantRepoFactory tenantRepoFactory = IdxCommon.getTenantRepoFactory(context);
		
		logger.debug(loggerPrefix + "AuthRequestHref={}", authRequestHref);
		
		AuthenticationRequest request = null;
		
		try {
			request = tenantRepoFactory.getAuthenticationRequestRepo().get(authRequestHref);
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "getAuthRequest exception", ex);
			throw new NodeProcessException(ex);
		}
		
		logger.info(loggerPrefix + "Exiting getAuthRequest");
		return request;
	}
	

}