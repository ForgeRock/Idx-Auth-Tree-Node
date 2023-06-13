package com.daon.idxAuthRequestNode;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.apache.http.util.TextUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.daon.identityx.rest.model.pojo.Application;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.Policy;
import com.daon.identityx.rest.model.pojo.User;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = IdxMobileAuthRequestNode.IdxMobileAuthRequestNodeOutcomeProvider.class, configClass = IdxMobileAuthRequestNode.Config.class, tags = {"marketplace", "trustnetwork", "multi-factor authentication"})
public class IdxMobileAuthRequestNode extends AbstractDecisionNode {

	private String loggerPrefix = "[IdentityX Mobile Auth Request]" + IdxAuthRequestNodePlugin.logAppender;
	private static final String BUNDLE = IdxMobileAuthRequestNode.class.getName();
	
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
			
			NodeState sharedState = context.getStateFor(this);
			
			String authHref = sharedState.get(IdxCommon.IDX_HREF_KEY).asString();
			logger.debug(loggerPrefix + "AuthenticationRequestHref={}", authHref);
			
			if (context.hasCallbacks() && textOutputCallbackOptional.isPresent() && textInputCallbackOptional.isPresent()) {	
				logger.debug(loggerPrefix + "==> Going to Next State ==>");
				sharedState.putShared(IdxCommon.IDX_AUTH_RESPONSE_KEY, textInputCallbackOptional.get().getText());
				return Action.goTo(IdxMobileAuthRequestNodeOutcome.NEXT_OUTCOME.name()).build();
			}
			
			String userId = context.getStateFor(this).get(IdxCommon.IDX_USER_ID_KEY).asString();
			
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
	
			sharedState.putShared(IdxCommon.IDX_HREF_KEY, finalRequest.getHref());
			
			return Action.send(callbacks).build();
		}
		catch (Exception ex) {
			logger.error(loggerPrefix + "Exception occurred: " + ex.getStackTrace());
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			ex.printStackTrace(pw);
			context.getStateFor(this).putShared(loggerPrefix + "StackTrace", new Date() + ": " + sw.toString());
            return Action.goTo(IdxMobileAuthRequestNodeOutcome.ERROR_OUTCOME.name()).build();

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
		request.setServerData(context.getStateFor(this).get(SharedStateConstants.USERNAME).asString());
		
		logger.debug(loggerPrefix + "UserId={} ApplicationId={} Policy={}", request.getUser().getUserId(), request.getApplication().getApplicationId(), request.getPolicy().getPolicyId());
		
		TenantRepoFactory tenantRepoFactory = IdxCommon.getTenantRepoFactory(context, this);
		
		try {
			request = tenantRepoFactory.getAuthenticationRequestRepo().create(request, IdxCommon.getAccessToken(context, this));
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "createAuthRequest exception", ex);
			throw new NodeProcessException(ex);
		}
		
		logger.info(loggerPrefix + "Exiting createAuthRequest");
		return request;
	}
	
	private AuthenticationRequest getAuthRequest(TreeContext context, String authRequestHref) throws Exception {
		
		logger.info(loggerPrefix + "Entering getAuthRequest");
		
		TenantRepoFactory tenantRepoFactory = IdxCommon.getTenantRepoFactory(context, this);
		
		logger.debug(loggerPrefix + "AuthRequestHref={}", authRequestHref);
		
		AuthenticationRequest request = null;
		
		try {
			request = tenantRepoFactory.getAuthenticationRequestRepo().get(authRequestHref, IdxCommon.getAccessToken(context, this));
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "getAuthRequest exception", ex);
			throw new NodeProcessException(ex);
		}
		
		logger.info(loggerPrefix + "Exiting getAuthRequest");
		return request;
	}

	/**
	 * The possible outcomes for the IdxSponsor node.
	 */
	public enum IdxMobileAuthRequestNodeOutcome {
		/**
		 * Successful Found User.
		 */
		NEXT_OUTCOME,
		/**
		 * Error occured. Need to check sharedstate for issue
		 */
		ERROR_OUTCOME
	}

	public static class IdxMobileAuthRequestNodeOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					IdxMobileAuthRequestNodeOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(IdxMobileAuthRequestNodeOutcome.NEXT_OUTCOME.name(), bundle.getString("nextOutcome")),
					new Outcome(IdxMobileAuthRequestNodeOutcome.ERROR_OUTCOME.name(), bundle.getString("errorOutcome")));
		}
	}    
    
    
    
    
}