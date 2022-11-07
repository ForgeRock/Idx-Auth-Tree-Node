package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;

import org.apache.http.util.TextUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONException;
import org.json.JSONObject;

import com.daon.identityx.rest.model.def.AuthenticationRequestStatusEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that validates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = IdxMobileValidateAuthRequestNode.OutcomeProvider.class, configClass = IdxMobileValidateAuthRequestNode.Config.class, tags = {"marketplace", "trustnetwork", "multi-factor authentication"})
public class IdxMobileValidateAuthRequestNode extends AbstractDecisionNode {

	private static LoggerWrapper logger = new LoggerWrapper();
	private String loggerPrefix = "[IdentityX Mobile Auth Request Validate Node][Partner] ";

    /**
     * Outcomes Ids for this node.
     */
    static final String SUCCESS_OUTCOME = "True";
    static final String FALSE_OUTCOME = "False";
    static final String ERROR_OUTCOME = "Error";
	
	public interface Config {
		
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		default AuthenticationRequestStatusEnum expectedStatus() {
			return AuthenticationRequestStatusEnum.COMPLETED_SUCCESSFUL;
		}	
	}
	
	private final Config nodeConfig;	
	
	 /**
     * Create the node.
     */
    @Inject
    public IdxMobileValidateAuthRequestNode(@Assisted Config config) {
        this.nodeConfig = config;
    }

	@Override
	public Action process(TreeContext context) {
		try {
			String test = null;
			JSONObject obj = null;
			boolean isJsonOk = false;
	
			try {
				obj = new JSONObject(context.sharedState.get(IdxCommon.IDX_AUTH_RESPONSE_KEY).asString());
				logger.debug(loggerPrefix + "Json={}", obj.toString());
			} catch (JSONException e) {
				logger.warn(loggerPrefix + "Cannot cast SharedState Key = [{}] to JSON Object = {}", IdxCommon.IDX_AUTH_RESPONSE_KEY, e.getMessage());
			}
	
			if (obj != null) {
				
				try {
					test = obj.getString(IdxCommon.IDX_AUTH_RESPONSE_PROPERTY_NAME);
					isJsonOk = true;
				} catch (JSONException e) {
					logger.warn(loggerPrefix + "Cannot cast JSON Object Property = [{}] to JSON Object = {}", IdxCommon.IDX_AUTH_RESPONSE_PROPERTY_NAME, e.getMessage());
				}
			}
	
			logger.debug("Test={}", test);
	
			if (TextUtils.isEmpty(test) || !isJsonOk) {
				test = context.sharedState.get(IdxCommon.IDX_AUTH_RESPONSE_KEY).asString();
				logger.debug(loggerPrefix + "Using-Postman={}", test);
			}
	
			if (validateAuthResponse(test, context)) {
				return Action.goTo(SUCCESS_OUTCOME)
						.replaceSharedState(context.sharedState)				
						.build();
			}
			return Action.goTo(FALSE_OUTCOME).build();
		}
		catch (Exception ex) {
            logger.error(loggerPrefix + "Exception occurred: " + ex.getMessage());
            ex.printStackTrace();
            context.sharedState.put(loggerPrefix + "Exception", new Date() + ": " + ex.toString());
            return Action.goTo(ERROR_OUTCOME).build();

		}
	}

	private boolean validateAuthResponse(String authResponse, TreeContext context) throws Exception {

		// Call API to check status. Return true, false or pending get the authHref value from sharedState
		String authHref = context.sharedState.get(IdxCommon.IDX_HREF_KEY).asString();
				
		try {
			
			TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);			
			
			AuthenticationRequest request = tenantRepoFactory.getAuthenticationRequestRepo().get(authHref);
			
			if (request == null) {
				logger.error(loggerPrefix + "AuthRequest Href = {} is invalid", authHref);
				return false;
			}
			
			request.setFidoAuthenticationResponse(authResponse);
			
			request = tenantRepoFactory.getAuthenticationRequestRepo().update(request);
			
			logger.debug(loggerPrefix + "Checking Status=[{}]", nodeConfig.expectedStatus());
			
			if (request.getStatus() == nodeConfig.expectedStatus()) {
				logger.debug(loggerPrefix + "Success Status=[{}]", nodeConfig.expectedStatus());
				context.sharedState.put(IdxCommon.IDX_HREF_KEY, request.getHref());
				//Required for 'Daon ADoS SRP Passcode Authenticator' [D409#9302|D409#8302]
				context.sharedState.put(IdxCommon.IDX_AUTH_RESPONSE_KEY, request.getFidoAuthenticationResponse());
				return true;
			}
			
			logger.error(loggerPrefix + "AuthRequest Status = {} is invalid", request.getStatus());
			return false;
			
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "validateAuthResponse exception", ex);
			return false;
		}
	}
	
    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, SUCCESS_OUTCOME)
                    )
            );
            results.add(new Outcome(FALSE_OUTCOME, FALSE_OUTCOME));
            results.add(new Outcome(ERROR_OUTCOME, ERROR_OUTCOME));

            return Collections.unmodifiableList(results);
        }
    }
}
