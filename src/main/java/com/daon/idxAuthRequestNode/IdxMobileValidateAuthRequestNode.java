package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

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
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that validates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = IdxMobileValidateAuthRequestNode.IdxMobileValidateAuthRequestNodeOutcomeProvider.class, configClass = IdxMobileValidateAuthRequestNode.Config.class, tags = {"marketplace", "trustnetwork", "multi-factor authentication"})
public class IdxMobileValidateAuthRequestNode extends AbstractDecisionNode {

	private static LoggerWrapper logger = new LoggerWrapper();
	private String loggerPrefix = "[IdentityX Mobile Auth Request Validate][Marketplace] ";
	private static final String BUNDLE = IdxMobileValidateAuthRequestNode.class.getName();
	
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
				obj = new JSONObject(context.getStateFor(this).get(IdxCommon.IDX_AUTH_RESPONSE_KEY).asString());
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
	
			logger.debug(loggerPrefix + "Test={}", test);
	
			if (TextUtils.isEmpty(test) || !isJsonOk) {
				test = context.getStateFor(this).get(IdxCommon.IDX_AUTH_RESPONSE_KEY).asString();
				logger.debug(loggerPrefix + "Using-Postman={}", test);
			}
	
			if (validateAuthResponse(test, context)) {
				return Action.goTo(IdxMobileValidateAuthRequestNodeOutcome.TRUE_OUTCOME.name()).build();
			}
			return Action.goTo(IdxMobileValidateAuthRequestNodeOutcome.FALSE_OUTCOME.name()).build();
		}
		catch (Exception ex) {
			logger.error(loggerPrefix + "Exception occurred: " + ex.getStackTrace());
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			ex.printStackTrace(pw);
			context.getStateFor(this).putShared(loggerPrefix + "StackTracke", new Date() + ": " + sw.toString());
            return Action.goTo(IdxMobileValidateAuthRequestNodeOutcome.ERROR_OUTCOME.name()).build();

		}
	}

	private boolean validateAuthResponse(String authResponse, TreeContext context) throws Exception {

		// Call API to check status. Return true, false or pending get the authHref value from sharedState
		String authHref = context.getStateFor(this).get(IdxCommon.IDX_HREF_KEY).asString();
				
		try {
			
			TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context, this);			
			
			AuthenticationRequest request = tenantRepoFactory.getAuthenticationRequestRepo().get(authHref, IdxCommon.getAccessToken(context, this));
			
			if (request == null) {
				logger.error(loggerPrefix + "AuthRequest Href = {} is invalid", authHref);
				return false;
			}
			
			request.setFidoAuthenticationResponse(authResponse);
			
			request = tenantRepoFactory.getAuthenticationRequestRepo().update(request, IdxCommon.getAccessToken(context, this));
			
			logger.debug(loggerPrefix + "Checking Status=[{}]", nodeConfig.expectedStatus());
			
			if (request.getStatus() == nodeConfig.expectedStatus()) {
				logger.debug(loggerPrefix + "Success Status=[{}]", nodeConfig.expectedStatus());
				 context.getStateFor(this).putShared(IdxCommon.IDX_HREF_KEY, request.getHref());
				//Required for 'Daon ADoS SRP Passcode Authenticator' [D409#9302|D409#8302]
				 context.getStateFor(this).putShared(IdxCommon.IDX_AUTH_RESPONSE_KEY, request.getFidoAuthenticationResponse());
				return true;
			}
			
			logger.error(loggerPrefix + "AuthRequest Status = {} is invalid", request.getStatus());
			return false;
			
		} catch (IdxRestException ex) {
			logger.error(loggerPrefix + "validateAuthResponse exception", ex);
			return false;
		}
	}
	
	
	/**
	 * The possible outcomes for the IdxSponsor node.
	 */
	public enum IdxMobileValidateAuthRequestNodeOutcome {
		/**
		 * Successful Found User.
		 */
		TRUE_OUTCOME,
		/**
		 * Did not find User.
		 */
		FALSE_OUTCOME,
		/**
		 * Error occured. Need to check sharedstate for issue
		 */
		ERROR_OUTCOME
	}
	
	
    public static class IdxMobileValidateAuthRequestNodeOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					IdxMobileValidateAuthRequestNodeOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(IdxMobileValidateAuthRequestNodeOutcome.TRUE_OUTCOME.name(), bundle.getString("trueOutcome")),
					new Outcome(IdxMobileValidateAuthRequestNodeOutcome.FALSE_OUTCOME.name(), bundle.getString("falseOutcome")),
					new Outcome(IdxMobileValidateAuthRequestNodeOutcome.ERROR_OUTCOME.name(), bundle.getString("errorOutcome")));
        }
    }
}
