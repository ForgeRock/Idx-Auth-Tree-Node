/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.findUser;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.StringUtils;
import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.sun.identity.sm.RequiredValueValidator;

import javax.inject.Inject;

/**
 * A node that checks to see if a provided username is enrolled in IdentityX
 *
 * Note on the userId value: By default, the node will assume the provided
 * username is the userId value from ForgeRock. If the implementation needs to
 * use a different value for the IdentityX userId, a custom node will need to be
 * inserted before this one to provide such mapping. Config values in this node
 * will allow the administrator to define which value in sharedState to use for
 * the IdentityX userId.
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = IdxCheckEnrollmentStatus.Config.class, tags = { "marketplace", "trustnetwork", "multi-factor authentication" })
public class IdxCheckEnrollmentStatus extends AbstractDecisionNode {

    private String loggerPrefix = "[IdentityX Check Enrollment Status Node][Partner] ";
	
	/**
	 * Configuration for the node.
	 */
	public interface Config {

		/**
		 * The client ID in ForgeRock we are using for Access Token Build
		 * 
		 * @return the client ID
		 */
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		String clientID();

		/**
		 * The client Secret in ForgeRock we are using for Access Token Build
		 * 
		 * @return the client Secret
		 */
		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		String clientSecret();

		/**
		 * BaseURL to IdentityX Store
		 * 
		 * @return the base URL to Daon
		 */
		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		@Password
		String baseURL();

		/**
		 * the attribute in sharedState to use for IdentityX userId
		 * 
		 * @return the userIdAttribute
		 */
		@Attribute(order = 400)
		String userIdAttribute();

	}

	private final Config config;
	private static LoggerWrapper logger = new LoggerWrapper();

	@Inject
	public IdxCheckEnrollmentStatus(@Assisted Config config) {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) {

		try {
			String userIdAttribute;
			// Check for the userIdAttribute in sharedState
			// If it is defined, we should use it instead of the AM USERNAME
			if (StringUtils.isBlank(config.userIdAttribute())) {
				userIdAttribute = SharedStateConstants.USERNAME;
			} else {
				userIdAttribute = config.userIdAttribute();
			}

			JsonValue usernameJson = context.sharedState.get(userIdAttribute);

			if (usernameJson.isNull() || StringUtils.isBlank(usernameJson.asString())) {
				logger.error(loggerPrefix + "Here is the userIdAttribute used to looking in sharedState: " + userIdAttribute);
				throw new NodeProcessException("Username attribute " + userIdAttribute + " is either null or empty");
			}

			String username = usernameJson.asString();

			String theClientID = config.clientID();
			String theClientSecret = config.clientSecret();
			String theBaseURL = config.baseURL();

			logger.debug("IdxCheckEnrollmentStatus::Configuration - gathered ClientID ClientSecret and BaseURL");

			TenantRepoFactory tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(theBaseURL).tenantRepoFactory;

			// Set all config params in SharedState
			JsonValue newState = context.sharedState.copy();

			newState.put("IdxClientID", theClientID);
			newState.put("IdxClientSecret", theClientSecret);
			newState.put("IdxBaseURL", theBaseURL);
			newState.put("IdxKeyUserName", username);

			User user = findUser(username, tenantRepoFactory, context);

			if (user == null) {
				logger.error("FATAL: UserID=[{}] not found in IdentityX", username);
				return goTo(false).replaceSharedState(newState).build();
			}

			logger.debug("Connected to the IdentityX Server @ [{}]", IdxCommon.getServerName(user.getHref()));
			logger.debug("User found with ID {}", username);

			newState.put(IdxCommon.IDX_USER_HREF_KEY, user.getHref());
			newState.put(IdxCommon.IDX_USER_INTERNAL_ID_KEY, user.getId());
			newState.put(IdxCommon.IDX_USER_ID_KEY, user.getUserId());

			logger.debug("Added to SharedState - User Id=[{}] UserId=[{}] Href=[{}]", user.getId(), user.getUserId(), user.getHref());

			return goTo(true).replaceSharedState(newState).build();
		} catch (Exception ex) {
            logger.error(loggerPrefix + "Exception occurred: " + ex.getMessage());
            ex.printStackTrace();
            context.sharedState.put("Exception", ex.toString());
            return Action.goTo("error").build();

		}
	}
}
