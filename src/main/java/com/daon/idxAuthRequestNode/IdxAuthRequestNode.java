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

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;
import static com.daon.idxAuthRequestNode.IdxCommon.objectMapper;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.def.TransactionPushNotificationTypeEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.User;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = IdxAuthRequestNode.IdxAuthRequestOutcomeProvider.class, configClass = IdxAuthRequestNode.Config.class, tags = {"marketplace", "trustnetwork", "multi-factor authentication" })
public class IdxAuthRequestNode implements Node {

	private String loggerPrefix = "[IdentityX Auth Request Initiator Node][Marketplace] ";

	private static final String BUNDLE = IdxAuthRequestNode.class.getName();

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
		 * the IdenitityX request type (IX, FI)
		 * 
		 * @return the request type
		 */
		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		default boolean isFidoRequest() {
			return true;
		}

		/**
		 * option to send push notifications
		 * 
		 * @return true or false
		 */
		@Attribute(order = 400, validators = { RequiredValueValidator.class })
		default boolean sendPushNotification() {
			return true;
		}
	}

	private final Config config;
	private static LoggerWrapper logger = new LoggerWrapper();

	/**
	 * Create the node.
	 */
	@Inject
	public IdxAuthRequestNode(@Assisted Config config) {
		this.config = config;
	}

	@Override
	public Action process(TreeContext context) {
		User user;

		try {
			try {
				user = objectMapper.readValue(context.getStateFor(this).get(IdxCommon.IDX_USER_KEY).asString(),
						User.class);
			} catch (IOException e) {
				logger.error(loggerPrefix + "Can't find user in SharedState");
				throw new NodeProcessException(e);
			}

			TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context, this);
			logger.debug(loggerPrefix + "Connected to the IdentityX Server");

			String authHref = generateAuthenticationRequest(user, config.policyName(), tenantRepoFactory, context);
			logger.debug(loggerPrefix + "Auth href: " + authHref);

			// Place the href value in sharedState
			logger.debug(loggerPrefix + "Setting auth URL in shared state...");
			context.getStateFor(this).putShared(IdxCommon.IDX_HREF_KEY, authHref);

			return Action.goTo(IdxAuthRequestOutcome.NEXT_OUTCOME.name()).build();
		} catch (Exception ex) {
			logger.error(loggerPrefix + "Exception occurred: " + ex.getMessage());
			ex.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.toString());
			return Action.goTo(IdxAuthRequestOutcome.ERROR_OUTCOME.name()).build();
		}
	}

	private String generateAuthenticationRequest(User user, String policyName, TenantRepoFactory tenantRepoFactory, TreeContext context)
			throws Exception {

		AuthenticationRequest request = new AuthenticationRequest();
		if (user == null) {
			String error = loggerPrefix + "Error retrieving user";
			logger.error(error);
			throw new NodeProcessException(error);
		} else {
			logger.debug(loggerPrefix + "User found with ID " + user.getUserId());
			request.setUser(user);
		}

		PolicyQueryHolder holder = new PolicyQueryHolder();
		holder.getSearchSpec().setPolicyId(policyName);
		holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
		PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
		PolicyCollection policyCollection;		
		
		try {
			//policyCollection = policyRepo.list(holder);
			policyCollection = policyRepo.list(holder, (HashMap<String, String>) IdxCommon.getAccessToken(context,this));
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}
		if (policyCollection.getItems().length > 0) {
			logger.debug(loggerPrefix + "Setting Policy On Authentication Request");
			request.setPolicy(policyCollection.getItems()[0]);
		} else {
			logger.error(loggerPrefix + "Could not find an active policy with the PolicyId: " + policyName);
			throw new NodeProcessException(
					loggerPrefix + "Could not find an active policy with the PolicyId: " + policyName);
		}

		String appId = config.applicationId();
		ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
		ApplicationQueryHolder applicationQueryHolder = new ApplicationQueryHolder();
		applicationQueryHolder.getSearchSpec().setApplicationId(appId);
		ApplicationCollection applicationCollection;
		try {
			applicationCollection = applicationRepo.list(applicationQueryHolder, (HashMap<String, String>) IdxCommon.getAccessToken(context,this));
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}

		if (applicationCollection.getItems().length > 0) {
			request.setApplication(applicationCollection.getItems()[0]);
		} else {
			logger.debug(loggerPrefix + "No Application was found with this name " + appId);
			throw new NodeProcessException(loggerPrefix + "No Application was found with this name " + appId);
		}

		request.setDescription("OpenAM has Requested an Authentication.");

		String txnRequestType = "FI";
		if (!config.isFidoRequest()) {
			txnRequestType = "IX";
		}
		request.setType(txnRequestType);
		request.setOneTimePasswordEnabled(false);
		request.setAuthenticationRequestId(UUID.randomUUID().toString());

		if (config.sendPushNotification()) {
			request.setPushNotificationType(TransactionPushNotificationTypeEnum.VERIFY_WITH_CONFIRMATION);
		}

		AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
		try {
			request = authenticationRequestRepo.create(request, (HashMap<String, String>) IdxCommon.getAccessToken(context,this));
		} catch (IdxRestException e) {
			logger.debug(loggerPrefix + "Error creating authentication request for user: " + user.getUserId());
			throw new NodeProcessException(e);
		}
		logger.debug(loggerPrefix + "Added an authentication request, - authRequestId: {}" + request.getId());
		return request.getHref();
	}

	/**
	 * The possible outcomes for the IdxSponsor node.
	 */
	public enum IdxAuthRequestOutcome {
		/**
		 * Successful Found User.
		 */
		NEXT_OUTCOME,
		/**
		 * Error occured. Need to check sharedstate for issue
		 */
		ERROR_OUTCOME
	}

	public static class IdxAuthRequestOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					IdxAuthRequestOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(IdxAuthRequestOutcome.NEXT_OUTCOME.name(), bundle.getString("nextOutcome")),
					new Outcome(IdxAuthRequestOutcome.ERROR_OUTCOME.name(), bundle.getString("errorOutcome")));
		}
	}
}
