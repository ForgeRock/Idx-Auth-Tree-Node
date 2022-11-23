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

import static com.daon.idxAuthRequestNode.IdxCommon.IDX_HREF_KEY;
import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;
import static org.forgerock.openam.auth.node.api.Action.goTo;

import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.google.common.collect.ImmutableList;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;

/**
 * A node that checks user authentication status in IdentityX
 */
@Node.Metadata(outcomeProvider = IdxAuthStatusNode.IdxAuthStatusOutcomeProvider.class, configClass = IdxAuthStatusNode.Config.class, tags = {
		"marketplace", "trustnetwork", "multi-factor authentication" })
public class IdxAuthStatusNode implements Node {

	private String loggerPrefix = "[IdentityX Auth Request Decision Node][Marketplace] ";
	private static final String BUNDLE = IdxAuthStatusNode.class.getName();

	private static LoggerWrapper logger = new LoggerWrapper();

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * Create the node.
	 */
	@Inject
	public IdxAuthStatusNode() {
	}

	@Override
	public Action process(TreeContext context) {
		try {

			String username = context.getStateFor(this).get("IdxKeyUserName").asString();
			if (username == null) {
				String errorMessage = "Error: IdxKeyUserName not found in sharedState! Make sure "
						+ "IdxCheckEnrollmentStatus node is in the tree!";
				logger.error(loggerPrefix + errorMessage);
				throw new NodeProcessException(errorMessage);
			}

			TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context, this);

			// call API to check status. Return true, false or pending
			// get the authHref value from sharedState
			String authHref = context.getStateFor(this).get(IDX_HREF_KEY).asString();

			if (authHref == null) {
				logger.error(loggerPrefix + "Error: href not found in SharedState!");
				throw new NodeProcessException("Unable to authenticate - HREF not found!");
			}

			String status = getAuthenticationRequestStatus(authHref, tenantRepoFactory, context, this);

			logger.debug(loggerPrefix + "Connected to the IdentityX Server @ [{}]", IdxCommon.getServerName(authHref));

			if (status.equalsIgnoreCase("COMPLETED_SUCCESSFUL")) {
				return goTo(IdxAuthStatusOutcome.SUCCESS_OUTCOME.name()).build();
			} else if (status.equalsIgnoreCase("PENDING")) {
				return goTo(IdxAuthStatusOutcome.PENDING_OUTCOME.name()).build();
			} else if (status.equalsIgnoreCase("EXPIRED")) {
				return goTo(IdxAuthStatusOutcome.EXPIRED_OUTCOME.name()).build();
			} else {
				return goTo(IdxAuthStatusOutcome.FAILED_OUTCOME.name()).build();
			}
		} catch (Exception ex) {
			logger.error(loggerPrefix + "Exception occurred: " + ex.getMessage());
			ex.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + ex.toString());
			return Action.goTo(IdxAuthStatusOutcome.ERROR_OUTCOME.name()).build();

		}
	}

	private String getAuthenticationRequestStatus(String authRequestHref, TenantRepoFactory tenantRepoFactory, TreeContext context, Node theNode)
			throws Exception {

		AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();

		AuthenticationRequest request;
		
		
		try {
			request = authenticationRequestRepo.get(authRequestHref, IdxCommon.getAccessToken(context, theNode));
		} catch (IdxRestException e) {
			logger.debug(loggerPrefix
					+ "An exception occurred while attempting to determine the status of the authentication "
					+ "request.  Exception: " + e.getMessage());
			throw new NodeProcessException(e);
		}
		logger.debug(loggerPrefix + "Retrieving an AuthenticationRequest with an HREF of " + authRequestHref);
		return request.getStatus().toString();
	}

	/**
	 * Defines the possible outcomes from this node.
	 */
	public static class IdxAuthStatusOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					IdxAuthStatusOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(IdxAuthStatusOutcome.PENDING_OUTCOME.name(), bundle.getString("pendingOutcome")),
					new Outcome(IdxAuthStatusOutcome.SUCCESS_OUTCOME.name(), bundle.getString("successOutcome")),
					new Outcome(IdxAuthStatusOutcome.FAILED_OUTCOME.name(), bundle.getString("failedOutcome")),
					new Outcome(IdxAuthStatusOutcome.EXPIRED_OUTCOME.name(), bundle.getString("expiredOutcome")),
					new Outcome(IdxAuthStatusOutcome.ERROR_OUTCOME.name(), bundle.getString("errorOutcome")));

		}
	}

	/**
	 * The possible outcomes for the IdxSponsor node.
	 */
	public enum IdxAuthStatusOutcome {
		/**
		 * Pending outcome.
		 */
		PENDING_OUTCOME,
		/**
		 * Pending outcome.
		 */
		SUCCESS_OUTCOME,
		/**
		 * Pending outcome.
		 */
		FAILED_OUTCOME,
		/**
		 * Pending outcome.
		 */
		EXPIRED_OUTCOME,
		/**
		 * Error occured. Need to check sharedstate for issue
		 */
		ERROR_OUTCOME
	}

}
