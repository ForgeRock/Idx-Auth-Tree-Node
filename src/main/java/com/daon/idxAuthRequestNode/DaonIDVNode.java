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
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.DaonIDVConstants.ERROR;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.inject.Inject;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that performs IDV onboarding using Daon TrustX
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = DaonIDVNode.Config.class,
               tags 			= {"marketplace", "trustnetwork", "identity management"})
public class DaonIDVNode extends AbstractDecisionNode 
{
    private final Logger logger = LoggerFactory.getLogger(DaonIDVNode.class);
    private final String loggerPrefix = "[Daon IDV Node][Marketplace] ";
    private final Config config;
    private String baseRestUri;

    /**
     * Configuration for the node.
     */
    public interface Config 
    {
        /**
         * Tenant name of the TrustX instance being used.
         * 
         * @return the tenant name
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String tenantName();
        
        /**
         * Region name of the TrustX instance being used.
         * 
         * @return the region name
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        String regionName();
        
        /**
         * The API Key used to authenticate the node to make calls to TrustX.
         * 
         * @return the API key
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        String apiKey();
        
        /**
         * The name of the TrustX process definition that will be used for IDV.
         * 
         * @return the process definition name
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        String processDefinitionName();
        
        /**
         * The version number of the TrustX process definition that will be used for IDV.
         * 
         * @return the process definition version number
         */
        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        String processDefinitionVersion();
        
        /**
         * The URL that TrustX will redirect to when IDV is complete.
         *
         * @return the redirect URL
         */
    	@Attribute(order = 600, validators = {RequiredValueValidator.class})
        String redirectUrl();
    	
    	 /**
         * Option to retrieve the user data from TrustX.
         * 
         * @return true or false
         */
        @Attribute(order = 700, validators = {RequiredValueValidator.class})
        default boolean getUserData()
        {
        	return true;
        }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public DaonIDVNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException 
    {
        this.config = config;
        baseRestUri = "https://" + config.tenantName() + "." + config.regionName() +".trustx.com/";
    }

    
    @Override
    public Action process(TreeContext context) throws NodeProcessException 
    {
    	try
    	{
    		logger.debug(loggerPrefix + "Entering Daon IDV Node");
    		Map<String, List<String>> parameters = context.request.parameters;
    		NodeState state = context.getStateFor(this);
    		
    		if (parameters.containsKey(ERROR))
    		{
    			throw new NodeProcessException("IDV failed:  " + parameters.get(ERROR).get(0));
    		}
    		
    		RestClient restClient = new RestClient(this.baseRestUri);
    		
    		if (state.isDefined("InstanceId"))
    		{
    			logger.debug(loggerPrefix + "Returned from TrustX IDV process");
    			String bearerToken = state.get("BearerToken").asString();
    			String processInstanceId = state.get("InstanceId").asString();
    			state.remove("InstanceId");
    			state.remove("BearerToken");
    			
    			String status = this.getProcessInstanceStatus(restClient, bearerToken, processInstanceId);
    			state.putShared("Status", status);
    			ObjectMapper mapper = new ObjectMapper();
    			ProcessInstanceStatus processStatus = mapper.readValue(status, ProcessInstanceStatus.class);
    			
    			if (processStatus.getStatus().equals("COMPLETED_ENDED_SUCCESS"))
    			{
    				if (config.getUserData())
    				{
    					String userData = this.getUserData(restClient, bearerToken, processStatus.getProcessDefnId(), processInstanceId);
    					state.putShared("UserData", userData);
    				}
    				logger.debug(loggerPrefix + "Exiting Daon IDV Node with True Outcome");
    				return Action.goTo(DaonIDVNode.TRUE_OUTCOME_ID).build();
    			}
    			else
    			{
    				logger.debug(loggerPrefix + "Exiting Daon IDV Node with False Outcome");
    				return Action.goTo(DaonIDVNode.FALSE_OUTCOME_ID).build();
    			}
    		}

    		String bearerToken = this.getBearerToken(restClient, config.apiKey());
    		String processToken = this.getProcessToken(restClient, bearerToken);
    		ProcessInstanceInfo info = this.createProcessInstance(restClient, bearerToken, processToken);
    		state.putShared("InstanceId", info.getProcessInstanceId());
    		state.putShared("BearerToken", bearerToken);

    		RedirectCallback redirectCallback = new RedirectCallback(info.getRedirectIdvUrl(), null, "GET");
    		redirectCallback.setTrackingCookie(true);
    		logger.debug(loggerPrefix + "Redirecting to " + info.getRedirectIdvUrl());
    		return Action.send(redirectCallback).build();
    	}
    	catch(Exception e)
    	{
    		logger.error(loggerPrefix + "Exception occurred: " + e.getStackTrace());
            logger.error(loggerPrefix + "Error = " + e.getMessage());
            logger.debug(ExceptionUtils.getStackTrace(e));
            context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", new Date() + ": " + sw.toString());
            logger.debug(loggerPrefix + "Exiting Daon IDV Node with False Outcome");
            return Action.goTo(DaonIDVNode.FALSE_OUTCOME_ID).build();
    	}
    }
    
    private String getBearerToken(RestClient restClient, String apiKey) throws NodeProcessException
    {
    	Response response = restClient.getBearerToken(apiKey);   	
    	String jsonString = response.readEntity(String.class);
	
		try
		{
			JsonNode token = new ObjectMapper().readTree(jsonString).get("token");
			String bearerToken = token.asText();
			return bearerToken;
		}
		catch(Exception e)
		{
			throw new NodeProcessException("Unable to get bearer token:  " + e.getMessage());
		}
    }
    
    private String getProcessToken(RestClient restClient, String bearerToken) throws NodeProcessException
    {
    	ProcessTokenRequest ptr = new ProcessTokenRequest();
    	UUID uuid = UUID.randomUUID();
        ptr.setName(uuid.toString());
        ptr.setProcessDefnName(config.processDefinitionName());
        ptr.setProcessDefnVersion(config.processDefinitionVersion());
        ptr.setStatus("ACTIVE");
        ptr.setType("UNLIMITED");
        ptr.setUiUrl(this.baseRestUri + "web/trustweb");
        
        ProcessTokenParameters parameters = new ProcessTokenParameters();
        parameters.set_redirectUrl(config.redirectUrl());
        
        ptr.setParameters(parameters);
        
        Response response = restClient.createProcessToken(bearerToken, ptr);
        
        String jsonString = response.readEntity(String.class);
        try
        {
        	JsonNode token = new ObjectMapper().readTree(jsonString).get("id");
        	String processToken = token.asText();
        	return processToken;
        }
        catch(Exception e)
        {
        	throw new NodeProcessException("Unable to create a process token: " + e.getMessage());
        }
    }
    
    private ProcessInstanceInfo createProcessInstance(RestClient restClient, String bearerToken, String processToken) throws NodeProcessException
    {
    	Response response = restClient.createProcessInstance(bearerToken, processToken);
		
		String jsonString = response.readEntity(String.class);
		try
		{
			ProcessInstanceInfo info = new ProcessInstanceInfo();
			ObjectMapper mapper = new ObjectMapper();
			JsonNode urlNode = mapper.readTree(jsonString).get("redirectUrl");
			JsonNode instanceNode = mapper.readTree(jsonString).get("processInstanceId");
			info.setRedirectIdvUrl(urlNode.asText());
			info.setProcessInstanceId(instanceNode.asText());
			return info;
		}
		catch (Exception e)
		{
			throw new NodeProcessException("Could not create a process instance: " + e.getMessage());
		}
    }
    
    
    private String getProcessInstanceStatus(RestClient restClient, String bearerToken, String processInstanceId)
    {
    	Response response = restClient.getProcessInstanceStatus(bearerToken, processInstanceId);
    	String jsonString = response.readEntity(String.class);
    	return jsonString;
    }
    
    
    private String getUserData(RestClient restClient, String bearerToken, String processDefnId, String processInstanceId)
    {
    	Response response = restClient.getUserData(bearerToken, processDefnId, processInstanceId);
    	String jsonString = response.readEntity(String.class);
    	return jsonString;
    }
}
