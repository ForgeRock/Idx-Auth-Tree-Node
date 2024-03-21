package com.daon.idxAuthRequestNode;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * 
 */
public class RestClient 
{
    private final Logger logger = LoggerFactory.getLogger(RestClient.class);
    private String restUri;
    private Client client = ClientBuilder.newClient();

    RestClient(String restUri) 
    {
        this.restUri = restUri;
    }

    
    public Response getBearerToken(String apiKey) 
    {
    	logger.debug("In getBearerToken: " + apiKey);
        return client
                .target(restUri)
                .path("api/arthr/apiKeys/issue")
                .request(MediaType.APPLICATION_JSON)
                .header("X-API-Key", apiKey)
                .post(Entity.json(""));
    }
    
    public Response createProcessToken(String bearerToken, ProcessTokenRequest ptr)
    {
    	logger.debug("In createProcessToken");
    	
    	ObjectMapper mapper = new ObjectMapper();
    	String request;
        
    	try 
    	{
    	    // convert user object to json string and return it 
    	    request = mapper.writeValueAsString(ptr);
    	    logger.debug(request);
    	
    	return client
    			.target(restUri)
    			.path("api/process-manager/processTokens")
    			.request(MediaType.APPLICATION_JSON)
    			.header("Content-Type", "application/json")
    			.header("Authorization", "Bearer " + bearerToken)
    			.post(Entity.json(request));
    	}
    	catch (Exception e) 
    	{
    	    // catch various errors
    	    e.printStackTrace();
    	    return null;
    	}
    }

    
    public Response createProcessInstance(String bearerToken, String processToken)
    {
    	logger.debug("In createProcessInstance");
    	
    	return client
    			.target(restUri)
    			.path("api/process-manager/processInstances/create")
    			.queryParam("pt", processToken)
    			.request(MediaType.APPLICATION_JSON)
    			.header("Content-Type", "application/json")
    			.header("Authorization", "Bearer " + bearerToken)
    			.post(Entity.json(""));
    }

    
    public Response getProcessInstanceStatus(String bearerToken, String processInstanceId)
    {
    	logger.debug("In getProcessInstanceStatus");
    	
    	return client
    			.target(restUri)
    			.path("api/process-manager/processInstances/" + processInstanceId)
    			.request(MediaType.APPLICATION_JSON)
    			.header("Content-Type",  "application/json")
    			.header("Authorization", "Bearer " + bearerToken)
    			.get(Response.class);
    }
    
    
    public Response getUserData(String bearerToken, String processDefnId, String processInstanceId)
    {
    	logger.debug("In getUserData");
    	
    	return client
    			.target(restUri)
    			.path("/api/userdata-server/processDefinitions/" + processDefnId + "/processInstances/" + processInstanceId + "/userdata")
    			.queryParam("optimized", "true")
    			.request(MediaType.APPLICATION_JSON)
    			.header("Content-Type", "application/json")
    			.header("Authorization", "Bearer " + bearerToken)
    			.get(Response.class);
    }
}
