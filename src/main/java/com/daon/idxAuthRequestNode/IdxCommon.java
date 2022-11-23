package com.daon.idxAuthRequestNode;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.forgerock.http.util.Json;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.utils.StringUtils;

import com.daon.identityx.rest.model.def.UserStatusEnum;
import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityx.auth.client.HttpClientRequestExecutor;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.base.RestClient;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.credentialsProviders.SimpleCredentialsProvider;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.UserRepository;
import org.forgerock.openam.auth.node.api.Node;

class IdxCommon {

	static ObjectMapper objectMapper = new ObjectMapper();

	private static LoggerWrapper logger = new LoggerWrapper();

	static final String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";
	static final String IDX_USER_KEY = "idx-user-object-shared-state-key";

	static final String IDX_USER_HREF_KEY = "idx-user-href-shared-state-key";
	static final String IDX_USER_INTERNAL_ID_KEY = "idx-user-internal-id-shared-state-key";
	static final String IDX_USER_ID_KEY = "idx-user-id-shared-state-key";
	static final String IDX_AUTH_RESPONSE_KEY = "idx-fido-auth-response-shared-state-key";

	static final String IDX_AUTH_RESPONSE_PROPERTY_NAME = "fidoAuthenticationResponse";
	static final String IDX_AUTH_REQUEST_TYPE = "FI";

	static final HttpClient httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();

	static User findUser(String userId, TenantRepoFactory tenantRepoFactory, TreeContext context, String theClientID, String theClientSecret, String idxBaseURL) throws Exception {

		if (theClientID == null) {
			logger.error("Error: ClientID not in shared state!");
			throw new NodeProcessException("ClientID not in shared state!");
		}
		
		if (theClientSecret == null) {
			logger.error("Error: ClientSecret not in shared state!");
			throw new NodeProcessException("ClientSecret not in shared state!");
		}
		
		if (idxBaseURL == null) {
			logger.error("Error: idxBaseURL not in shared state!");
			throw new NodeProcessException("idxBaseURL not in shared state!");
		}
		

		String identityCloudURL = context.request.serverUrl + "/oauth2/alpha/access_token";
		logger.error("Here is the identityCloudURL: " + identityCloudURL);
		
		
		String accessToken = getAccessToken(theClientID, theClientSecret, identityCloudURL);

		Map<String, String> requestHeaders = new HashMap<>();

		// Pass the JWT generated into the header name defined in the IdentityX Admin
		// Console

		requestHeaders.put("Authorization", accessToken);

		// Sample Test of a basic Active User Retrieval

		UserQueryHolder uqh = new UserQueryHolder();

		uqh.getSearchSpec().setStatus(UserStatusEnum.ACTIVE);

		UserRepository userRepo = tenantRepoFactory.getUserRepo();
		UserQueryHolder holder = new UserQueryHolder();
		holder.getSearchSpec().setUserId(userId);
		holder.getSearchSpec().setStatus(UserStatusEnum.ACTIVE);
		UserCollection userCollection;
		userCollection = userRepo.list(holder, (HashMap<String, String>) requestHeaders);

		if (userCollection == null) {
			return null;
		}
		if (userCollection.getItems() == null) {
			return null;
		}
		switch (userCollection.getItems().length) {
		case 0:
			return null;
		case 1:
			return userCollection.getItems()[0];
		default:
			String error = "More than one Daon user with the same UserId";
			logger.error(error);
			throw new NodeProcessException(error);
		}
	}

	static TenantRepoFactory getTenantRepoFactory(TreeContext context, Node theNode) throws Exception {
		TenantRepoFactory tenantRepoFactory;

		String theBaseURL = context.getStateFor(theNode).get("IdxBaseURL").asString();
		
		if (theBaseURL == null) {
			logger.error("Error: The Base URL was not in the shared state!");
			throw new NodeProcessException("The Base URL was not in the shared state!");
		}

		tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(theBaseURL).tenantRepoFactory;

		if (tenantRepoFactory != null) {
			logger.debug("Successfully Initialised the TenantRepoFactory");
		} else {
			logger.error("Failure to Initialised the TenantRepoFactory");
			throw new NodeProcessException("Error creating tenantRepoFactory");
		}

		return tenantRepoFactory;
	}

	static String getServerName(String href) {

		logger.info("Entering getServerName");

		String server = null;

		if (StringUtils.isNotEmpty(href)) {

			URL url;

			try {

				url = new URL(href);

				String host = url.getHost();
				int port = url.getPort();

				if (port == -1) {
					server = String.format("%s", host);
				} else {
					server = String.format("%s:%d", host, port);
				}

			} catch (MalformedURLException ex) {
				logger.error("getServerName Exception", ex);
			}
		}

		logger.info("Exiting getServerName");
		return server;
	}

	public static String getAccessToken(String clientID, String clientSecret, String baseURL) throws Exception {
		String retVal = null;
		String accessToken = Base64.getEncoder().encodeToString((clientID + ":" + clientSecret).getBytes());

		// form parameters
		Map<Object, Object> data = new HashMap<>();
		data.put("grant_type", "client_credentials");
		data.put("scope", "fr:idm:*");

		HttpRequest request = HttpRequest.newBuilder().POST(buildFormDataFromMap(data)).uri(URI.create(baseURL)).setHeader("Authorization", "Basic " + accessToken).setHeader("Content-Type", "application/x-www-form-urlencoded").build();

		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		if (response != null && response.statusCode() == 200 && response.body().contains("access_token")) {
			LinkedHashMap responseBody = (LinkedHashMap) Json.readJson(response.body());
			retVal = (String) responseBody.get("access_token");
		}
		return retVal;
	}
	
	public static HashMap<String, String> getAccessToken(TreeContext context, Node thisNode) throws Exception {
		NodeState newState = context.getStateFor(thisNode);
		String clientID = newState.get("IdxClientID").asString();
		String clientSecret = newState.get("IdxClientSecret").asString();
		String identityCloudURL = context.request.serverUrl + "/oauth2/alpha/access_token";
		String retVal = getAccessToken(clientID,clientSecret,identityCloudURL);
		HashMap<String, String> requestHeaders = new HashMap<>();
		requestHeaders.put("Authorization", retVal);
		
		return requestHeaders;
	}
	
	

	private static HttpRequest.BodyPublisher buildFormDataFromMap(Map<Object, Object> data) {
		var builder = new StringBuilder();
		for (Map.Entry<Object, Object> entry : data.entrySet()) {
			if (builder.length() > 0) {
				builder.append("&");
			}
			builder.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
			builder.append("=");
			builder.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
		}
		return HttpRequest.BodyPublishers.ofString(builder.toString());
	}

	
	//for testing purposes only
	
	public static User findUser(String userId, String clientID, String clientSecret, String identityXBaseURL, String frURL) throws Exception {

		SimpleCredentialsProvider provider = new SimpleCredentialsProvider(identityXBaseURL, null);

		SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactory.getSocketFactory();

		HttpClientRequestExecutor requestExecutor = new HttpClientRequestExecutor.HttpClientRequestExecutorBuilder().setApiKey(provider.getApiKey())

				.setSSLConnectionSocketFactory(socketFactory).setConnectionTimeout(50000).setMaxConnTotal(50).setMaxConnPerRoute(20).build();

		RestClient restClient = new RestClient.RestClientBuilder().setRequestExecutor(requestExecutor).build();

		TenantRepoFactory tenantRepoFactory = new TenantRepoFactory.TenantRepoFactoryBuilder().setRestClient(restClient).setBaseUrl(provider.getBaseUrl()).build();

		Map<String, String> requestHeaders = new HashMap<>();

		String theAT = getAccessToken(clientID, clientSecret, frURL);

		requestHeaders.put("Authorization", theAT);

		UserRepository userRepo = tenantRepoFactory.getUserRepo();
		UserQueryHolder holder = new UserQueryHolder();
		holder.getSearchSpec().setUserId(userId);
		holder.getSearchSpec().setStatus(UserStatusEnum.ACTIVE);
		UserCollection userCollection;
		userCollection = userRepo.list(holder, (HashMap<String, String>) requestHeaders);

		if (userCollection == null) {
			return null;
		}
		if (userCollection.getItems() == null) {
			return null;
		}
		switch (userCollection.getItems().length) {
		case 0:
			return null;
		case 1:
			return userCollection.getItems()[0];
		default:
			String error = "More than one Daon user with the same UserId";
			logger.error(error);
			throw new NodeProcessException(error);
		}

	}

}
