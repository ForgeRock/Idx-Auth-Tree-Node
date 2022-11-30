package com.daon.idxAuthRequestNode;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

import com.identityx.auth.client.HttpClientRequestExecutor;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.base.RestClient;
import com.identityx.clientSDK.credentialsProviders.SimpleCredentialsProvider;

class IdxTenantRepoFactorySingleton {

	private static LoggerWrapper logger = new LoggerWrapper();

	private static IdxTenantRepoFactorySingleton tenantRepoInstance = null;
	
	private static String baseURL = "";

	public TenantRepoFactory tenantRepoFactory = null;

	private IdxTenantRepoFactorySingleton(String baseURL) throws Exception {

		logger.info("Entering IdxTenantRepoFactorySingleton");

		SimpleCredentialsProvider provider = new SimpleCredentialsProvider(baseURL, null);
		SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactory.getSocketFactory();
		HttpClientRequestExecutor requestExecutor = new HttpClientRequestExecutor.HttpClientRequestExecutorBuilder().setApiKey(provider.getApiKey()).setSSLConnectionSocketFactory(socketFactory).setConnectionTimeout(50000).setMaxConnTotal(50).setMaxConnPerRoute(20).build();

		RestClient restClient = new RestClient.RestClientBuilder().setRequestExecutor(requestExecutor).build();
		tenantRepoFactory = new TenantRepoFactory.TenantRepoFactoryBuilder().setRestClient(restClient).setBaseUrl(provider.getBaseUrl()).build();

		IdxTenantRepoFactorySingleton.baseURL = baseURL;
		logger.info("Exiting IdxTenantRepoFactorySingleton");
	}

	static IdxTenantRepoFactorySingleton getInstance(String baseURL) throws Exception {
		logger.info("Entering getInstance");

		if (tenantRepoInstance == null || baseURL != IdxTenantRepoFactorySingleton.baseURL) {
			logger.debug("TenantRepoFactory is null, creating new instance");
			tenantRepoInstance = new IdxTenantRepoFactorySingleton(baseURL);
		}

		logger.info("Exiting getInstance");
		return tenantRepoInstance;
	}
}
