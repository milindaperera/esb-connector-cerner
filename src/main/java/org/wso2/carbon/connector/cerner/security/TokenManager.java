/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.connector.cerner.security;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.connector.cerner.CernerConnectorException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.util.ArrayList;

/**
 * This will hold and manage tokens
 */
public class TokenManager {

    private static final Log LOG = LogFactory.getLog(TokenManager.class);
    private static final JsonParser parser = new JsonParser();
    private static final TokenStore TOKEN_STORE = new InMemoryTokenStore();

    private TokenManager() {
    }

    /**
     * Function to get access to ken for given client ID and token EP
     *
     * @param clientId
     * @param tokenEP
     * @return
     * @throws CernerConnectorException
     */
    public static Token getToken(String clientId, String tokenEP) throws CernerConnectorException {
        String tokenKey = clientId + SecurityConstants.TOKEN_KEY_SEPARATOR + tokenEP;
        return TOKEN_STORE.get(tokenKey);
    }

    /**
     * Function to remove token from the token cache
     *
     * @param clientId
     * @param tokenEP
     */
    public static void removeToken(String clientId, String tokenEP) {
        String tokenKey = clientId + SecurityConstants.TOKEN_KEY_SEPARATOR + tokenEP;
        TOKEN_STORE.remove(tokenKey);
    }

    /**
     * Clean all Access tokens from the token cache
     */
    public static void clean() {
        TOKEN_STORE.clean();
        LOG.info("Token map cleaned");
    }

    /**
     * Function to get new token
     *
     * @param clientId
     * @param clientSecret
     * @param tokenEP
     * @return
     * @throws CernerConnectorException
     */
    public static synchronized Token getNewSystemToken (String clientId, char[] clientSecret, String scope,
                                                   String tokenEP) throws CernerConnectorException {
        String tokenKey = clientId + SecurityConstants.TOKEN_KEY_SEPARATOR + tokenEP;
        Token token = TOKEN_STORE.get(tokenKey);
        if (token == null || !token.isActive()) {
            token = getSystemAccessToken(clientId, clientSecret, scope, tokenEP);
            TOKEN_STORE.add(tokenKey, token);
        }
        return token;
    }

    /**
     * Function to retrieve new client credential access token from the token endpoint
     *
     * @param clientId
     * @param clientSecret
     * @param tokenEP
     * @return
     * @throws CernerConnectorException
     */
    private static Token getSystemAccessToken(String clientId, char[] clientSecret, String scope,
                                            String tokenEP) throws CernerConnectorException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving new system access token from token endpoint");
        }
        long curTimeInMillis = System.currentTimeMillis();
        HttpPost postRequest = new HttpPost(tokenEP);

        String authHeader = new String(new Base64().encode((clientId + ':' + String.valueOf(clientSecret)).getBytes()));
        postRequest.addHeader("Authorization", authHeader);

        ArrayList<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
        parameters.add(new BasicNameValuePair("scope", scope));
        try {
            postRequest.setEntity(new UrlEncodedFormEntity(parameters));
        } catch (UnsupportedEncodingException e) {
            throw new CernerConnectorException(e, "Error occurred while preparing access token request payload");
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(postRequest)) {
            HttpEntity responseEntity = response.getEntity();
            if (responseEntity == null) {
                throw new CernerConnectorException("Failed to retrieve access token : No entity received");
            }
            int responseStatus = response.getStatusLine().getStatusCode();
            String respMessage = EntityUtils.toString(responseEntity);
            if (responseStatus == HttpURLConnection.HTTP_OK) {
                JsonElement jsonElement = parser.parse(respMessage);
                JsonObject jsonObject = jsonElement.getAsJsonObject();
                String accessToken = jsonObject.get("access_token").getAsString();
                long expireIn = jsonObject.get("expires_in").getAsLong();

                Token token = new Token(accessToken, curTimeInMillis, expireIn * 1000);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(token);
                }
                return token;
            } else {
                String message = "Error occurred while retrieving access token. Response: " +
                                                                    "[Status : " + responseStatus + " " +
                                                                    "Message: " + respMessage + "]";
                throw new CernerConnectorException(message);
            }
        } catch (IOException e) {
            throw new CernerConnectorException(e, "Error occurred while retrieving access token");
        }
    }
}
