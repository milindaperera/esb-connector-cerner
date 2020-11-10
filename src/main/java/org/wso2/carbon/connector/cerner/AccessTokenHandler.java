/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.connector.cerner;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.wso2.carbon.connector.cerner.security.Token;
import org.wso2.carbon.connector.cerner.security.TokenManager;
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;

/**
 * Class mediator implementation to handle access token
 * This will retrieve token from token store or from the cerner token endpoint based on the configured parameters
 */
public class AccessTokenHandler extends AbstractConnector {

    private static final Log LOG = LogFactory.getLog(AccessTokenHandler.class);

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        String accessToken = (String) messageContext.getProperty(Constants.CERNER_PROPERTY_ACCESS_TOKEN);
        if (StringUtils.isEmpty(accessToken)) {
            // If the access token not available in the message context, retrieve from the connection configuration
            // or from the token endpoint
            accessToken = (String) getParameter(messageContext, Constants.CERNER_ACCESS_TOKEN);
            if (StringUtils.isEmpty(accessToken)) {
                String clientId = (String) getParameter(messageContext, Constants.CERNER_CLIENT_ID);
                String clientSecret = (String) getParameter(messageContext, Constants.CERNER_CLIENT_SECRET);
                String tokenEP = (String) getParameter(messageContext, Constants.CERNER_TOKEN_EP);
                String scopes = (String) getParameter(messageContext, Constants.CERNER_SCOPES);

                if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret) || StringUtils.isEmpty(tokenEP)) {
                    String msg = "\"clientId\", \"clientSecret\", \"tokenEndpoint\" parameters or " +
                                                                        "\"accessToken\" parameter must present";
                    LOG.error(msg);
                    throw new CernerConnectorException(msg);
                }

                Token token = TokenManager.getToken(clientId, tokenEP);
                if (token == null || !token.isActive()) {
                    if (LOG.isDebugEnabled()) {
                        if (token == null) {
                            LOG.debug("Token does not exists in token store");
                        } else {
                            LOG.debug("Access token is inactive");
                        }
                    }
                    if (StringUtils.isEmpty(scopes)) {
                        scopes = Constants.CERNER_DEFAULT_SCOPES;
                    }
                    token = TokenManager.getNewSystemToken(clientId, clientSecret.toCharArray(), scopes, tokenEP);
                }
                accessToken = token.getAccessToken();
            }
            messageContext.setProperty(Constants.CERNER_PROPERTY_ACCESS_TOKEN, accessToken);
        }
    }
}
