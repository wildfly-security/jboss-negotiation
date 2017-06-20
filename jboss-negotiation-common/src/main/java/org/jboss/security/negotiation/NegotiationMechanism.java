/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.security.negotiation;

import static io.undertow.util.Headers.AUTHORIZATION;
import static io.undertow.util.Headers.NEGOTIATE;
import static io.undertow.util.Headers.WWW_AUTHENTICATE;
import static io.undertow.util.StatusCodes.UNAUTHORIZED;
import io.undertow.security.api.AuthenticatedSessionManager;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.ServerConnection;
import io.undertow.util.AttachmentKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.picketbox.commons.cipher.Base64;

/**
 * An {@link AuthenticationMechanism} implementation to enable JBoss Negotiation based SPNEGO authentication within Undertow.
 *
 * Undertow does contain an authentication mechanism implementation to handle SPNEGO based authentication, however this is based
 * on a different architecture and is not compatible with the JAAS based approach to request validation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class NegotiationMechanism implements AuthenticationMechanism {

    private static final AttachmentKey<NegotiationMessage> MESSAGE_KEY = AttachmentKey.create(NegotiationMessage.class);

    private static final Logger log = Logger.getLogger(NegotiationMechanism.class);

    private static final String NEGOTIATION_PLAIN = NEGOTIATE.toString();
    private static final String NEGOTIATE_PREFIX = NEGOTIATE + " ";

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        log.trace("Authenticating user");

        List<String> authHeaders = exchange.getRequestHeaders().get(AUTHORIZATION);
        if (authHeaders != null) {
            for (String current : authHeaders) {
                if (current.startsWith(NEGOTIATE_PREFIX)) {
                    String authTokenBase64 = current.substring(NEGOTIATE_PREFIX.length());
                    byte[] authToken = Base64.decode(authTokenBase64);
                    ByteArrayInputStream authTokenIS = new ByteArrayInputStream(authToken);
                    MessageTrace.logRequestBase64(authTokenBase64);
                    MessageTrace.logRequestHex(authToken);

                    ServerConnection connection = exchange.getConnection();
                    NegotiationContext negContext = connection.getAttachment(NegotiationContext.ATTACHMENT_KEY);
                    if (negContext == null) {
                        negContext = new NegotiationContext();
                        connection.putAttachment(NegotiationContext.ATTACHMENT_KEY, negContext);
                    }

                    try {
                        MessageFactory mf = MessageFactory.newInstance();
                        if (mf.accepts(authTokenIS) == false) {
                            throw new IOException("Unsupported negotiation mechanism.");
                        }
                        negContext.setRequestMessage(mf.createMessage(authTokenIS));
                    } catch (NegotiationException | IOException e) {
                        log.debug(e);
                        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
                    }

                    Account account = null;
                    AuthenticatedSessionManager sessionManager = (AuthenticatedSessionManager)exchange.getAttachment(AuthenticatedSessionManager.ATTACHMENT_KEY);
                    if (sessionManager != null) {
                        AuthenticatedSessionManager.AuthenticatedSession authSession = sessionManager.lookupSession(exchange);
                        if (authSession != null) {
                            account = authSession.getAccount();
                            if (account != null && account.getPrincipal() != null) {
                                negContext.setUsername(account.getPrincipal().getName());
                            }
                        }
                    }

                    String username = negContext.getUsername();
                    if (username == null || username.length() == 0) {
                        username = UUID.randomUUID().toString();
                        negContext.setUsername(username);
                    }

                    IdentityManager identityManager = getIdentityManager(securityContext);
                    try {
                        negContext.associate();
                        if (account != null) {
                            account = identityManager.verify(account);
                        } else {
                            account = identityManager.verify(username, null);
                        }
                        if (account != null) {
                            securityContext.authenticationComplete(account, "SPNEGO", true);

                            NegotiationMessage responseMessage = negContext.getResponseMessage();
                            if (responseMessage != null) {
                                ByteArrayOutputStream responseMessageOS = new ByteArrayOutputStream();
                                try {
                                    responseMessage.writeTo(responseMessageOS, true);
                                } catch (IOException e) {
                                    // Only using ByteArrayOutputStreams, should not actually hit this.
                                    throw new IllegalStateException(e);
                                }
                                String responseHeader = responseMessageOS.toString();

                                MessageTrace.logResponseBase64(responseHeader);

                                exchange.getResponseHeaders().put(WWW_AUTHENTICATE, NEGOTIATE_PREFIX + responseHeader);
                            }

                            connection.removeAttachment(NegotiationContext.ATTACHMENT_KEY);
                            return AuthenticationMechanismOutcome.AUTHENTICATED;
                        }
                        exchange.putAttachment(MESSAGE_KEY, negContext.getResponseMessage());
                    } finally {
                        negContext.clear();
                    }

                    // By this point we had a header we should have been able to verify but for some reason
                    // it was not correctly structured.
                    return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
                }
            }
        }

        // No suitable header was found so authentication was not even attempted.
        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
    }

    @SuppressWarnings("deprecation")
    private IdentityManager getIdentityManager(SecurityContext securityContext) {
        return securityContext.getIdentityManager();
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        final String header;

        NegotiationMessage responseMessage = exchange.getAttachment(MESSAGE_KEY);
        if (responseMessage != null) {
            ByteArrayOutputStream responseMessageOS = new ByteArrayOutputStream();
            try {
                responseMessage.writeTo(responseMessageOS, true);
            } catch (IOException e) {
                // Only using ByteArrayOutputStreams, should not actually hit this.
                throw new IllegalStateException(e);
            }
            String responseHeader = responseMessageOS.toString();

            MessageTrace.logResponseBase64(responseHeader);

            header = NEGOTIATE_PREFIX + responseHeader;
        } else {
            header = NEGOTIATION_PLAIN;
        }

        exchange.getResponseHeaders().put(WWW_AUTHENTICATE, header);
        // Mechanisms must not set their own status code, however due to UNDERTOW-548 we need to as when paired with
        // FORM auth the ServletFormAuthenticationMechanism gets in there early and sets it to 200.
        exchange.setStatusCode(UNAUTHORIZED);
        return new ChallengeResult(true, UNAUTHORIZED);
    }

}
