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

import java.util.Map;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;

/**
 * The {@link AuthenticationMechanismFactory} to return the {@link NegotiationMechanism}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class NegotiationMechanismFactory implements AuthenticationMechanismFactory {

    public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory,
            Map<String, String> properties) {
        return new NegotiationMechanism();
    }

}
