/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014, Red Hat, Inc. and/or its affiliates, and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.security.negotiation;

import org.jboss.logging.Logger;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

/**
 * A Kerberos {@link LoginModule} that wraps the JDK supplied module and has the additional capability of adding a
 * {@link GSSCredential} to the populated {@link Subject}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KerberosLoginModule implements LoginModule {

    private static final Logger log = Logger.getLogger(KerberosLoginModule.class);

    /**
     * Module option to configure how this {@link LoginModule} handles delegation credentials.
     *
     *  IGNORE - (Default) Do not use the delegation credential, just perform normal Kerberos authentication.
     *  USE - If a {@link GSSCredential} is available use it to populate the Subject, if it is not available
     *        fall back to standard Kerberos authentication.
     *  REQUIRE - Require that a {@link GSSCredential} is available and use it to populate the Subject, if it is
     *            not available then fail authentication.
     */
    public static final String DELEGATION_CREDENTIAL = "delegationCredential";

    /**
     * Module option to enable adding a {@link GSSCredential} to the private credentials of the populated {@link Subject}.
     *
     * Defaults to false.
     */
    public static final String ADD_GSS_CREDENTIAL = "addGSSCredential";

    /**
     * The lifetime in seconds of the {@link GSSCredential}, a negative value will set this to GSSCredential.INDEFINITE_LIFETIME.
     *
     * Defaults to GSSCredential.DEFAULT_LIFETIME
     */
    public static final String CREDENTIAL_LIFETIME = "credentialLifetime";

    private static final String SUN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String IBM_MODULE = "com.ibm.security.auth.module.Krb5LoginModule";

    private static Class<LoginModule> WRAPPED_CLASS;

    static {
        Class<LoginModule> wrappedClass = SecurityActions.loadLoginModuleClass(SUN_MODULE);
        if (wrappedClass == null) {
            wrappedClass = SecurityActions.loadLoginModuleClass(IBM_MODULE);
        }
        if (wrappedClass == null) {
            throw new IllegalStateException("Unable to locate any Krb5LoginModule");
        }

        if (log.isTraceEnabled()) {
            log.tracef("Wrapped Krb5LoginModule is '%s'", wrappedClass.getName());
        }

        KerberosLoginModule.WRAPPED_CLASS = wrappedClass;
    }

    private DelegationCredential delegationCredential = DelegationCredential.IGNORE;
    private boolean addGssCredential;
    private int credentialLifetime = GSSCredential.DEFAULT_LIFETIME;
    private LoginModule wrapped;

    private Subject subject;
    private GSSCredential credential;
    private boolean usingWrappedLoginModule;
    private Subject intermediateSubject;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        if (options.containsKey(DELEGATION_CREDENTIAL)) {
            delegationCredential = DelegationCredential.valueOf((String)options.get(DELEGATION_CREDENTIAL));
        }
        log.tracef("delegationCredential=%s", delegationCredential);

        if (delegationCredential != DelegationCredential.REQUIRE) {
            /*
             * If the setting is REQUIRE we would never have a need to call the wrapped module.
             */
            wrapped = SecurityActions.newInstance(WRAPPED_CLASS);
            if (wrapped == null) {
                throw new IllegalStateException("Unable to instantiate Krb5LoginModule to wrap!");
            }

            Map<String, ?> tweakedOptions = new HashMap<String, Object>(options);
            tweakedOptions.remove(ADD_GSS_CREDENTIAL);
            tweakedOptions.remove(CREDENTIAL_LIFETIME);
            tweakedOptions.remove(DELEGATION_CREDENTIAL);

            wrapped.initialize(subject, callbackHandler, sharedState, tweakedOptions);
            log.trace("Initialised wrapped login module.");
        } else {
            log.trace("Skipping wrapped login module initialisation.");
        }

        this.subject = subject;
        addGssCredential = Boolean.parseBoolean((String) options.get(ADD_GSS_CREDENTIAL));
        log.tracef("addGssCredential=%b", addGssCredential);
        if (options.containsKey(CREDENTIAL_LIFETIME)) {
            if (addGssCredential == false) {
                throw new IllegalStateException(String.format("Option '%s' has been specified within enabling '%s'",
                        CREDENTIAL_LIFETIME, ADD_GSS_CREDENTIAL));
            }
            credentialLifetime = Integer.parseInt((String) options.get(CREDENTIAL_LIFETIME));
            if (credentialLifetime < 0) {
                credentialLifetime = GSSCredential.INDEFINITE_LIFETIME;
            }
            log.tracef("credentialLifetime=%d", credentialLifetime);
        }
    }

    public boolean login() throws LoginException {
        switch (delegationCredential) {
            case REQUIRE:
                credential = DelegationCredentialContext.getDelegCredential();
                if (credential == null) {
                    throw new LoginException("Module configured to use delegated credential but no delegated credential available.");
                }
                log.trace("We have a delegation credential, login() is a success.");

                usingWrappedLoginModule = false;
                return true;
            case USE:
                credential = DelegationCredentialContext.getDelegCredential();
                if (credential != null) {
                    log.trace("We have a delegation credential, login() is a success.");
                    usingWrappedLoginModule = false;
                    return true;
                }
                log.trace("No delegation credential so falling through to use wrapped login module.");
                // If we did not have a credential fall through to the default approach.
            default:
                usingWrappedLoginModule = true;
                return wrapped.login();

        }
    }

    public boolean commit() throws LoginException {
        final boolean response;

        if (usingWrappedLoginModule) {
            response = wrapped.commit();
            log.tracef("Called wrapped login module respone=%b", response);

            if (response && addGssCredential) {
                log.trace("Adding GSSCredential to populated Subject");
                final GSSManager manager = GSSManager.getInstance();
                try {
                    GSSCredential credential = Subject.doAs(subject, new PrivilegedExceptionAction<GSSCredential>() {

                        public GSSCredential run() throws Exception {
                            Set<KerberosPrincipal> principals = subject.getPrincipals(KerberosPrincipal.class);
                            if (principals.size() < 1) {
                                throw new LoginException("No KerberosPrincipal Found");
                            } else if (principals.size() > 1) {
                                throw new LoginException("Too Many KerberosPrincipals Found");
                            }
                            KerberosPrincipal principal = principals.iterator().next();
                            log.tracef("Creating GSSName for Principal '%s'" , principal);
                            GSSName name = manager.createName(principal.getName(), GSSName.NT_USER_NAME, Constants.KERBEROS_V5);

                            return manager.createCredential(name, credentialLifetime, Constants.KERBEROS_V5,
                                    GSSCredential.INITIATE_ONLY);
                        }
                    });

                    SecurityActions.addPrivateCredential(subject, credential);
                    log.trace("Added private credential.");
                    this.credential = credential;
                } catch (PrivilegedActionException e) {
                    Exception cause = e.getException();
                    if (cause instanceof LoginException) {
                        throw (LoginException) cause;
                    } else {
                        log.debug(e);
                        throw new LoginException("Unable to create GSSCredential");
                    }
                }
            }
        } else {
            log.trace("Jumping straight to mapping of delegation credential.");
            intermediateSubject = GSSUtil.populateSubject(subject, addGssCredential, credential);

            response = true;
        }

        return response;
    }

    public boolean abort() throws LoginException {
        try {
            if (usingWrappedLoginModule) {
                log.trace("Calling wrapped login module to abort.");
                return wrapped.abort();
            }
            log.trace("No wrapped module call to abort.");
            return true;
        } finally {
            cleanUp();
        }
    }

    public boolean logout() throws LoginException {
        try {
            if (usingWrappedLoginModule) {
                if (credential != null) {
                    log.trace("Remocing GSSCredential added to subject during authentication.");
                    SecurityActions.removePrivateCredential(subject, credential);
                }

                log.trace("Passing to wrapped login module to logout.");
                return wrapped.logout();
            } else {
                log.trace("Removing credentials from Subject poplulated from delegation credential.");
                GSSUtil.clearSubject(subject, intermediateSubject, credential);

                return true;
            }
        } finally {
            cleanUp();
        }
    }

    private void cleanUp() {
        wrapped = null;
        subject = null;
        if (credential != null && usingWrappedLoginModule) {
            // Don't want to dispose of it if it was delegated to us as there could be subsequent use for it.
            try {
                log.trace("Disposing of GSSCredential");
                credential.dispose();
            } catch (GSSException ignored) {
            }
        }
        credential = null;
    }

    private enum DelegationCredential {
        IGNORE, REQUIRE, USE;
    }

}
