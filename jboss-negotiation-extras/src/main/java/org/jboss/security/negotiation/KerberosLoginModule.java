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
import org.ietf.jgss.Oid;
import org.jboss.logging.Logger;

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
     * Module option to specify if any {@link GSSCredential} being added to the {@link Subject} should be wrapped to prevent disposal.
     *
     * Has no effect if a {@link GSSCredential} is not being added to the {@link Subject}.
     *
     * Defaults to false.
     */
    public static final String WRAP_GSS_CREDENTIAL = "wrapGSSCredential";

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
    private boolean wrapGssCredential;
    private int credentialLifetime = GSSCredential.DEFAULT_LIFETIME;
    private LoginModule wrapped;

    private Subject subject;
    private GSSCredential rawCredential;
    private GSSCredential storedCredential;
    private boolean usingWrappedLoginModule;
    private Subject intermediateSubject;

    @Override
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
            tweakedOptions.remove(WRAP_GSS_CREDENTIAL);
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
        wrapGssCredential = Boolean.parseBoolean((String) options.get(WRAP_GSS_CREDENTIAL));
        log.tracef("wrapGssCredential=%b", wrapGssCredential);
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

    @Override
    public boolean login() throws LoginException {
        switch (delegationCredential) {
            case REQUIRE:
                rawCredential = DelegationCredentialContext.getDelegCredential();
                if (rawCredential == null) {
                    throw new LoginException("Module configured to use delegated credential but no delegated credential available.");
                }
                log.trace("We have a delegation credential, login() is a success.");

                usingWrappedLoginModule = false;
                return true;
            case USE:
                rawCredential = DelegationCredentialContext.getDelegCredential();
                if (rawCredential != null) {
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

    @Override
    public boolean commit() throws LoginException {
        final boolean response;

        if (usingWrappedLoginModule) {
            response = wrapped.commit();
            log.tracef("Called wrapped login module respone=%b", response);

            if (response && addGssCredential) {
                log.trace("Adding GSSCredential to populated Subject");
                final GSSManager manager = GSSManager.getInstance();
                try {
                    final GSSCredential credential = Subject.doAs(subject, new PrivilegedExceptionAction<GSSCredential>() {

                        @Override
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

                    storedCredential = wrapGssCredential ? wrapCredential(credential) : credential;
                    SecurityActions.addPrivateCredential(subject, storedCredential);
                    log.trace("Added private credential.");
                    this.rawCredential = credential;
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
            if (addGssCredential) {
                storedCredential = wrapGssCredential ? wrapCredential(rawCredential) : rawCredential;
            }
            intermediateSubject = GSSUtil.populateSubject(subject, rawCredential, storedCredential);

            response = true;
        }

        return response;
    }

    @Override
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

    @Override
    public boolean logout() throws LoginException {
        try {
            if (usingWrappedLoginModule) {
                if (rawCredential != null) {
                    log.trace("Removing GSSCredential added to subject during authentication.");
                    SecurityActions.removePrivateCredential(subject, storedCredential);
                }

                log.trace("Passing to wrapped login module to logout.");
                return wrapped.logout();
            } else {
                log.trace("Removing credentials from Subject poplulated from delegation credential.");
                GSSUtil.clearSubject(subject, intermediateSubject, storedCredential);

                return true;
            }
        } finally {
            cleanUp();
        }
    }

    private void cleanUp() {
        wrapped = null;
        subject = null;
        if (rawCredential != null && usingWrappedLoginModule) {
            // Don't want to dispose of it if it was delegated to us as there could be subsequent use for it.
            try {
                log.trace("Disposing of GSSCredential");
                rawCredential.dispose();
            } catch (GSSException ignored) {
            }
        }
        rawCredential = null;
    }

    private enum DelegationCredential {
        IGNORE, REQUIRE, USE;
    }

    private static GSSCredential wrapCredential(final GSSCredential credential) {
        return new GSSCredential() {

            @Override
            public int getUsage(Oid mech) throws GSSException {
                return credential.getUsage(mech);
            }

            @Override
            public int getUsage() throws GSSException {
                return credential.getUsage();
            }

            @Override
            public int getRemainingLifetime() throws GSSException {
                return credential.getRemainingLifetime();
            }

            @Override
            public int getRemainingInitLifetime(Oid mech) throws GSSException {
                return credential.getRemainingInitLifetime(mech);
            }

            @Override
            public int getRemainingAcceptLifetime(Oid mech) throws GSSException {
                return credential.getRemainingAcceptLifetime(mech);
            }

            @Override
            public GSSName getName(Oid mech) throws GSSException {
                return credential.getName(mech);
            }

            @Override
            public GSSName getName() throws GSSException {
                return credential.getName();
            }

            @Override
            public Oid[] getMechs() throws GSSException {
                return credential.getMechs();
            }

            @Override
            public void dispose() throws GSSException {
                // Prevent disposal of our credential.
            }

            @Override
            public void add(GSSName name, int initLifetime, int acceptLifetime, Oid mech, int usage) throws GSSException {
                credential.add(name, initLifetime, acceptLifetime, mech, usage);
            }

        };
    }

}
