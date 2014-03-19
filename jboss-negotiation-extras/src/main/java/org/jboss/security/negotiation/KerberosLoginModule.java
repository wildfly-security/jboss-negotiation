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

/**
 * A Kerberos {@link LoginModule} that wraps the JDK supplied module and has the additional capability of adding a
 * {@link GSSCredential} to the populated {@link Subject}
 * 
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KerberosLoginModule implements LoginModule {

    private static final String ADD_GSS_CREDENTIAL = "addGSSCredential";

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

        KerberosLoginModule.WRAPPED_CLASS = wrappedClass;
    }

    private boolean addGssCredential;
    private LoginModule wrapped;

    private Subject subject;
    private GSSCredential credential;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        wrapped = SecurityActions.newInstance(WRAPPED_CLASS);
        if (wrapped == null) {
            throw new IllegalStateException("Unable to instantiate Krb5LoginModule to wrap!");
        }
        
        Map<String, ?> tweakedOptions = options;
        if (tweakedOptions.containsKey(ADD_GSS_CREDENTIAL)) {
            tweakedOptions = new HashMap<String, Object>(options);
            tweakedOptions.remove(ADD_GSS_CREDENTIAL);
        }
        wrapped.initialize(subject, callbackHandler, sharedState, tweakedOptions);
        
        this.subject = subject;
        addGssCredential = Boolean.parseBoolean((String) options.get(ADD_GSS_CREDENTIAL));
    }

    public boolean login() throws LoginException {
        return wrapped.login();
    }

    public boolean commit() throws LoginException {
        boolean response = wrapped.commit();

        if (response && addGssCredential) {
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
                        GSSName name = manager.createName(principal.getName(), GSSName.NT_USER_NAME, Constants.KERBEROS_V5);

                        return manager.createCredential(name, GSSCredential.DEFAULT_LIFETIME, Constants.KERBEROS_V5,
                                GSSCredential.INITIATE_ONLY);
                    }
                });

                SecurityActions.addPrivateCredential(subject, credential);
                this.credential = credential;
            } catch (PrivilegedActionException e) {
                Exception cause = e.getException();
                if (cause instanceof LoginException) {
                    throw (LoginException) cause;
                } else {
                    throw new LoginException("Unable to create GSSCredential");
                }
            }
        }

        return response;
    }

    public boolean abort() throws LoginException {
        try {
            return wrapped.abort();
        } finally {
            cleanUp();
        }
    }

    public boolean logout() throws LoginException {
        try {

            if (credential != null) {
                SecurityActions.removePrivateCredential(subject, credential);
            }

            return wrapped.abort();
        } finally {
            cleanUp();
        }
    }

    private void cleanUp() {
        wrapped = null;
        subject = null;
        if (credential != null) {
            try {
                credential.dispose();
            } catch (GSSException ignored) {
            }
            credential = null;
        }

    }

}
