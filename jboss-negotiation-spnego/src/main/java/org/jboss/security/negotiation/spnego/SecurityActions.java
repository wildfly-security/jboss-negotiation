/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015, Red Hat, Inc. and/or its affiliates, and individual contributors
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

package org.jboss.security.negotiation.spnego;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Set;

import javax.security.auth.Subject;

/**
 * Package level security actions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SecurityActions {

    static void addPrivateCredential(final Subject subject, final Object credential) {
        loginModuleActions().addPrivateCredential(subject, credential);
    }

    static void removePrivateCredential(final Subject subject, final Object credential) {
        loginModuleActions().removePrivateCredential(subject, credential);
    }

    private static LoginModuleActions loginModuleActions() {
        return System.getSecurityManager() != null ? LoginModuleActions.PRIVILEGED : LoginModuleActions.NON_PRIVILEGED;
    }

    private interface LoginModuleActions {

        void addPrivateCredential(final Subject subject, final Object credential);

        void removePrivateCredential(final Subject subject, final Object credential);

        static final LoginModuleActions NON_PRIVILEGED = new LoginModuleActions() {

            public void addPrivateCredential(Subject subject, Object credential) {
                Set<Object> privateCredentials = subject.getPrivateCredentials();
                privateCredentials.add(credential);
            }

            public void removePrivateCredential(Subject subject, Object credential) {
                Set<Object> privateCredentials = subject.getPrivateCredentials();
                privateCredentials.remove(credential);
            }
        };

        static final LoginModuleActions PRIVILEGED = new LoginModuleActions() {

            public void addPrivateCredential(final Subject subject, final Object credential) {
                AccessController.doPrivileged(new PrivilegedAction<Void>() {

                    public Void run() {
                        NON_PRIVILEGED.addPrivateCredential(subject, credential);
                        return null;
                    }
                });
            }

            public void removePrivateCredential(final Subject subject, final Object credential) {
                AccessController.doPrivileged(new PrivilegedAction<Void>() {

                    public Void run() {
                        NON_PRIVILEGED.removePrivateCredential(subject, credential);
                        return null;
                    }
                });
            }
        };
    }

}
