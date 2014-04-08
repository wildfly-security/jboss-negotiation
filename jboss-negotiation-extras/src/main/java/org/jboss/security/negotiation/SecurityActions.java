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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.spi.LoginModule;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

/**
 * Package level security actions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SecurityActions {

    private static final String SUN_GSSUTIL = "com.sun.security.jgss.GSSUtil";
    private static final String CREATE_SUBJECT = "createSubject";

    static Class<LoginModule> loadLoginModuleClass(final String className) {
        return loginModuleActions().loadLoginModuleClass(className);
    }

    static LoginModule newInstance(final Class<LoginModule> moduleClass) {
        return loginModuleActions().newInstance(moduleClass);
    }

    static void addPrivateCredential(final Subject subject, final Object credential) {
        loginModuleActions().addPrivateCredential(subject, credential);
    }

    static void removePrivateCredential(final Subject subject, final Object credential) {
        loginModuleActions().removePrivateCredential(subject, credential);
    }

    static Method getCreateSubjectMethod() {
        return loginModuleActions().getCreateSubjectMethod();
    }

    static Subject invokeCreateSubject(final Method createSubjectMethod, final GSSName gssName, final GSSCredential gssCredential) throws GSSException {
        return loginModuleActions().invokeCreateSubject(createSubjectMethod, gssName, gssCredential);
    }

    static void copySubjectContents(final Subject from, final Subject to) {
        loginModuleActions().copySubjectContents(from, to);
    }

    static void removeSubjectContents(final Subject toSubtract, final Subject from) {
        loginModuleActions().removeSubjectContents(toSubtract, from);
    }

    private static LoginModuleActions loginModuleActions() {
        return System.getSecurityManager() != null ? LoginModuleActions.PRIVILEGED : LoginModuleActions.NON_PRIVILEGED;
    }

    private interface LoginModuleActions {

        Class<LoginModule> loadLoginModuleClass(final String className);

        LoginModule newInstance(final Class<LoginModule> moduleClass);

        void addPrivateCredential(final Subject subject, final Object credential);

        void removePrivateCredential(final Subject subject, final Object credential);

        Method getCreateSubjectMethod();

        Subject invokeCreateSubject(final Method createSubjectMethod, final GSSName gssName, final GSSCredential gssCredential) throws GSSException;

        void copySubjectContents(final Subject from, final Subject to);

        void removeSubjectContents(final Subject toSubtract, final Subject from);

        static final LoginModuleActions NON_PRIVILEGED = new LoginModuleActions() {

            public Class<LoginModule> loadLoginModuleClass(String className) {
                try {
                    return (Class<LoginModule>) KerberosLoginModule.class.getClassLoader().loadClass(className);
                } catch (ClassNotFoundException e) {
                    return null;
                } catch (ClassCastException e) {
                    return null;
                }
            }

            public LoginModule newInstance(Class<LoginModule> moduleClass) {
                try {
                    return moduleClass.newInstance();
                } catch (InstantiationException e) {
                    return null;
                } catch (IllegalAccessException e) {
                    return null;
                }
            }

            public void addPrivateCredential(Subject subject, Object credential) {
                Set<Object> privateCredentials = subject.getPrivateCredentials();
                privateCredentials.add(credential);
            }

            public void removePrivateCredential(Subject subject, Object credential) {
                Set<Object> privateCredentials = subject.getPrivateCredentials();
                privateCredentials.remove(credential);
            }

            @SuppressWarnings({ "rawtypes", "unchecked" })
            public Method getCreateSubjectMethod() {
                try {
                    Class sunGssUtil = GSSUtil.class.getClassLoader().loadClass(SUN_GSSUTIL);
                    return sunGssUtil.getMethod(CREATE_SUBJECT, GSSName.class, GSSCredential.class);
                } catch (ClassNotFoundException e) {
                    return null;
                } catch (NoSuchMethodException e) {
                    return null;
                } catch (SecurityException e) {
                    return null;
                }

            }

            public Subject invokeCreateSubject(Method createSubjectMethod, GSSName gssName, GSSCredential gssCredential) throws GSSException {

                try {
                    return (Subject)createSubjectMethod.invoke(null, gssName, gssCredential);
                } catch (IllegalAccessException e) {
                    return null;
                } catch (IllegalArgumentException e) {
                    return null;
                } catch (InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof GSSException) {
                        throw (GSSException) cause;
                    }
                    return null;
                }
            }

            public void copySubjectContents(Subject from, Subject to) {
                to.getPrincipals().addAll(from.getPrincipals());
                to.getPublicCredentials().addAll(from.getPublicCredentials());
                to.getPrivateCredentials().addAll(from.getPrivateCredentials());
            }

            public void removeSubjectContents(Subject toSubtract, Subject from) {
                from.getPrincipals().removeAll(toSubtract.getPrincipals());
                from.getPublicCredentials().removeAll(toSubtract.getPublicCredentials());
                from.getPrivateCredentials().removeAll(toSubtract.getPrivateCredentials());
            }
        };

        static final LoginModuleActions PRIVILEGED = new LoginModuleActions() {

            private PrivilegedAction<Method> GET_CREATE_SUBJECT_METHOD_ACTION = new PrivilegedAction<Method>() {

                public Method run() {
                    return NON_PRIVILEGED.getCreateSubjectMethod();
                }
            };

            public Class<LoginModule> loadLoginModuleClass(final String className) {
                return AccessController.doPrivileged(new PrivilegedAction<Class<LoginModule>>() {

                    public Class<LoginModule> run() {
                        return NON_PRIVILEGED.loadLoginModuleClass(className);
                    }
                });
            }

            public LoginModule newInstance(final Class<LoginModule> moduleClass) {
                return AccessController.doPrivileged(new PrivilegedAction<LoginModule>() {

                    public LoginModule run() {
                        return NON_PRIVILEGED.newInstance(moduleClass);
                    }
                });
            }

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

            public Method getCreateSubjectMethod() {
                return AccessController.doPrivileged(GET_CREATE_SUBJECT_METHOD_ACTION);
            }

            public Subject invokeCreateSubject(final Method createSubjectMethod, final GSSName gssName,
                    final GSSCredential gssCredential) throws GSSException {
                try {
                    return AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {

                        public Subject run() throws Exception {
                            return NON_PRIVILEGED.invokeCreateSubject(createSubjectMethod, gssName, gssCredential);
                        }
                    });
                } catch (PrivilegedActionException e) {
                    throw (GSSException) e.getCause();
                }
            }

            public void copySubjectContents(final Subject from, final Subject to) {
                AccessController.doPrivileged(new PrivilegedAction<Void>() {

                    public Void run() {
                        NON_PRIVILEGED.copySubjectContents(from, to);
                        return null;
                    }
                });

            }

            public void removeSubjectContents(final Subject toSubtract, final Subject from) {
                AccessController.doPrivileged(new PrivilegedAction<Void>() {

                    public Void run() {
                        NON_PRIVILEGED.removeSubjectContents(toSubtract, from);
                        return null;
                    }
                });

            }
        };
    }

}
