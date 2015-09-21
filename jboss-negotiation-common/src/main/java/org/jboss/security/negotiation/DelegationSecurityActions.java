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
package org.jboss.security.negotiation;

import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSCredential;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SubjectInfo;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class DelegationSecurityActions {

    static GSSCredential getDelegationCredential() {
        return delegationCredentialAction().getDelegationCredential();
    }

    private static DelegationCredentialAction delegationCredentialAction() {
        return System.getSecurityManager() != null ? DelegationCredentialAction.PRIVILEGED : DelegationCredentialAction.NON_PRIVILEGED;
    }

    private interface DelegationCredentialAction {

        GSSCredential getDelegationCredential();

        static final DelegationCredentialAction NON_PRIVILEGED = new DelegationCredentialAction() {

            @Override
            public GSSCredential getDelegationCredential() {
                SecurityContext securityContext = SecurityContextAssociation.getSecurityContext();
                if (securityContext != null) {
                    SubjectInfo subjectInfo = securityContext.getSubjectInfo();
                    if (subjectInfo != null) {
                        Subject subject = subjectInfo.getAuthenticatedSubject();
                        if (subject != null) {
                            for (Object current : subject.getPrivateCredentials()) {
                                if (current instanceof GSSCredential) {
                                    return (GSSCredential) current;
                                }
                            }
                        }
                    }
                }
                return null;
            }
        };

        static final DelegationCredentialAction PRIVILEGED = new DelegationCredentialAction() {

            final PrivilegedAction<GSSCredential> ACTION = NON_PRIVILEGED::getDelegationCredential;

            @Override
            public GSSCredential getDelegationCredential() {
                return AccessController.doPrivileged(ACTION);
            }
        };
    }

}
