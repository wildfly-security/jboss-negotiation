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

import java.lang.reflect.Method;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.jboss.logging.Logger;

/**
 * Utility class for converting a {@link GSSCredential} to a {@link Subject}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class GSSUtil {

    private static final Logger log = Logger.getLogger(GSSUtil.class);

    private static final Method CREATE_SUBJECT_METHOD = SecurityActions.getCreateSubjectMethod();

    /**
     * Populate the supplied {@link Subject} based on the supplied {@link GSSCredential}
     *
     * @param subject - The Subject to populate.
     * @param delegatedCredential - The GSSCredential to use for population.
     * @param privateCredential The optional {@link GSSCredential} to add to the private credentials of the {@link Subject}.
     * @return A {@link Subject} that was created from the GSSCredential so that we can identify the content to remove later.
     */
    static Subject populateSubject(Subject subject, GSSCredential delegatedCredential, GSSCredential privateCredential) throws LoginException {
        Subject intermediateSubject = null;
        if (CREATE_SUBJECT_METHOD != null) {
            try {
                GSSName name = delegatedCredential.getName(Constants.KERBEROS_V5);
                intermediateSubject = SecurityActions.invokeCreateSubject(CREATE_SUBJECT_METHOD, name, delegatedCredential);
                log.trace("Delegated credential converted to Subject.");
                SecurityActions.copySubjectContents(intermediateSubject, subject);
                log.trace("Copied conents of temporary Subject to Subject from the LoginContext");
            } catch (GSSException e) {
                log.debug(e);
                throw new LoginException("Unable to use supplied GSSCredential to populate Subject.");
            }
        } else if (privateCredential == null) {
            throw new LoginException(
                    "Utility not available to convert from GSSCredential and adding GSSCredential to Subject disabled - this would just result in an empty Subject!");
        }
        if (privateCredential != null) {
            log.trace("Also add the GSSCredential to the Subject");
            SecurityActions.addPrivateCredential(subject, privateCredential);
        }

        return intermediateSubject;
    }

    static void clearSubject(final Subject subject, final Subject intermediateSubject, final GSSCredential credential) {
        log.trace("Remove the GSSCredential from the Subject");
        SecurityActions.removePrivateCredential(subject, credential);
        log.trace("Subtract the remaining principals and credentials we added to the Subject");
        SecurityActions.removeSubjectContents(intermediateSubject, subject);
    }

}
