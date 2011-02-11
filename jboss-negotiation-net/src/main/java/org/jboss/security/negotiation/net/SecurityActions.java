/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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
package org.jboss.security.negotiation.net;

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;

/**
 * PrivilegedActions for this package.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
class SecurityActions
{

   static SecurityContext createSecurityContext(final Principal p, final Object cred, final Subject s,
         final String domainName) throws PrivilegedActionException
   {
      return AccessController.doPrivileged(new PrivilegedExceptionAction<SecurityContext>()
      {
         public SecurityContext run() throws Exception
         {
            return SecurityContextFactory.createSecurityContext(p, cred, s, domainName);
         }
      });
   }

   static void setSecurityContext(final SecurityContext sc)
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      {
         public Object run()
         {
            SecurityContextAssociation.setSecurityContext(sc);
            return null;
         }
      });
   }

   static SecurityContext getSecurityContext()
   {
      return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>()
      {
         public SecurityContext run()
         {
            return SecurityContextAssociation.getSecurityContext();
         }
      });
   }
   
   static String getClientSecurityDomain()
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      {
         public String run()
         {
            return (String) System.getProperty("org.jboss.security.negotiation.default.client.security.domain", "com.sun.security.jgss.krb5.initiate");
         }
      });
   }
   
   static String getServerName()
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      {
         public String run()
         {
            return (String) System.getProperty("org.jboss.security.negotiation.server.principal");
         }
      });
   }
   
}
