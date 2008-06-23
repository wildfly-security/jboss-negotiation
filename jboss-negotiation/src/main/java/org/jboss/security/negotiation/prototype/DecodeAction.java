/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.auth.spi;

import java.security.PrivilegedExceptionAction;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import javax.management.ObjectName;
import javax.management.MBeanServer;
import javax.management.MBeanServerInvocationHandler;

import org.jboss.security.plugins.JaasSecurityDomainMBean;
import org.jboss.mx.util.MBeanServerLocator;

/**
 * PriviledgedActions used by login modules for decoding passwords
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
class DecodeAction implements PrivilegedExceptionAction
{
   String password;
   ObjectName serviceName;

   DecodeAction(String password, ObjectName serviceName)
   {
      this.password = password;
      this.serviceName = serviceName;
   }

   /**
    * 
    * @return
    * @throws Exception
    */
   public Object run() throws Exception
   {   
       MBeanServer server = MBeanServerLocator.locateJBoss();
       JaasSecurityDomainMBean securityDomain = (JaasSecurityDomainMBean)
          MBeanServerInvocationHandler.newProxyInstance(server, serviceName,
             JaasSecurityDomainMBean.class, false);

      // Invoke the jaasSecurityDomain.decodeb64 op
      byte[] secret = securityDomain.decode64(password);
      // Convert to UTF-8 base char array
      String secretPassword = new String(secret, "UTF-8");
      return secretPassword.toCharArray();
   }
   static char[] decode(String password, ObjectName serviceName)
      throws Exception
   {
      DecodeAction action = new DecodeAction(password, serviceName);
      try
      {
         char[] decode = (char[]) AccessController.doPrivileged(action);
         return decode;
      }
      catch(PrivilegedActionException e)
      {
         throw e.getException();
      }
   }
}
