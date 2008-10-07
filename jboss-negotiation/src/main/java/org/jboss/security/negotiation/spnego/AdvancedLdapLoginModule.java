/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.negotiation.spnego;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

/**
 * This login module has now been moved to the 'org.jboss.security.negotiation' package, 
 * this class remains for backwards compatibility. 
 *
 * 
 * @author darran.lofthouse@jboss.com
 * @since 3rd July 2008
 */
@Deprecated
public class AdvancedLdapLoginModule extends org.jboss.security.negotiation.AdvancedLdapLoginModule
{

   private static boolean warned = false;

   @Override
   public void initialize(Subject subject, CallbackHandler handler, Map sharedState, Map options)
   {
      super.initialize(subject, handler, sharedState, options);

      if (warned == false)
      {
         warned = true;
         String thisClass = this.getClass().getName();
         String superClass = org.jboss.security.negotiation.AdvancedLdapLoginModule.class.getName();
         log.warn("'" + thisClass + "' is deprecated, use '" + superClass + "' instead.");
      }
   }

}
