/*
 * JBoss, Home of Professional Open Source.
 * 
 * Copyright 2007, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.negotiation;

import static org.jboss.security.negotiation.Constants.KERBEROS_V5;
import static org.jboss.security.negotiation.Constants.KERBEROS_V5_LEGACY;
import static org.jboss.security.negotiation.Constants.NTLM;
import static org.jboss.security.negotiation.Constants.SPNEGO;

import org.ietf.jgss.Oid;

/**
 * Utility to convert Oid to a meaningful name.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class OidNameUtil
{

   /**
    * Return the name of the passed in Oid, if this is not available
    * return the identifier.
    *  
    * @param oid
    * @return
    */
   public static String getName(final Oid oid)
   {      
      if (KERBEROS_V5.equals(oid))
      {
         return "Kerberos V5";
      }
      else if (KERBEROS_V5_LEGACY.equals(oid))
      {
         return "Kerberos V5 Legacy";
      }
      else if (NTLM.equals(oid))
      {
         return "NTLM";
      }
      else if (SPNEGO.equals(oid))
      {
         return "SPNEGO";
      }
      else
      {
         return String.valueOf(oid);
      }
   }
}
