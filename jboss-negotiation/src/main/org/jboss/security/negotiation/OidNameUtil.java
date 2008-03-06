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

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * Utility to convert Oid to a meaningful name.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class OidNameUtil
{

   private static final Oid KERBEROS_V5;

   private static final Oid KERBEROS_V5_LEGACY;

   private static final Oid NTLM;

   private static final Oid SPNEGO;

   static
   {
      try
      {
         KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
         KERBEROS_V5_LEGACY = new Oid("1.2.840.48018.1.2.2");
         SPNEGO = new Oid("1.3.6.1.5.5.2");
         NTLM = new Oid("1.3.6.1.4.1.311.2.2.10");
      }
      catch (GSSException e)
      {
         throw new RuntimeException("Unable to initialise Oid", e);
      }
   }

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
