package org.jboss.security.negotiation;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public class Constants
{
   public static final Oid KERBEROS_V5;

   public static final Oid KERBEROS_V5_LEGACY;

   public static final Oid NTLM;

   public static final Oid SPNEGO;

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
   
}
