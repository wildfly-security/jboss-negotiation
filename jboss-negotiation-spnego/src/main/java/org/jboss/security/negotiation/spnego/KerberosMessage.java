/*
 * Copyright © 2012  Red Hat Middleware, LLC. or third-party contributors as indicated 
 * by the @author tags or express copyright attribution statements applied by the 
 * authors. All third-party contributions are distributed under license by Red Hat 
 * Middleware LLC.
 *
 * This copyrighted material is made available to anyone wishing to use, modify, copy, 
 * or redistribute it subject to the terms and conditions of the GNU Lesser General 
 * Public License, v. 2.1. This program is distributed in the hope that it will be 
 * useful, but WITHOUT A WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for 
 * more details. You should have received a copy of the GNU Lesser General Public License, 
 * v.2.1 along with this distribution; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

package org.jboss.security.negotiation.spnego;

import java.io.IOException;
import java.io.OutputStream;

import org.ietf.jgss.Oid;
import org.jboss.security.negotiation.NegotiationMessage;

/**
 * A message implementation to provide a wrapper around plain Kerberos messages.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 24th July 2012
 * @version $Revision$
 */
public class KerberosMessage extends NegotiationMessage
{
   private final Oid messageOid;

   private final byte[] token;

   public KerberosMessage(final Oid messageOid, final byte[] token)
   {
      this.messageOid = messageOid;
      this.token = token;
   }

   public Oid getMessageOid()
   {
      return messageOid;
   }

   public byte[] getToken()
   {
      return token;
   }

   @Override
   public void writeTo(OutputStream os) throws IOException
   {
      os.write(token);
   }

   @Override
   public String getMessageType()
   {
      return "Kerberos";
   }

}
