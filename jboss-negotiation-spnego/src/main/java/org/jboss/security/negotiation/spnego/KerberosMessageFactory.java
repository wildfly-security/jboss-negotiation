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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.jboss.logging.Logger;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.jboss.security.negotiation.Constants;
import org.jboss.security.negotiation.MessageFactory;
import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInitDecoder;

/**
 * The message factory for reading Kerberos messages from InputStreams and
 * creating the Java representation of the message.
 * 
 * The created messages are only a simple wrapper around the byte[] representation
 * to allow the message to be passed for direct use by the login module
 * 
 * @author darran.lofthouse@jboss.com
 * @since 24th July 2012
 * @version $Revision$
 */
public class KerberosMessageFactory extends MessageFactory
{

   private static final Logger log = Logger.getLogger(KerberosMessageFactory.class);

   @Override
   public boolean accepts(InputStream in) throws IOException
   {
      if (in.markSupported() == false)
      {
         throw new IllegalArgumentException("The passed in InputStream needs to support mark/reset.");
      }

      in.mark(1);
      try
      {
         int dataRead = in.read();
         if (dataRead == 0x60)
         {
            int length = NegTokenInitDecoder.readLength(in);
            Oid messageId = new Oid(in);

            return Constants.KERBEROS_V5.equals(messageId);
         }

         return false;

      }
      catch (GSSException e)
      {
         log.debug("Error determining message Oid", e);
         return false;
      }
      finally
      {
         in.reset();
      }
   }

   @Override
   public NegotiationMessage createMessage(InputStream in) throws IOException
   {
      if (accepts(in) == true)
      {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         byte[] temp = new byte[256];
         int count = -1;
         while ((count = in.read(temp)) > -1)
         {
            baos.write(temp, 0, count);
         }

         return new KerberosMessage(Constants.KERBEROS_V5, baos.toByteArray());
      }
      else
      {
         throw new IllegalArgumentException("InputStream does not contain Kerberos message.");
      }
   }

}
