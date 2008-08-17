/*
 * Copyright © 2008  Red Hat Middleware, LLC. or third-party contributors as indicated 
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
import java.io.InputStream;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSException;
import org.jboss.security.negotiation.MessageFactory;
import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInitDecoder;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTargDecoder;

/**
 * The message factory for reading SPNEGO messages from InputStreams and
 * creating the Java representation of the message.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
public class SPNEGOMessageFactory extends MessageFactory
{

   private static final Logger log = Logger.getLogger(SPNEGOMessageFactory.class);

   @Override
   public boolean accepts(InputStream in) throws IOException
   {
      if (in.markSupported() == false)
      {
         throw new IllegalArgumentException("The passed in InputStream needs to support mark/reset.");
      }

      in.mark(1);
      int dataRead = in.read();
      in.reset();

      return (dataRead == 0x60) || (dataRead == 0xa1);
   }

   @Override
   public NegotiationMessage createMessage(InputStream in) throws IOException
   {
      if (accepts(in) == true)
      {
         in.mark(1);
         int dataRead = in.read();
         in.reset();

         try
         {
            if (dataRead == 0x60)
            {
               return NegTokenInitDecoder.decode(in);
            }
            // The accepts method will have confirmed it is either 0x60 or 0xa1
            return NegTokenTargDecoder.decode(in);
         }
         catch (GSSException e)
         {
            IOException ioe = new IOException("Unable to createMessage");
            ioe.initCause(e);

            throw ioe;
         }
      }
      else
      {
         throw new IllegalArgumentException("InputStream does not contain SPNEGO message.");
      }
   }

}
