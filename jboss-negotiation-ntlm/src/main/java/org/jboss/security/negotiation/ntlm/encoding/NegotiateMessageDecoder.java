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

package org.jboss.security.negotiation.ntlm.encoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.jboss.security.negotiation.ntlm.Constants;

/**
 * A Decoder to decode the NegotiateMessage
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiateMessageDecoder
{

   private static void readVerifySignature(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] expected = Constants.SIGNATURE;
      byte[] dataRead = new byte[expected.length];

      is.read(dataRead);
      if (Arrays.equals(expected, dataRead) == false)
      {
         throw new IOException("Invalid signature, expected '" + new String(expected) + "' actual '"
               + new String(dataRead) + "'");
      }
      data.read += dataRead.length;
   }

   private static void readVerifyMessageType(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] expected = Constants.NEGOTIATE_MESSAGE_TYPE;
      byte[] dataRead = new byte[expected.length];

      is.read(dataRead);
      if (Arrays.equals(expected, dataRead) == false)
      {
         throw new IOException("Invalid MessageType, expected '" + new String(expected) + "' actual '"
               + new String(dataRead) + "'");
      }
      data.read += dataRead.length;
   }

   public static NegotiateMessage decode(final byte[] token) throws IOException
   {
      System.out.println("Token - ");
      for (byte current : token)
      {
         if (current == 0)
         {
            continue;
         }
         System.out.print("'" + (char) current + "', ");
      }
      DecoderData data = new DecoderData();
      ByteArrayInputStream bais = new ByteArrayInputStream(token);

      readVerifySignature(bais, data);
      readVerifyMessageType(bais, data);
      NegotiateFlagsDecoder.readNegotiateFlags(bais, data);

      return data.message;
   }
}
