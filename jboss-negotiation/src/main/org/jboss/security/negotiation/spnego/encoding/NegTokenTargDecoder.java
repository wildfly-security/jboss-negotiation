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

package org.jboss.security.negotiation.spnego.encoding;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * NegTokenTarg Decoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenTargDecoder extends NegTokenDecoder
{

   private static void decodeNegResult(final InputStream is, final NegTokenTarg negTokenTarg) throws IOException
   {
      int length = readLength(is);
      byte type = (byte) is.read();

      byte negResult = (byte) is.read();

      switch (negResult)
      {
         case 0x00 :
            negTokenTarg.setNegResult(NegTokenTarg.ACCEPT_COMPLETED);
            break;
         case 0x01 :
            negTokenTarg.setNegResult(NegTokenTarg.ACCEPT_INCOMPLETE);
            break;
         case 0x02 :
            negTokenTarg.setNegResult(NegTokenTarg.REJECTED);
            break;
         default :
            throw new IOException("Unexpected negResult");
      }
   }

   private static void decodeSupportedMech(final InputStream is, final NegTokenTarg negTokenTarg) throws IOException,
         GSSException
   {
      int length = readLength(is);

      negTokenTarg.setSupportedMech(new Oid(is));
   }

   private static void decodeResponseToken(final InputStream is, final NegTokenTarg negTokenTarg) throws IOException
   {
      int length = readLength(is);

      byte type = (byte) is.read();
      int tokenLength = readLength(is);

      byte[] responseToken = new byte[tokenLength];
      is.read(responseToken);

      negTokenTarg.setResponseToken(responseToken);
   }

   private static void decodeMechListMIC(final InputStream is, final NegTokenTarg negTokenTarg) throws IOException
   {
      int length = readLength(is);

      byte[] mechListMIC = new byte[length];
      is.read(mechListMIC);

      negTokenTarg.setMechListMIC(mechListMIC);
   }

   private static void decodeNegTokenTargSequence(final InputStream is, final NegTokenTarg negTokenTarg)
         throws IOException, GSSException
   {
      byte type = (byte) is.read();
      int sequenceLength = readLength(is);

      int leftAfter = is.available() - sequenceLength;

      while (is.available() > leftAfter)
      {
         byte sequenceType = (byte) is.read();

         switch (sequenceType)
         {
            case (byte) 0xa0 :
               decodeNegResult(is, negTokenTarg);
               break;
            case (byte) 0xa1 :
               decodeSupportedMech(is, negTokenTarg);
               break;
            case (byte) 0xa2 :
               decodeResponseToken(is, negTokenTarg);
               break;
            case (byte) 0xa3 :
               decodeMechListMIC(is, negTokenTarg);
               break;
            default :
               throw new IOException("Unexpected message type");
         }
      }

   }

   public static NegTokenTarg decode(final byte[] token) throws IOException, GSSException
   {
      NegTokenTarg negTokenTarg = new NegTokenTarg();
      ByteArrayInputStream bais = new ByteArrayInputStream(token);

      byte firstByte = (byte) bais.read();
      int totalLength = readLength(bais);

      decodeNegTokenTargSequence(bais, negTokenTarg);

      return negTokenTarg;
   }
}
