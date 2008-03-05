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

package com.darranl.spnego;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * NegTokenInit Decoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenInitDecoder extends NegTokenDecoder
{

   protected static void decodeRequestFlags(final InputStream is, final NegTokenInit negTokenInit) throws IOException
   {
      int length = NegTokenDecoder.readLength(is);
      byte[] reqFlags = new byte[length];
      is.read(reqFlags);

      negTokenInit.setReqFlags(reqFlags);
   }

   protected static void decodeMechTypes(final InputStream is, final NegTokenInit negTokenInit) throws IOException,
         GSSException
   {
      int length = NegTokenDecoder.readLength(is);
      byte sequenceType = (byte) is.read();
      int sequenceLength = NegTokenDecoder.readLength(is);

      int leftAfter = is.available() - sequenceLength;

      while (is.available() > leftAfter)
      {
         negTokenInit.addMechType(new Oid(is));
      }
   }

   protected static void decodeMechToken(final InputStream is, final NegTokenInit negTokenInit) throws IOException
   {
      int length = NegTokenDecoder.readLength(is);

      byte type = (byte) is.read();
      int tokenLength = readLength(is);

      byte[] mechToken = new byte[tokenLength];
      is.read(mechToken);

      negTokenInit.setMechToken(mechToken);
   }

   protected static void decodeMechListMIC(final InputStream is, final NegTokenInit negTokenInit) throws IOException
   {
      int length = NegTokenDecoder.readLength(is);
      byte[] mechListMIC = new byte[length];
      is.read(mechListMIC);

      negTokenInit.setMechListMIC(mechListMIC);
   }

   protected static void decodeNegTokenInitSequence(final InputStream is, final NegTokenInit negTokenInit)
         throws IOException, GSSException
   {
      byte type = (byte) is.read();
      int sequenceLength = NegTokenDecoder.readLength(is);

      int leftAfter = is.available() - sequenceLength;

      while (is.available() > leftAfter)
      {
         byte sequenceType = (byte) is.read();

         switch (sequenceType)
         {
            case (byte) 0xa0 :
               decodeMechTypes(is, negTokenInit);
               break;
            case (byte) 0xa1 :
               decodeRequestFlags(is, negTokenInit);
               break;
            case (byte) 0xa2 :
               decodeMechToken(is, negTokenInit);
               break;
            case (byte) 0xa3 :
               decodeMechListMIC(is, negTokenInit);
               break;
            default :
               throw new IOException("Unexpected message type");
         }
      }

   }

   /**
    *  Decode the SPNEGO message contained witin the byte[] and return a
    *  NegTokenInit object.
    * 
    * @param token - The SPNEGO message contained 
    * with a byte[]
    * @return The decoded NegTokenInit
    * @throws IOException 
    * @throws GSSException 
    */
   public static NegTokenInit decode(final byte[] token) throws IOException, GSSException
   {
      NegTokenInit negTokenInit = new NegTokenInit();
      ByteArrayInputStream bais = new ByteArrayInputStream(token);
      byte firstByte = (byte) bais.read();

      int totalLength = NegTokenDecoder.readLength(bais);

      negTokenInit.setMessageOid(new Oid(bais));

      int tokenType = bais.read();
      int remainingLength = NegTokenDecoder.readLength(bais);

      decodeNegTokenInitSequence(bais, negTokenInit);

      return negTokenInit;
   }
}
