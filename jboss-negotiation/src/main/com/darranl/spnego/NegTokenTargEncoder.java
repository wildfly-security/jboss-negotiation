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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * NegTokenTarg Encoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenTargEncoder extends NegTokenEncoder
{

   protected static int getTotalLength(final List tokens)
   {
      int length = 0;
      Iterator it = tokens.iterator();
      while (it.hasNext())
      {
         byte[] current = (byte[]) it.next();
         length += current.length;
      }

      return length;
   }

   protected static void encodeNegTokenTarg(final List tokens)
   {
      byte[] constructedSequence = createTypeLength((byte) 0xa1, getTotalLength(tokens));

      tokens.add(0, constructedSequence);
   }

   protected static void encodeConstructedSequence(final List tokens)
   {
      byte[] constructedSequence = createTypeLength((byte) 0x30, getTotalLength(tokens));

      tokens.add(0, constructedSequence);
   }

   protected static void encodeNegResult(final List tokens, final Integer negResult)
   {
      if (negResult == null)
         return;

      byte result;

      if (NegTokenTarg.ACCEPT_COMPLETED.equals(negResult))
      {
         result = 0x00;
      }
      else if (NegTokenTarg.ACCEPT_INCOMPLETE.equals(negResult))
      {
         result = 0x01;
      }
      else
      {
         result = 0x02;
      }

      byte[] negResultToken =
      {(byte) 0xa0, 0x03, 0x0a, 0x01, result};

      tokens.add(0, negResultToken);
   }

   protected static void encodeSupportedMech(final List tokens, final Oid supportedMech) throws GSSException
   {
      if (supportedMech == null)
         return;

      byte[] supportedMechToken = supportedMech.getDER();
      byte[] sequenceLength = createTypeLength((byte) 0xa1, supportedMechToken.length);

      tokens.add(0, supportedMechToken);
      tokens.add(0, sequenceLength);
   }

   protected static void encodeResponseToken(final List tokens, final byte[] responseToken)
   {
      if (responseToken == null || responseToken.length == 0)
         return;

      byte[] octletLength = createTypeLength((byte) 0x04, responseToken.length);
      byte[] sequenceLength = createTypeLength((byte) 0xa2, responseToken.length + octletLength.length);

      tokens.add(0, responseToken);
      tokens.add(0, octletLength);
      tokens.add(0, sequenceLength);
   }

   protected static void encodeMechListMIC(final List tokens, final byte[] mechListMIC)
   {
      if (mechListMIC == null || mechListMIC.length == 0)
         return;

      byte[] octletLength = createTypeLength((byte) 0x04, mechListMIC.length);
      byte[] sequenceLength = createTypeLength((byte) 0xa3, mechListMIC.length + octletLength.length);

      tokens.add(0, mechListMIC);
      tokens.add(0, octletLength);
      tokens.add(0, sequenceLength);
   }

   protected static byte[] contructMessage(final List tokens) throws IOException
   {
      int length = getTotalLength(tokens);

      ByteArrayOutputStream baous = new ByteArrayOutputStream(length);

      Iterator it = tokens.iterator();
      while (it.hasNext())
      {
         baous.write((byte[]) it.next());
      }

      return baous.toByteArray();
   }

   public static byte[] encode(final NegTokenTarg negTokenTarg) throws GSSException, IOException
   {
      List tokens = new LinkedList();

      encodeMechListMIC(tokens, negTokenTarg.getMechListMIC());
      encodeResponseToken(tokens, negTokenTarg.getResponseToken());
      encodeSupportedMech(tokens, negTokenTarg.getSupportedMech());
      encodeNegResult(tokens, negTokenTarg.getNegResult());
      encodeConstructedSequence(tokens);
      encodeNegTokenTarg(tokens);

      return contructMessage(tokens);
   }
}
