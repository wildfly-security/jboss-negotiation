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

import java.io.IOException;
import java.io.InputStream;

/**
 * A Decoder to decode field lengths.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 8th August 2008
 */
public class FieldDecoder
{
   public static final byte MSB_MASK = (byte) 0x80;

   static NTLMField readFieldLengths(final InputStream is, final DecoderData data) throws IOException
   {
      NTLMField field = new NTLMField();

      byte[] len = new byte[2];
      byte[] maxLen = new byte[2];
      byte[] offset = new byte[4];

      is.read(len);
      is.read(maxLen);
      is.read(offset);

      data.read += 8;

      field.setLength(convertToUnsignedInt(len));
      field.setMaxLength(convertToUnsignedInt(maxLen));
      field.setOffset(convertToUnsignedInt(offset));

      return field;
   }

   static int convertToUnsignedInt(final byte[] bytes)
   {
      int total = 0;

      for (int i = 0; i < bytes.length; i++)
      {
         byte current = bytes[i];
         boolean msbSet = ((byte) (current & MSB_MASK)) == MSB_MASK;

         int value = current & 127;

         if (msbSet)
         {
            value += 128;
         }

         if (i > 0)
         {
            value = value * (int) (Math.pow(2, 8 * i));
         }

         total += value;
      }

      return total;
   }

}
