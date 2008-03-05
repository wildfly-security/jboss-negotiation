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

import java.io.IOException;
import java.io.InputStream;

/**
 * NegToken Decoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenDecoder
{

   public static int readLength(final InputStream is) throws IOException
   {
      byte first = (byte) is.read();
      byte masked = (byte) (first & (byte) 128);
   
      if (masked == 0)
      {
         return first;
      }
   
      int lengthLength = first & (byte) 127;
   
      byte[] lengthBytes = new byte[lengthLength];
      is.read(lengthBytes);
   
      int length = 0;
      for (int i = 0; i < lengthLength; i++)
      {
         int currentPos = lengthLength - i - 1;
         int currentLength = lengthBytes[currentPos];
   
         if (currentLength < 0)
         {
            currentLength += 256;
         }
   
         if (i > 0)
         {
            currentLength = currentLength * (int) (Math.pow(2, 8 * i));
         }
   
         length += currentLength;
      }
   
      return length;
   }

}
