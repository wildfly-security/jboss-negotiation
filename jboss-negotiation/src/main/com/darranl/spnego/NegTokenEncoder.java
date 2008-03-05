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

/**
 * Neg Token Encoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenEncoder
{

   private static int bitsRequired(int x)
   {
      return (int) (Math.log(x) / Math.log(2)) + 1;
   }

   public static byte[] createTypeLength(final byte type, final int length)
   {
      byte[] token;

      int bitsRequired = bitsRequired(length);

      if (bitsRequired <= 7)
      {
         token = new byte[2];
         token[1] = (byte) length;
      }
      else
      {
         int bytesRequired = bitsRequired / 8;
         if (bitsRequired % 8 != 0)
         {
            bytesRequired++;
         }

         token = new byte[bytesRequired + 2];

         token[1] = (byte) (bytesRequired | 0x80);

         int lengthLeft = length;

         for (int i = 0; i < bytesRequired; i++)
         {
            int pos = bytesRequired - i - 1;
            if (pos == 0)
            {
               token[i + 2] = (byte) lengthLeft;
            }
            else
            {
               int pow = pos * 8;
               int multiplier = (int) Math.pow(2, pow);
               int byteValue = lengthLeft / multiplier;

               token[i + 2] = (byte) byteValue;

               lengthLeft -= byteValue * multiplier;
            }

         }
      }

      token[0] = type;

      return token;
   }
}
