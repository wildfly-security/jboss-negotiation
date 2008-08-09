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

package org.jboss.security.negotiation.common;

/**
 * Utility class to assist debugging.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class DebugHelper
{

   private static final char[] HEX_VALUES = new char[]
   {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

   public static String convertToHex(final byte[] message)
   {
      StringBuilder sb = new StringBuilder(message.length * 5);

      for (byte current : message)
      {
         sb.append(" 0x").append(toHex(current));
      }

      return sb.toString();
   }

   private static String toHex(byte b)
   {
      char[] characters = new char[2];
      characters[0] = HEX_VALUES[(b >>> 4) & 0x0F];
      characters[1] = HEX_VALUES[b & 0x0F];
      return new String(characters);
   }

}
