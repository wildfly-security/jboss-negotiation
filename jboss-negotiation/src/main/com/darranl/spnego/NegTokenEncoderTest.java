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

import java.util.Arrays;

import junit.framework.TestCase;

/**
 * Test case to test NegTokenEncoder. 
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenEncoderTest extends TestCase
{

   private static void log(final byte[] name)
   {
      String hex = DebugHelper.convertToHex(name);
      System.out.println(hex);
   }

   /**
    *  Test the createTypeLength method correctly 
    *  creates a lengh of one byte using both extremes 
    *  and a value in the middle. 
    */
   public void testCreateTypeLength_OneBye()
   {
      byte[] tl_1 = NegTokenEncoder.createTypeLength((byte) 0x00, 1);
      assertTrue(Arrays.equals(new byte[]
      {0x00, 0x01}, tl_1));
      log(tl_1);

      byte[] tl_2 = NegTokenEncoder.createTypeLength((byte) 0x00, 64);
      assertTrue(Arrays.equals(new byte[]
      {0x00, 0x40}, tl_2));
      log(tl_2);

      byte[] tl_3 = NegTokenEncoder.createTypeLength((byte) 0x00, 127);
      assertTrue(Arrays.equals(new byte[]
      {0x00, 0x7F}, tl_3));
      log(tl_3);

      byte[] tl_4 = NegTokenEncoder.createTypeLength((byte) 0x00, 255);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x81, (byte) 0xFF}, tl_4));
      log(tl_4);
   }

   public void testCreateTypeLength_TwoBytes()
   {
      byte[] tl_1 = NegTokenEncoder.createTypeLength((byte) 0x00, 256);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x82, 0x01, 0x00}, tl_1));
      log(tl_1);

      byte[] tl_2 = NegTokenEncoder.createTypeLength((byte) 0x00, 32768);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x82, (byte) 0x80, 0x00}, tl_2));
      log(tl_2);

      byte[] tl_3 = NegTokenEncoder.createTypeLength((byte) 0x00, 65280);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x82, (byte) 0xFF, 0x00}, tl_3));
      log(tl_3);

      byte[] tl_4 = NegTokenEncoder.createTypeLength((byte) 0x00, 65535);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x82, (byte) 0xFF, (byte) 0xFF}, tl_4));
      log(tl_4);
   }

   public void testCreateTypeLength_ThreeBytes()
   {
      byte[] tl_1 = NegTokenEncoder.createTypeLength((byte) 0x00, 65536);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x83, 0x01, 0x00, 0x00}, tl_1));
      log(tl_1);

      byte[] tl_2 = NegTokenEncoder.createTypeLength((byte) 0x00, 8421375);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x83, (byte) 0x80, 0x7F, (byte) 0xFF}, tl_2));
      log(tl_2);

      byte[] tl_3 = NegTokenEncoder.createTypeLength((byte) 0x00, 16777215);
      assertTrue(Arrays.equals(new byte[]
      {0x00, (byte) 0x83, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, tl_3));
      log(tl_3);
   }
}
