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

import junit.framework.TestCase;

/**
 * Test case to test the NegTokenInitDecoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenInitDecoderTest extends TestCase
{

   /**
    * Test that the readLength method can correctly read 
    * and decode the length.
    *
    */
   public void testReadLength() throws Exception
   {
      byte[] b1 = new byte[]
      {0x01};
      assertEquals(1, NegTokenDecoder.readLength(new ByteArrayInputStream(b1)));

      byte[] b2 = new byte[]
      {0x40};
      assertEquals(64, NegTokenDecoder.readLength(new ByteArrayInputStream(b2)));

      byte[] b3 = new byte[]
      {0x7F};
      assertEquals(127, NegTokenDecoder.readLength(new ByteArrayInputStream(b3)));

      byte[] b4 = new byte[]
      {(byte) 0x81, (byte) 0xFF};
      assertEquals(255, NegTokenDecoder.readLength(new ByteArrayInputStream(b4)));

      byte[] b5 = new byte[]
      {(byte) 0x82, 0x01, 0x00};
      assertEquals(256, NegTokenDecoder.readLength(new ByteArrayInputStream(b5)));

      byte[] b6 = new byte[]
      {(byte) 0x82, (byte) 0x80, 0x00};
      assertEquals(32768, NegTokenDecoder.readLength(new ByteArrayInputStream(b6)));

      byte[] b7 = new byte[]
      {(byte) 0x82, (byte) 0xFF, 0x00};
      assertEquals(65280, NegTokenDecoder.readLength(new ByteArrayInputStream(b7)));

      byte[] b8 = new byte[]
      {(byte) 0x82, (byte) 0xFF, (byte) 0xFF};
      assertEquals(65535, NegTokenDecoder.readLength(new ByteArrayInputStream(b8)));

      byte[] b9 = new byte[]
      {(byte) 0x83, 0x01, 0x00, 0x00};
      assertEquals(65536, NegTokenDecoder.readLength(new ByteArrayInputStream(b9)));

      byte[] b10 = new byte[]
      {(byte) 0x83, (byte) 0x80, 0x7F, (byte) 0xFF};
      assertEquals(8421375, NegTokenDecoder.readLength(new ByteArrayInputStream(b10)));

      byte[] b11 = new byte[]
      {(byte) 0x83, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
      assertEquals(16777215, NegTokenDecoder.readLength(new ByteArrayInputStream(b11)));

   }
}
