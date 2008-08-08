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

import junit.framework.TestCase;

/**
 * Test case for FieldDecoder.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 8th August 2008
 */
public class FieldDecoderTest extends TestCase
{

   public void testConvertToUnsignedInt() throws Exception
   {
      assertEquals(6, FieldDecoder.convertToUnsignedInt(new byte[]
      {0x06}));

      assertEquals(1542, FieldDecoder.convertToUnsignedInt(new byte[]
      {0x06, 0x06}));

      assertEquals(128, FieldDecoder.convertToUnsignedInt(new byte[]
      {(byte) 0x80}));

      assertEquals(129, FieldDecoder.convertToUnsignedInt(new byte[]
      {(byte) 0x81}));

      assertEquals(33153, FieldDecoder.convertToUnsignedInt(new byte[]
      {(byte) 0x81, (byte) 0x81}));
   }
}
