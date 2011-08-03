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

import org.picketbox.commons.cipher.Base64;

import junit.framework.TestCase;

/**
 * Test case to test the NegotiationMessageDecoder
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiationMessageDecoderTest extends TestCase
{

   /**
    * Simple test case to test decoding an NTLM message
    * created by Java.
    */
   public void testDecode_JavaClient() throws Exception
   {
      String message = "TlRMTVNTUAABAAAAA7IAAAYABgAoAAAACAAIACAAAABLRVJCRVJPU2RvbWFpbg==";
      byte[] requestMessage = Base64.decode(message);

      NegotiateMessage negMessage = NegotiateMessageDecoder.decode(requestMessage);

      assertEquals("Domain", "domain", negMessage.getDomainName());
      assertEquals("Name", "KERBEROS", negMessage.getWorkstationName());

      System.out.println(negMessage);
   }

   public void testDecode_FirefoxClient() throws Exception
   {
      String message = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=";
      byte[] requestMessage = Base64.decode(message);

      NegotiateMessage negMessage = NegotiateMessageDecoder.decode(requestMessage);

      assertNull("Domain", negMessage.getDomainName());
      assertNull("Name", negMessage.getWorkstationName());

      System.out.println(negMessage);
   }
}
