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

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import junit.framework.TestCase;

/**
 * Test case for the NegTokenTargEncoder.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenTargEncoderTest extends TestCase
{

   /**
    * Test a NegTokenTarg response can be constructed to request 
    * an alternate supported mechanism.
    * @throws GSSException 
    * @throws IOException 
    *
    */
   public void testSupportedMech() throws GSSException, IOException
   {
      NegTokenTarg targ = new NegTokenTarg();
      targ.setNegResult(NegTokenTarg.ACCEPT_INCOMPLETE);
      targ.setSupportedMech(new Oid("1.2.840.113554.1.2.2"));

      byte[] response = NegTokenTargEncoder.encode(targ);

      String responseHex = DebugHelper.convertToHex(response);
      System.out.println(responseHex);
   }
}
