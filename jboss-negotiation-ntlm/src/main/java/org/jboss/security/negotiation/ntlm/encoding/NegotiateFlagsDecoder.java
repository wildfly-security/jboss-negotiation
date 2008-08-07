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
 * Decoder to decode the NegotiateFlags field.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
class NegotiateFlagsDecoder
{

   // TODO - Write real decoding once we have a client sending valid flags !!
   static void readNegotiateFlags(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] dataRead = new byte[4];
      NegotiateFlags flags = new NegotiateFlags();
      data.message.setNegotiateFlags(flags);

      System.out.println("\nNegotiateFlags - ");
      for (byte current : dataRead)
      {
         System.out.print("'" + current + "', ");
      }
      System.out.println();
   }

}
