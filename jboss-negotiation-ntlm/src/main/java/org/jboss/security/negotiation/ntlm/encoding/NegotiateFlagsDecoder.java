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

   static void readNegotiateFlags(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] dataRead = new byte[4];
      NegotiateFlags flags = new NegotiateFlags();

      is.read(dataRead);

      readAtoG(flags, dataRead[0]);
      readHtoL(flags, dataRead[1]);
      readMtoS(flags, dataRead[2]);
      readTtoX(flags, dataRead[3]);

      data.message.setNegotiateFlags(flags);
      data.read += dataRead.length;
   }

   private static void readAtoG(final NegotiateFlags flags, final byte b)
   {
      flags.setUnicode(((byte) b & 0x01) == 0x01); // 1
      flags.setOem(((byte) b & 0x02) == 0x02); // 2
      flags.setRequestTarget(((byte) b & 0x04) == 0x04); // 4
      flags.setSign(((byte) b & 0x10) == 0x10); // 16
      flags.setSeal(((byte) b & 0x20) == 0x20); // 32
      flags.setDatagram(((byte) b & 0x40) == 0x40); // 64
      flags.setLmKey(((byte) b & 0x80) == 0x80); // 128
   }

   private static void readHtoL(final NegotiateFlags flags, final byte b)
   {
      flags.setNtlm(((byte) b & 0x02) == 0x02); // 2
      flags.setNtOnly(((byte) b & 0x04) == 0x04); // 4
      flags.setOemDomainSupplied(((byte) b & 0x10) == 0x10); // 16
      flags.setOemWorkstationSupplied(((byte) b & 0x20) == 0x20); // 32
      flags.setAlwaysSign(((byte) b & 0x80) == 0x80); // 128      
   }

   private static void readMtoS(final NegotiateFlags flags, final byte b)
   {
      flags.setTargetTypeDomain(((byte) b & 0x01) == 0x01); // 1
      flags.setTargetTypeServer(((byte) b & 0x02) == 0x02); // 2
      flags.setTargetTypeShare(((byte) b & 0x04) == 0x04); // 4
      flags.setNtlm2(((byte) b & 0x08) == 0x08); // 8
      flags.setIdentify(((byte) b & 0x10) == 0x10); // 16    
      flags.setRequestNonNTSessionKey(((byte) b & 0x40) == 0x40); // 64
      flags.setTargetInfo(((byte) b & 0x80) == 0x80); // 128            
   }

   private static void readTtoX(final NegotiateFlags flags, final byte b)
   {
      flags.setNegotiateVersion(((byte) b & 0x02) == 0x02); // 2    
      flags.setSessionKeyExchange128Bit(((byte) b & 0x20) == 0x20); // 32
      flags.setExplicitKeyExchange(((byte) b & 0x40) == 0x40); // 64
      flags.setEncryption56Bit(((byte) b & 0x80) == 0x80); // 128
   }

}
