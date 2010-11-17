/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.security.negotiation.cipher;

import org.jboss.security.negotiation.NegotiationException;

/**
 * A decoder for the encrypted part of the Kerberos ticket.
 * We need to decode the ticket to retrieve the client principal.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public abstract class Decoder
{
   
   /**
    * Factory method to create the correct implementation.
    * 
    * @param type Encryption type
    * @return concrete implementation
    * @throws NegotiationException
    */
   public static Decoder getInstace(int type) throws NegotiationException
   {
      Decoder decoder = null;
      switch (type)
      {
         case 1:
            decoder = new DesCbcCrcDecoder();
            break;
         case 3:
            decoder = new DesCbcMd5Decoder();
            break;
         case 16:
            decoder = new Des3CbcHmacSha1KdDecoder();
            break;
         case 17:
            decoder = new Aes128CtsHmacSha1Decoder();
            break;
         case 18:
            decoder = new Aes256CtsHmacSha1Decoder();
            break;
         case 23:
            decoder = new ArcFourHmacDecoder();
            break;
         default:
            throw new NegotiationException("Type not supported: " + type);
      }
      return decoder;
   }

   public abstract int keySize();
   
   public abstract int checksumSize();
   
   public abstract int confounderSize();
   
   public abstract int blockSize();
   
   public abstract byte[] decrypt(byte[] cipher, byte[] key, int usage) throws NegotiationException;
   
   public int startOfChecksum()
   {
      return confounderSize();
   }
   
   public int dataSize(byte[] data)
   {
      return data.length - startOfData();
   }
   
   public int startOfData()
   {
      return confounderSize() + checksumSize();
   }
   
   public byte[] decryptedData(byte[] data)
   {
      int tempSize = dataSize(data);
      byte[] result = new byte[tempSize];
      System.arraycopy(data, startOfData(), result, 0, tempSize);
      return result;
   }
}
