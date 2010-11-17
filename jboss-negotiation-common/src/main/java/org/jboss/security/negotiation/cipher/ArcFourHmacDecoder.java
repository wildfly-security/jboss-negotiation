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

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.security.negotiation.NegotiationException;

/**
 * A {@link Decoder} for ArcFourHmac.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class ArcFourHmacDecoder extends Decoder
{

   private static final int hashSize = 16;

   public int blockSize()
   {
      return 1;
   }

   public int checksumSize()
   {
      return 16;
   }

   public int confounderSize()
   {
      return 8;
   }

   public int keySize()
   {
      return 16;
   }

   public byte[] decrypt(byte[] cipher, byte[] key, int usage) throws NegotiationException
   {
      byte[] ivec = new byte[blockSize()];
      return decrypt(cipher, key, ivec, usage);
   }

   public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage) throws NegotiationException
   {
      try
      {
         return decrypt(key, usage, ivec, cipher, 0, cipher.length);
      }
      catch (GeneralSecurityException e)
      {
         NegotiationException ne = new NegotiationException(e.getMessage());
         ne.initCause(e);
         throw ne;
      }
   }

   private byte[] decrypt(byte[] baseKey, int usage, byte[] ivec, byte[] ciphertext, int start, int len)
         throws GeneralSecurityException
   {
      // compute K1
      byte[] k1 = new byte[baseKey.length];
      System.arraycopy(baseKey, 0, k1, 0, baseKey.length);

      // get the salt using key usage
      byte[] salt = getSalt(usage);

      // compute K2 using K1
      byte[] k2 = getHmac(k1, salt);

      // compute K3 using K2 and checksum
      byte[] checksum = new byte[hashSize];
      System.arraycopy(ciphertext, start, checksum, 0, hashSize);
      byte[] k3 = getHmac(k2, checksum);

      // Decrypt [confounder | plaintext ] (without checksum)
      Cipher cipher = Cipher.getInstance("ARCFOUR");
      SecretKeySpec secretKey = new SecretKeySpec(k3, "ARCFOUR");
      cipher.init(Cipher.DECRYPT_MODE, secretKey);
      byte[] plaintext = cipher.doFinal(ciphertext, start + hashSize, len - hashSize);

      // Verify checksum
      byte[] calculatedHmac = getHmac(k2, plaintext);
      boolean cksumFailed = false;
      if (calculatedHmac.length >= hashSize)
      {
         for (int i = 0; i < hashSize; i++)
         {
            if (calculatedHmac[i] != ciphertext[i])
            {
               cksumFailed = true;
               System.err.println("Checksum failed !");
               break;
            }
         }
      }
      if (cksumFailed)
      {
         throw new GeneralSecurityException("Checksum failed");
      }

      // Get rid of confounder
      // [ confounder | plaintext ]
      byte[] output = new byte[plaintext.length - confounderSize()];
      System.arraycopy(plaintext, confounderSize(), output, 0, output.length);

      return output;
   }

   protected byte[] getHmac(byte[] key, byte[] msg) throws GeneralSecurityException
   {
      SecretKey keyKi = new SecretKeySpec(key, "HmacMD5");
      Mac m = Mac.getInstance("HmacMD5");
      m.init(keyKi);

      // generate hash
      byte[] hash = m.doFinal(msg);
      return hash;
   }

   private byte[] getSalt(int usage)
   {
      int ms_usage = arcfour_translate_usage(usage);
      byte[] salt = new byte[4];
      salt[0] = (byte) (ms_usage & 0xff);
      salt[1] = (byte) ((ms_usage >> 8) & 0xff);
      salt[2] = (byte) ((ms_usage >> 16) & 0xff);
      salt[3] = (byte) ((ms_usage >> 24) & 0xff);
      return salt;
   }

   private int arcfour_translate_usage(int usage)
   {
      switch (usage)
      {
         case 3 :
            return 8;
         case 9 :
            return 8;
         case 23 :
            return 13;
         default :
            return usage;
      }
   }

   public byte[] decryptedData(byte[] data)
   {
      return data;
   }
}
