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
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.jboss.security.negotiation.NegotiationException;

/**
 * Common methods for the Aes*CtsHmacSha1 types.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public abstract class AesCtsHmacSha1Decoder extends Decoder
{

   private static Logger log = Logger.getLogger(AesCtsHmacSha1Decoder.class);

   private static final int BLOCK_SIZE = 16;

   private static final byte[] ZERO_IV = new byte[] {0, 0, 0, 0, 0, 0, 0, 0,
                                                     0, 0, 0, 0, 0, 0, 0, 0};

   private static final int hashSize = 96 / 8;

   public int blockSize()
   {
      return 16;
   }

   public int checksumSize()
   {
      return hashSize;
   }

   public int confounderSize()
   {
      return blockSize();
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

   protected byte[] decrypt(byte[] baseKey, int usage, byte[] ivec, byte[] cipherText, int start, int length)
         throws GeneralSecurityException
   {
      byte[] output = decryptCTS(baseKey, usage, ivec, cipherText, start, length, true);
      return output;
   }

   protected byte[] decryptCTS(byte[] baseKey, int usage, byte[] ivec, byte[] ciphertext, int start, int len,
         boolean confounder_exists) throws GeneralSecurityException
   {
      byte[] Ke = null;
      byte[] Ki = null;

      try
      {
         // Derive encryption key
         byte[] constant = new byte[5];
         constant[0] = (byte) ((usage >> 24) & 0xff);
         constant[1] = (byte) ((usage >> 16) & 0xff);
         constant[2] = (byte) ((usage >> 8) & 0xff);
         constant[3] = (byte) (usage & 0xff);

         constant[4] = (byte) 0xaa;
         Ke = dk(baseKey, constant); // Encryption key

         // Decrypt [confounder | plaintext ] (without checksum)

         // AES in JCE
         Cipher cipher = Cipher.getInstance("AES/CTS/NoPadding");
         SecretKeySpec secretKey = new SecretKeySpec(Ke, "AES");
         IvParameterSpec encIv = new IvParameterSpec(ivec, 0, ivec.length);
         cipher.init(Cipher.DECRYPT_MODE, secretKey, encIv);
         byte[] plaintext = cipher.doFinal(ciphertext, start, len - hashSize);

         // Derive integrity key
         constant[4] = (byte) 0x55;
         Ki = dk(baseKey, constant); // Integrity key

         // Verify checksum
         // H1 = HMAC(Ki, conf | plaintext | pad)
         byte[] calculatedHmac = getHmac(Ki, plaintext);
         int hmacOffset = start + len - hashSize;
         boolean cksumFailed = false;
         if (calculatedHmac.length >= hashSize)
         {
            for (int i = 0; i < hashSize; i++)
            {
               if (calculatedHmac[i] != ciphertext[hmacOffset + i])
               {
                  cksumFailed = true;
                  log.error("Checksum failed !");
                  break;
               }
            }
         }
         if (cksumFailed)
         {
            throw new GeneralSecurityException("Checksum failed");
         }

         if (confounder_exists)
         {
            // Get rid of confounder
            // [ confounder | plaintext ]
            byte[] output = new byte[plaintext.length - BLOCK_SIZE];
            System.arraycopy(plaintext, BLOCK_SIZE, output, 0, output.length);
            return output;
         }
         else
         {
            return plaintext;
         }
      }
      finally
      {
         if (Ke != null)
         {
            Arrays.fill(Ke, 0, Ke.length, (byte) 0);
         }
         if (Ki != null)
         {
            Arrays.fill(Ki, 0, Ki.length, (byte) 0);
         }
      }
   }

   protected byte[] getHmac(byte[] key, byte[] msg) throws GeneralSecurityException
   {
      SecretKey keyKi = new SecretKeySpec(key, "HMAC");
      Mac m = Mac.getInstance("HmacSHA1");
      m.init(keyKi);

      // generate hash
      byte[] hash = m.doFinal(msg);

      // truncate hash
      byte[] output = new byte[hashSize];
      System.arraycopy(hash, 0, output, 0, hashSize);
      return output;
   }

   protected byte[] dk(byte[] key, byte[] constant) throws GeneralSecurityException
   {
      return randomToKey(dr(key, constant));
   }

   protected byte[] randomToKey(byte[] in)
   {
      // simple identity operation
      return in;
   }

   private byte[] dr(byte[] key, byte[] constant) throws GeneralSecurityException
   {
      Cipher encCipher = getCipher(key, null, Cipher.ENCRYPT_MODE);
      int blocksize = encCipher.getBlockSize();

      if (constant.length != blocksize)
      {
         constant = nfold(constant, blocksize * 8);
      }
      byte[] toBeEncrypted = constant;

      int keybytes = (getKeySeedLength() >> 3); // from bits to bytes
      byte[] rawkey = new byte[keybytes];

      /* loop encrypting the blocks until enough key bytes are generated */
      int n = 0, len;
      while (n < keybytes)
      {
         byte[] cipherBlock = encCipher.doFinal(toBeEncrypted);
         len = (keybytes - n <= cipherBlock.length ? (keybytes - n) : cipherBlock.length);
         System.arraycopy(cipherBlock, 0, rawkey, n, len);
         n += len;
         toBeEncrypted = cipherBlock;
      }
      return rawkey;
   }

   protected Cipher getCipher(byte[] key, byte[] ivec, int mode) throws GeneralSecurityException
   {
      // IV
      if (ivec == null)
      {
         ivec = ZERO_IV;
      }
      SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      IvParameterSpec encIv = new IvParameterSpec(ivec, 0, ivec.length);
      cipher.init(mode, secretKey, encIv);
      return cipher;
   }
   
   public byte[] decryptedData(byte[] data)
   {
      return data;
   }

   static byte[] nfold(byte[] in, int outbits)
   {
      int inbits = in.length;
      outbits >>= 3; // count in bytes

      /* first compute lcm(n,k) */
      int a, b, c, lcm;
      a = outbits; // n
      b = inbits; // k

      while (b != 0)
      {
         c = b;
         b = a % b;
         a = c;
      }
      lcm = outbits * inbits / a;

      /* now do the real work */
      byte[] out = new byte[outbits];
      Arrays.fill(out, (byte) 0);

      int thisbyte = 0;
      int msbit, i, bval, oval;

      // this will end up cycling through k lcm(k,n)/k times, which
      // is correct
      for (i = lcm - 1; i >= 0; i--)
      {
         /* compute the msbit in k which gets added into this byte */
         msbit = (/* first, start with msbit in the first, unrotated byte */
         ((inbits << 3) - 1)
         /* then, for each byte, shift to right for each repetition */
         + (((inbits << 3) + 13) * (i / inbits))
         /* last, pick out correct byte within that shifted repetition */
         + ((inbits - (i % inbits)) << 3)) % (inbits << 3);

         /* pull out the byte value itself */
         // Mask off values using &0xff to get only the lower byte
         // Use >>> to avoid sign extension
         bval = ((((in[((inbits - 1) - (msbit >>> 3)) % inbits] & 0xff) << 8) | (in[((inbits) - (msbit >>> 3)) % inbits] & 0xff)) >>> ((msbit & 7) + 1)) & 0xff;
         thisbyte += bval;

         /* do the addition */
         // Mask off values using &0xff to get only the lower byte
         oval = (out[i % outbits] & 0xff);
         thisbyte += oval;
         out[i % outbits] = (byte) (thisbyte & 0xff);

         /* keep around the carry bit, if any */
         thisbyte >>>= 8;
      }

      /* if there's a carry bit left over, add it back in */
      if (thisbyte != 0)
      {
         for (i = outbits - 1; i >= 0; i--)
         {
            /* do the addition */
            thisbyte += (out[i] & 0xff);
            out[i] = (byte) (thisbyte & 0xff);

            /* keep around the carry bit, if any */
            thisbyte >>>= 8;
         }
      }

      return out;
   }

   protected abstract int getKeySeedLength();
}
