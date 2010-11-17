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
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.security.negotiation.NegotiationException;

/**
 * A {@link Decoder} for Des3CbcHmacSha1Kd.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class Des3CbcHmacSha1KdDecoder extends Decoder
{

   private static final byte[] ZERO_IV = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};

   private static final byte[] PARITY_BIT_MASK = {(byte)0x80, (byte)0x40, (byte)0x20, (byte)0x10,
                                                  (byte)0x08, (byte)0x04, (byte)0x02};
   
   public int blockSize()
   {
      return 8;
   }

   public int checksumSize()
   {
      return 20;
   }

   public int confounderSize()
   {
      return blockSize();
   }

   public int keySize()
   {
      return 24;
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

         Cipher decCipher = getCipher(Ke, ivec, Cipher.DECRYPT_MODE);
         int blockSize = decCipher.getBlockSize();

         // Decrypt [confounder | plaintext | padding] (without checksum)
         int cksumSize = checksumSize();
         int cipherSize = len - cksumSize;
         byte[] decrypted = decCipher.doFinal(ciphertext, start, cipherSize);

         // decrypted = [confounder | plaintext | padding]

         // Derive integrity key
         constant[4] = (byte) 0x55;
         Ki = dk(baseKey, constant); // Integrity key

         // Verify checksum
         // H1 = HMAC(Ki, conf | plaintext | pad)
         byte[] calculatedHmac = getHmac(Ki, decrypted);

         boolean cksumFailed = false;
         if (calculatedHmac.length >= cksumSize)
         {
            for (int i = 0; i < cksumSize; i++)
            {
               if (calculatedHmac[i] != ciphertext[cipherSize + i])
               {
                  cksumFailed = true;
                  break;
               }
            }
         }

         if (cksumFailed)
         {
            throw new GeneralSecurityException("Checksum failed");
         }

         // Prepare decrypted msg and ivec to be returned
         // Last blockSize bytes of ciphertext without checksum
         if (ivec != null && ivec.length == blockSize)
         {
            System.arraycopy(ciphertext, start + cipherSize - blockSize, ivec, 0, blockSize);
         }

         // Get rid of confounder
         // [plaintext | padding]
         byte[] plaintext = new byte[decrypted.length - blockSize];
         System.arraycopy(decrypted, blockSize, plaintext, 0, plaintext.length);
         return plaintext; // padding still there
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

   protected Cipher getCipher(byte[] key, byte[] ivec, int mode) throws GeneralSecurityException
   {
      // NoSuchAlgorithException
      SecretKeyFactory factory = SecretKeyFactory.getInstance("desede");

      // InvalidKeyException
      KeySpec spec = new DESedeKeySpec(key, 0);

      // InvalidKeySpecException
      SecretKey secretKey = factory.generateSecret(spec);

      // IV
      if (ivec == null)
      {
         ivec = ZERO_IV;
      }

      // NoSuchAlgorithmException, NoSuchPaddingException
      // NoSuchProviderException
      Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
      IvParameterSpec encIv = new IvParameterSpec(ivec, 0, ivec.length);

      // InvalidKeyException, InvalidAlgorithParameterException
      cipher.init(mode, secretKey, encIv);

      return cipher;
   }

   protected byte[] getHmac(byte[] key, byte[] msg) throws GeneralSecurityException
   {
      SecretKey keyKi = new SecretKeySpec(key, "HmacSHA1");
      Mac m = Mac.getInstance("HmacSHA1");
      m.init(keyKi);
      return m.doFinal(msg);
   }

   protected byte[] randomToKey(byte[] in)
   {
      if (in.length != 21)
      {
         throw new IllegalArgumentException("input must be 168 bits");
      }

      byte[] one = keyCorrection(des3Expand(in, 0, 7));
      byte[] two = keyCorrection(des3Expand(in, 7, 14));
      byte[] three = keyCorrection(des3Expand(in, 14, 21));

      byte[] key = new byte[24];
      System.arraycopy(one, 0, key, 0, 8);
      System.arraycopy(two, 0, key, 8, 8);
      System.arraycopy(three, 0, key, 16, 8);

      return key;
   }

   byte[] dk(byte[] key, byte[] constant) throws GeneralSecurityException
   {
      return randomToKey(dr(key, constant));
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

   protected int getKeySeedLength()
   {
      return 168; // bits; 3DES key material has 21 bytes
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

   private static byte[] des3Expand(byte[] input, int start, int end)
   {
      if ((end - start) != 7)
         throw new IllegalArgumentException("Invalid length of DES Key Value:" + start + "," + end);

      byte[] result = new byte[8];
      byte last = 0;
      System.arraycopy(input, start, result, 0, 7);
      byte posn = 0;

      // Fill in last row
      for (int i = start; i < end; i++)
      {
         byte bit = (byte) (input[i] & 0x01);
         ++posn;
         if (bit != 0)
         {
            last |= (bit << posn);
         }
      }

      result[7] = last;
      setParityBit(result);
      return result;
   }

   private static void setParityBit(byte[] key)
   {
      for (int i = 0; i < key.length; i++)
      {
         int bitCount = 0;
         for (int maskIndex = 0; maskIndex < PARITY_BIT_MASK.length; maskIndex++)
         {
            if ((key[i] & PARITY_BIT_MASK[maskIndex]) == PARITY_BIT_MASK[maskIndex])
            {
               bitCount++;
            }
         }
         if ((bitCount & 0x01) == 1)
         {
            // Odd number of 1 bits in the top 7 bits. Set parity bit to 0
            key[i] = (byte) (key[i] & (byte) 0xfe);
         }
         else
         {
            // Even number of 1 bits in the top 7 bits. Set parity bit to 1
            key[i] = (byte) (key[i] | 1);
         }
      }
   }
   
   private static byte[] keyCorrection(byte[] key)
   {
      // check for weak key
      try
      {
         if (DESKeySpec.isWeak(key, 0))
         {
            key[7] = (byte)(key[7] ^ 0xF0);
         }
      }
      catch (InvalidKeyException ex)
      {
         // swallow, since it should never happen
      }
      return key;
   }

   public byte[] decryptedData(byte[] data)
   {
      return data;
   }
}
