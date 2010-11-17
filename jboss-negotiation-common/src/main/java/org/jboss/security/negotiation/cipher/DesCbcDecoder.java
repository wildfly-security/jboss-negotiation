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
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.security.negotiation.NegotiationException;

/**
 * Common methods for the DesCbc types.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public abstract class DesCbcDecoder extends Decoder
{

   protected abstract byte[] calculateChecksum(byte[] data, int size) throws NegotiationException;
   
   public int blockSize()
   {
      return 8;
   }

   public int keySize()
   {
      return 8;
   }

   public int confounderSize()
   {
      return 8;
   }

   public byte[] decrypt(byte[] cipher, byte[] key, int usage) throws NegotiationException
   {
      byte[] ivec = new byte[keySize()];
      return decrypt(cipher, key, ivec, usage);
   }

   public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage) throws NegotiationException
   {
      if (key.length > 8)
         throw new NegotiationException("Invalid DES Key!");

      byte[] data = new byte[cipher.length];
      cbc_encrypt(cipher, data, key, ivec, false);
      if (!isChecksumValid(data))
         throw new NegotiationException("Bad integrity check on AP_REQ");
      return data;
   }

   protected boolean isChecksumValid(byte[] data) throws NegotiationException
   {
      byte[] cksum1 = checksumField(data);
      byte[] cksum2 = generateChecksum(data);
      return isChecksumEqual(cksum1, cksum2);
   }

   private boolean isChecksumEqual(byte[] cksum1, byte[] cksum2)
   {
      if (cksum1 == cksum2)
         return true;
      if ((cksum1 == null && cksum2 != null) || (cksum1 != null && cksum2 == null))
         return false;
      if (cksum1.length != cksum2.length)
         return false;
      for (int i = 0; i < cksum1.length; i++)
      {
         if (cksum1[i] != cksum2[i])
            return false;
      }
      return true;
   }

   private byte[] checksumField(byte[] data)
   {
      byte[] result = new byte[checksumSize()];
      for (int i = 0; i < checksumSize(); i++)
      {
         result[i] = data[startOfChecksum() + i];
      }
      return result;
   }

   private byte[] generateChecksum(byte[] data) throws NegotiationException
   {
      byte[] cksum1 = checksumField(data);
      resetChecksumField(data);
      byte[] cksum2 = calculateChecksum(data, data.length);
      copyChecksumField(data, cksum1);
      return cksum2;
   }

   private void resetChecksumField(byte[] data)
   {
      for (int i = startOfChecksum(); i < startOfChecksum() + checksumSize(); i++)
      {
         data[i] = 0;
      }
   }

   private void copyChecksumField(byte[] data, byte[] cksum)
   {
      for (int i = 0; i < checksumSize(); i++)
      {
         data[startOfChecksum() + i] = cksum[i];
      }
   }

   public static void cbc_encrypt(byte[] input, byte[] output, byte[] key, byte[] ivec, boolean encrypt)
         throws NegotiationException
   {

      Cipher cipher = null;
      try
      {
         cipher = Cipher.getInstance("DES/CBC/NoPadding");
      }
      catch (GeneralSecurityException e)
      {
         NegotiationException ne = new NegotiationException("JCE provider may not be installed. " + e.getMessage());
         ne.initCause(e);
         throw ne;
      }
      IvParameterSpec params = new IvParameterSpec(ivec);
      SecretKeySpec skSpec = new SecretKeySpec(key, "DES");
      try
      {
         SecretKey sk = (SecretKey) skSpec;
         if (encrypt)
            cipher.init(Cipher.ENCRYPT_MODE, sk, params);
         else
            cipher.init(Cipher.DECRYPT_MODE, sk, params);
         byte[] result;
         result = cipher.doFinal(input);
         System.arraycopy(result, 0, output, 0, result.length);
      }
      catch (GeneralSecurityException e)
      {
         NegotiationException ne = new NegotiationException(e.getMessage());
         ne.initCause(e);
         throw ne;
      }
   }
}
