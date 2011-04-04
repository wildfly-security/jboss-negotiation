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
package org.jboss.security.negotiation.spnego.encoding;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;

import org.jboss.security.negotiation.NegotiationException;
import org.jboss.security.negotiation.cipher.Decoder;

/**
 * Parses a token to retrieve specific parts required.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class TokenParser
{

   private String crealm;
   
   private String cname;

   /**
    * Method to be invoked to parse and decode the token.
    * 
    * @param data byte array containing the token
    * @param subject {@link Subject} containing the private key
    * @throws Exception
    */
   public void parseToken(byte[] data, Subject subject) throws Exception
   {
      ByteArrayInputStream bais = new ByteArrayInputStream(data);
      // get the AP_REQ part
      byte[] b = getAP_REQ(bais);
      bais.close();
      
      bais = new ByteArrayInputStream(b);
      // get the Ticket part
      b = getTicket(bais);
      bais.close();
      
      bais = new ByteArrayInputStream(b);
      // get the EncryptedData part
      b = getEncryptedData(bais);
      bais.close();
      
      bais = new ByteArrayInputStream(b);
      // decode the EncryptedData
      handleEncryptedData(bais, b.length, subject);
      bais.close();
   }

   /**
    * Parses the {@link InputStream} until it finds the sequence at position indicated by the byte.
    * 
    * @param is {@link InputStream} to read
    * @param type position in the sequence
    * @return data found
    * @throws Exception
    */
   public byte[] getValueAt(InputStream is, byte type) throws Exception
   {
      byte[] bytes = null;
      byte tag;
      do
      {
         tag = (byte) is.read();
         int sequenceLength = NegTokenDecoder.readLength(is);
         bytes = new byte[sequenceLength];
         is.read(bytes);
         if (is.available() == 0)
         {
            is = new ByteArrayInputStream(bytes);
         }
      }
      while (!isContextSpecific(tag, type));
      return bytes;
   }

   /**
    * Verify that the tag is the correct one.
    * 
    * @param tag byte to verify
    * @param cntxtTag byte to match
    * @return true if match
    */
   public boolean isContextSpecific(byte tag, byte cntxtTag)
   {
      return ((tag & 0x01f) == cntxtTag);
   }
   
   /**
    * Parses the {@link InputStream} until the AP_REQ is found.
    * 
    * @param is {@link InputStream} to read
    * @return the AP_REQ data
    * @throws Exception
    */
   public byte[] getAP_REQ(InputStream is) throws Exception
   {
      is.read();
      NegTokenDecoder.readLength(is);
      byte[] bytes = getValueAt(is, (byte) 14);

      return bytes;
   }

   /**
    * Parses the {@link InputStream} until the Ticket is found.
    * 
    * @param is {@link InputStream} to read
    * @return the Ticket data
    * @throws Exception
    */
   public byte[] getTicket(InputStream is) throws Exception
   {
      byte[] bytes = getValueAt(is, (byte) 3);

      return bytes;
   }

   /**
    * Parses the {@link InputStream} until the EncryptedData is found.
    * 
    * @param is {@link InputStream} to read
    * @return the EncryptedData data
    * @throws Exception
    */
   public byte[] getEncryptedData(InputStream is) throws Exception
   {
      byte[] bytes = getValueAt(is, (byte) 3);

      return bytes;
   }
   
   /**
    * Decodes the encrypted data and parses the encrypted part to retrieve the client
    * realm and principal.
    * 
    * @param is {@link InputStream} to read
    * @param size encrypted data size
    * @param subject {@link} Subject containing the private key
    * @throws Exception
    */
   public void handleEncryptedData(InputStream is, int size, Subject subject) throws Exception
   {
      is.mark(size);
      byte[] bytes = getValueAt(is, (byte) 0);
      bytes = Arrays.copyOfRange(bytes, 2, 3);
      BigInteger bi = new BigInteger(bytes);
      int eType = bi.intValue();

      KerberosKey key = getKrbKey(subject, eType);

      is.reset();
      bytes = getValueAt(is, (byte) 2);
      ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
      bais.read();
      int cipherLength = NegTokenDecoder.readLength(bais);
      byte[] cipher = new byte[cipherLength];
      bais.read(cipher);
      bais.close();
      
      byte[] ticketBytes = decrypt(key, cipher);
      byte[] temp = reset(ticketBytes);
      
      // at this point we have the decrypted ticket
      bais = new ByteArrayInputStream(temp);
      bais.read();
      int length = NegTokenDecoder.readLength(bais);
      temp = new byte[length];
      bais.read(temp);
      bais.close();
      bais = new ByteArrayInputStream(temp);
      
      byte[] realm = getValueAt(bais, (byte) 2);
      bais.close();
      
      // at this point we have a Realm in the byte[]
      realm = Arrays.copyOfRange(realm, 2, realm.length);
      crealm = new String(realm);
      bais = new ByteArrayInputStream(temp);
      byte[] principalName = getValueAt(bais, (byte) 3);
      bais.close();
      
      // at this point we have a PrincipalName in the byte[]
      bais = new ByteArrayInputStream(principalName);
      byte[] names = getValueAt(bais, (byte) 1);
      bais.close();
      names = Arrays.copyOfRange(names, 2, names.length);
      
      // at this point we have the sequence of names in the byte[]
      bais = new ByteArrayInputStream(names);
      String[] cnames = getNames(bais);
      bais.close();
      StringBuffer buffer = new StringBuffer(cnames[0]);
      for (int i = 1; i < cnames.length; i++)
      {
         buffer.append("/");
         buffer.append(cnames[i]);
      }
      cname = buffer.toString();
   }
   
   /**
    * Parses the data to find all the principal names.
    * 
    * @param is {@link InputStream} to read
    * @return array of names
    * @throws Exception
    */
   public String[] getNames(InputStream is) throws Exception
   {
      List<String> principals = new ArrayList<String>();
      do
      {
         is.read();
         int length = NegTokenDecoder.readLength(is);
         byte[] name = new byte[length];
         is.read(name);
         principals.add(new String(name));
      }
      while (is.available() > 0);
      
      String[] names = new String[principals.size()];
      names = principals.toArray(names);
      
      return names;
   }
   
   /**
    * Retrieves the private key from the {@link Subject}.
    * 
    * @param sub {@link SUbject} containing the private key
    * @param keyType type of the key
    * @return the private key
    */
   public KerberosKey getKrbKey(Subject sub, int keyType)
   {
      Set<Object> creds = sub.getPrivateCredentials(Object.class);
      for (Iterator<Object> i = creds.iterator(); i.hasNext();)
      {
         Object cred = i.next();
         if (cred instanceof KerberosKey)
         {
            KerberosKey key = (KerberosKey) cred;
            if (key.getKeyType() == keyType)
            {
               return (KerberosKey) cred;
            }
         }
      }
      return null;
   }
   
   /**
    * Decodes the data.
    * 
    * @param key private key
    * @param cipher
    * @return decoded data
    * @throws NegotiationException
    */
   public byte[] decrypt(KerberosKey key, byte[] cipher) throws NegotiationException
   {
      Decoder decoder = Decoder.getInstace(key.getKeyType());
      byte[] plain = decoder.decrypt(cipher, key.getEncoded(), 2);
      return decoder.decryptedData(plain);
   }
   
   /**
    * Resets the size.
    * 
    * @param data
    * @return
    */
   public byte[] reset(byte[] data)
   {
      byte[] bytes = null;
      if ((data[1] & 0xFF) < 128)
      {
         bytes = new byte[data[1] + 2];
         System.arraycopy(data, 0, bytes, 0, data[1] + 2);
      }
      else
      {
         if ((data[1] & 0xFF) > 128)
         {
             int len = (int)(data[1] & (byte) 0x7F);
             int result = 0;
             for (int i = 0; i < len; i++)
             {
                result |= (data[i + 2] & 0xFF) << (8 * (len - i - 1));
             }
             bytes = new byte[result + len + 2];
             System.arraycopy(data, 0, bytes, 0, result + len + 2);
         }
      }
      return bytes;
   }
   
   /**
    * Returns the principal name of the client.
    * 
    * @return principal name
    */
   public String getPrincipalName()
   {
      return cname + "@" + crealm;
   }
}
