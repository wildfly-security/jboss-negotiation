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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.jboss.security.negotiation.ntlm.Constants;

/**
 * A Decoder to decode the NegotiateMessage
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiateMessageDecoder
{

   private static void readVerifySignature(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] expected = Constants.SIGNATURE;
      byte[] dataRead = new byte[expected.length];

      is.read(dataRead);
      if (Arrays.equals(expected, dataRead) == false)
      {
         throw new IOException("Invalid signature, expected '" + new String(expected) + "' actual '"
               + new String(dataRead) + "'");
      }
      data.read += dataRead.length;
   }

   private static void readVerifyMessageType(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] expected = Constants.NEGOTIATE_MESSAGE_TYPE;
      byte[] dataRead = new byte[expected.length];

      is.read(dataRead);
      if (Arrays.equals(expected, dataRead) == false)
      {
         throw new IOException("Invalid MessageType, expected '" + new String(expected) + "' actual '"
               + new String(dataRead) + "'");
      }
      data.read += dataRead.length;
   }

   private static void readVersion(final InputStream is, final DecoderData data) throws IOException
   {
      byte[] version;
      if (data.message.getNegotiateFlags().isNegotiateVersion() == true)
      {
         version = new byte[8];
      }
      else
      {
         version = new byte[0];
      }
      is.read(version);
      data.read += version.length;

      data.message.setVersion(version);
   }

   private static String readPayloadValue(final InputStream is, final DecoderData data, final NTLMField field)
         throws IOException
   {
      byte[] dataRead = new byte[field.getLength()];

      int offset = field.getOffset();
      int bytesRead = data.read;

      if (bytesRead < offset)
      {
         int toSkip = offset - bytesRead;
         is.skip(toSkip);
         data.read += toSkip;
      }
      else if (bytesRead > offset)
      {
         throw new IllegalStateException("Read beyond offset.");
      }

      is.read(dataRead);
      data.read += dataRead.length;

      return new String(dataRead);
   }

   private static void readPayload(final InputStream is, final DecoderData data) throws IOException
   {
      NegotiateMessage message = data.message;
      NTLMField domainFields = message.getDomainNameFields();
      NTLMField workstationFields = message.getWorkstationFields();

      boolean readDomainName = (domainFields.getLength() > 0);
      boolean readWSName = (workstationFields.getLength() > 0);

      String domainName = "";
      String workstationName = "";

      if (readWSName && readDomainName)
      {
         // If both are required we need to check the ordering.
         int wsOffset = workstationFields.getOffset();
         int domainOffset = domainFields.getOffset();

         if (wsOffset < domainOffset)
         {
            workstationName = readPayloadValue(is, data, workstationFields);
            domainName = readPayloadValue(is, data, domainFields);
         }
         else
         {
            domainName = readPayloadValue(is, data, domainFields);
            workstationName = readPayloadValue(is, data, workstationFields);
         }

         message.setDomainName(domainName);
         message.setWorkstationName(workstationName);
      }
      else if (readWSName)
      {
         workstationName = readPayloadValue(is, data, workstationFields);
      }
      else if (readDomainName)
      {
         domainName = readPayloadValue(is, data, domainFields);
      }

   }

   public static NegotiateMessage decode(final InputStream is) throws IOException
   {
      DecoderData data = new DecoderData();

      readVerifySignature(is, data);
      readVerifyMessageType(is, data);
      NegotiateFlagsDecoder.readNegotiateFlags(is, data);
      data.message.setDomainNameFields(FieldDecoder.readFieldLengths(is, data));
      data.message.setWorkstationFields(FieldDecoder.readFieldLengths(is, data));
      readVersion(is, data);
      readPayload(is, data);

      return data.message;
   }

   public static NegotiateMessage decode(final byte[] token) throws IOException
   {
      ByteArrayInputStream bais = new ByteArrayInputStream(token);

      return decode(bais);
   }
}
