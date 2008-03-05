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

package com.darranl.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.codec.binary.Hex;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

/**
 * Debug code to test header as encoded by Microsoft.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class MicrosoftDecoding
{

   private static final String encoded = "YIIEygYGKwYBBQUCoIIEvjCCBLqgMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKoZIhvcSAQICAwYKKwYBBAGCNwICCqKCBIQEggSAYIIEfAYJKoZIhvcSAQICAQBuggRrMIIEZ6ADAgEFoQMCAQ6iBwMFACAAAACjggOXYYIDkzCCA4+gAwIBBaERGw9EQUxORVQuUExVUy5DT02iIDAeoAMCAQKhFzAVGwRIVFRQGw1zYW1wbGVfc2VydmVyo4IDUTCCA02gAwIBA6KCA0QEggNAF+1Zfe6/6t26s6CdqiH45+FVeFoqux5TjWAPNrhf6dCLAUJk0eY+Oth4Uve1J4HMv44IAix5Qcp1qlUchf45NQ43vf/lmz1p0jL9vdEe/icBYLnLlN7E8+SjOeDmLn4/a18sy4LN7nx1bOEgN/JVMI8xywLnVTrOyQGMzUxAeBfSaLDskP001h5haFSc+J08oToS0NYIQ4Beaj9Rn1mENcNCV9ZidNfVdrGnpkZSu1coAboRerIKg4ZPftzEJdU0RUFtSLBuHyxqxdSoFMXmzi44/uVEZi0RiMyHF9xBEifpJFTgWExc4lgOeeHp+HkWAwoDYJt5L7WDfsMf7W5gw0tmAsJOpSL6s8NYNSmv+1EKXllkF7Zs9oIa2HDdqPjlX1I2IaeobN5LBPx4j12pgfCymgcilggQyhXjLdlOPJ+31T7OugkYtqiPbrHn9OLGah6R6XzGHjPO+Siv0eCVn0vWdMoH29UZ+jS7EifkNz3J3EpN1/OpuW46E+IdupzN1hgmFHwjgA+3LSKjqTgN9BYqZeaH1R6snuMsNEhLAG6AOov/9FDhtx8pKbZmRkNzLj20vqFptPYcbNmnZ4G4EnJ9ZvM4XOqNQ12Cp19FD0vE2CBkpxYh772TUVMTuayaRDk0U0BQR3FXLge9Z1fNPU2LbMQN5b0aTfGtgcOX0r7DiZ9kZM0t7AYMCVBiFvH3DvUmNcN7azdVcFKcOREmYy2Bo43mUiUAVhPbyTZJNqgPEaFdw3pgNBKBZCfySMwyRU/BKT7v09C6gDWKKuCFFNbgdZWxnj5GmYOaDsUGT1woYJFBnZO/9fjy7U/H+9x82llm9p7IPTL2C/lE05sPE5M+vRJCAL3xeGY3Q2ptmS8z28QPV0schl09CriHu/mEo7AEeJ04iQNFUVcFBdqk1a8r9Zq/M7Gjs5FN86yv4V0kTscvRthAQ4wvluFvZHtwF5VdnKWNwWHBomFgJap4zr41i6e4N6Z0S9TMcL5jQCbkao5GvYaEjxUnlDbgNDSrEKI/zxzQsE2uOfOp/nmixlz07C+xOsqYVNZgbxrPxectEjUEzzwEZq+VTSsbT9U0edBsHLv3rx8Bde4yNDde/6SBtjCBs6ADAgEDooGrBIGommHtA6iDG0no+z7tX/mAsEKHQvhjcKthP4cke9RbhgWj2aO0MgXsBm5ZyxOcNLPEwsPQPA6Jm5SU8732GQTP0MRBFjAMImuxEnrDBUDhd1lQXDoI6yv/a0E7VtrOb78HnvnS3eny1YXrMQG5Pdy5xbtVhfNESJUa2oJhBmBDlrqdeM3WohXyGHg0ujIjQ9gX9hJZJa6PzPBeJboJkv5aEacK8vLRTrWL";

   private static final byte LEAD_BYTE = 0x60;

   private enum DERType {
      Integer, BitString, OctletString, ObjectIdentifier, Sequence;
   }

   private enum NegotiationToken {
      NegTokenInit, NegTokenTarg;
   }

   private static final int readLength(final InputStream is) throws IOException
   {
      byte first = (byte) is.read();
      byte masked = (byte) (first & (byte) 128);

      if (masked == 0)
      {
         return first;
      }

      int lengthLength = first & (byte) 127;

      byte[] lengthBytes = new byte[lengthLength];
      is.read(lengthBytes);

      int length = 0;
      for (int i = 0; i < lengthLength; i++)
      {
         int currentPos = lengthLength - i - 1;
         int currentLength = lengthBytes[currentPos];

         if (currentLength < 0)
         {
            currentLength += 256;
         }

         if (i > 0)
         {
            currentLength = currentLength * 256 * i;
         }

         length += currentLength;
      }

      return length;
   }

   private static final int readConstructedSequenceLength(final InputStream is) throws IOException
   {
      is.mark(Integer.MAX_VALUE);

      byte type = (byte) is.read();
      if (type != 0x30)
      {
         is.reset();
         throw new IOException("Not Constructed Sequence");
      }

      return readLength(is);
   }

   private static final DERType readType(final InputStream is) throws IOException
   {
      is.mark(Integer.MAX_VALUE);
      switch (is.read())
      {
         case 0x02 :
            return DERType.Integer;
         case 0x03 :
            return DERType.BitString;
         case 0x04 :
            return DERType.OctletString;
         case 0x06 :
            return DERType.ObjectIdentifier;
         case 0x10 :
            return DERType.Sequence;
         default :
            is.reset();
            return null;
      }
   }

   private static final NegotiationToken readTokenType(final InputStream is) throws IOException
   {
      is.mark(Integer.MAX_VALUE);
      switch (is.read())
      {
         case 0xA0 :
            return NegotiationToken.NegTokenInit;
         case 0xA1 :
            return NegotiationToken.NegTokenTarg;
         default :
            is.reset();
            return null;

      }
   }

   public static List readMechTypes(final InputStream is) throws IOException, GSSException
   {
      int sequenceLength = readConstructedSequenceLength(is);
      System.out.println("sequenceLength " + sequenceLength);

      int leftAfterSequence = is.available() - sequenceLength;
      List mechTypes = new ArrayList();
      while (is.available() > leftAfterSequence)
      {
         mechTypes.add(new Oid(is));
      }

      return mechTypes;
   }

   public static byte[] readMechToken(final InputStream is) throws IOException
   {
      int length = readLength(is);

      byte[] token = new byte[length];
      is.read(token);

      return token;
   }

   public static final byte[] parse(final byte[] spnegoToken) throws IOException, GSSException
   {
      byte[] token = null;

      ByteArrayInputStream bais = new ByteArrayInputStream(spnegoToken);

      byte lead = (byte) bais.read();
      if (lead != LEAD_BYTE)
      {
         System.err.println("Invalid leading byte.");
      }

      System.out.println("Length - " + readLength(bais));

      Oid oid = new Oid(bais);
      System.out.println(oid.toString());

      NegotiationToken tokenType = readTokenType(bais);
      System.out.println(tokenType.name());

      int negTokenInitLength = readLength(bais);
      System.out.println("negTokenInitLength " + negTokenInitLength);

      int sequenceLength = readConstructedSequenceLength(bais);
      System.out.println("sequenceLength " + sequenceLength);

      int leftAfterSequence = bais.available() - sequenceLength;

      while (bais.available() > leftAfterSequence)
      {
         byte type = (byte) bais.read();

         int length = 0;
         switch (type)
         {
            case (byte) 0xA0 :
               System.out.println("mechTypes");
               length = readLength(bais);

               List mechTypes = readMechTypes(bais);
               for (Object current : mechTypes)
               {
                  System.out.println(current.toString());
               }
               break;
            case (byte) 0xA1 :
               System.out.println("reqFlags");
               length = readLength(bais);
               bais.skip(length);
               break;
            case (byte) 0xA2 :
               System.out.println("mechToken");
               //length = readLength(bais);

               token = readMechToken(bais);
               char[] hex = Hex.encodeHex(token);

               for (int i = 0; i < hex.length; i++)
               {
                  if (i % 2 == 0)
                  {
                     System.out.print(" 0x");
                  }
                  System.out.print(hex[i]);
               }
               System.out.println();

               byte[] base64 = Base64.encodeBase64Chunked(token);
               System.out.println(new String(base64));

               break;
            case (byte) 0xA3 :
               System.out.println("mechListMIC");
               length = readLength(bais);
               bais.skip(length);
               break;
            default :
               throw new IOException("Unexpected type");
         }
      }

      System.out.println(bais.available());

      return token;
   }

   /** 
    * 
    * @param args
    * @throws IOException 
    * @throws GSSException 
    */
   public static void main(final String[] args) throws IOException, GSSException
   {
      byte[] decoded = Base64.decodeBase64(encoded.getBytes());

      System.out.println(encoded.indexOf("YII", 1));

      System.out.println("Decoded Length " + decoded.length);

      char[] result = Hex.encodeHex(decoded);
      for (int i = 0; i < result.length; i++)
      {
         if (i % 2 == 0)
         {
            System.out.print(" 0x");
         }
         System.out.print(result[i]);
      }

      System.out.println();

      char[] binary = BinaryCodec.toAsciiChars(decoded);
      System.out.println("Binary Length = " + binary.length);
      System.out.println("Bits Per Byte " + binary.length / decoded.length);
      for (int i = 0; i < binary.length; i++)
      {
         if (i % 8 == 0)
         {
            System.out.print(" ");
         }
         System.out.print(binary[i]);
      }
      System.out.println();

      for (int i = 0; i < decoded.length; i++)
      {
         System.out.print(" " + (int) decoded[i]);
      }
      System.out.println();

      // Parsing Message
      int pos = 1;

      byte masked = (byte) (decoded[pos] & (byte) 127);
      System.out.println("Masked " + (int) masked);
      if (masked > 0)
      {
         System.out.println("First byte is length length");
      }
      else
      {

      }

      parse(decoded);
   }

}
