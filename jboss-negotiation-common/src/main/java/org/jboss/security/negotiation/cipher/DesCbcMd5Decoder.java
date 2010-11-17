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

import java.security.MessageDigest;

import org.jboss.security.negotiation.NegotiationException;

/**
 * A {@link Decoder} for DesCbcMd5.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class DesCbcMd5Decoder extends DesCbcDecoder
{

   public int checksumSize()
   {
      return 16;
   }

   protected byte[] calculateChecksum(byte[] data, int size) throws NegotiationException
   {
      MessageDigest md5 = null;
      try
      {
         md5 = MessageDigest.getInstance("MD5");
      }
      catch (Exception e)
      {
         throw new NegotiationException("JCE provider may not be installed. " + e.getMessage());
      }
      try
      {
         md5.update(data);
         return (md5.digest());
      }
      catch (Exception e)
      {
         throw new NegotiationException(e.getMessage());
      }
   }
}
