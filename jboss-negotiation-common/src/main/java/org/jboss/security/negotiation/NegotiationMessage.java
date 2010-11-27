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

package org.jboss.security.negotiation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.jboss.util.Base64;

/**
 * The common base type for all negotiation messages.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
public abstract class NegotiationMessage
{

   /**
    * Write the message to the provided output stream in 
    * it's raw form.
    */
   public abstract void writeTo(final OutputStream os) throws IOException;

   /**
    * @return The message type.
    */
   public abstract String getMessageType();
   
   
   /**
    * Write the message to the provided output stream, if base64 is set the
    * output should be base64 encoded.
    */
   public void writeTo(final OutputStream os, final boolean base64) throws IOException
   {
      if (base64 == true)
      {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         writeTo(baos);
         String encoded = Base64.encodeBytes(baos.toByteArray());
         os.write(encoded.getBytes());
      }
      else
      {
         writeTo(os);
      }
   }

}
