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

import java.io.InputStream;

/**
 * The base message factory for reading messages from InputStreams and
 * creating the Java representation of the message.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
public abstract class MessageFactory
{

   /**
    * @return a new MessageFactory to process a message available from an InputStream.
    */
   public static MessageFactory newInstance()
   {
      return null;
   }

   /**
    * Peek at the data in the InputStream and return true if this
    * MessageFactory can handle the data.
    */
   public abstract boolean accepts(final InputStream in);

   /**
    * Read the message from the InputStream and create the Java
    * representation of the message.
    */
   public abstract Object createMessage(final InputStream in);

}
