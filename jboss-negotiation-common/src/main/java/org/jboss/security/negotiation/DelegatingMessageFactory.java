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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * A message factory to delegate to a list of sub message factories.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
class DelegatingMessageFactory extends MessageFactory
{

   private List<MessageFactory> delegates;

   DelegatingMessageFactory(final List<MessageFactory> delegates)
   {
      this.delegates = delegates;
   }

   @Override
   public boolean accepts(final InputStream in) throws IOException
   {
      for (MessageFactory current : delegates)
      {
         if (current.accepts(in) == true)
         {
            return true;
         }
      }

      return false;
   }

   @Override
   public NegotiationMessage createMessage(final InputStream in) throws IOException
   {
      for (MessageFactory current : delegates)
      {
         if (current.accepts(in) == true)
         {
            return current.createMessage(in);
         }
      }

      throw new IllegalStateException("No suitable MessageFactory found for message.");
   }

}
