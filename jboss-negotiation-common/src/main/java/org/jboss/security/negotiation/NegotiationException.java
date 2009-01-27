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

/**
 * A negotiation exception for when a checked exception is required.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
public class NegotiationException extends Exception
{

   private static final long serialVersionUID = 1673369082849726544L;

   public NegotiationException()
   {
      super();
   }

   public NegotiationException(String message, Throwable cause)
   {
      super(message, cause);
   }

   public NegotiationException(String message)
   {
      super(message);
   }

   public NegotiationException(Throwable cause)
   {
      super(cause);
   }

}
