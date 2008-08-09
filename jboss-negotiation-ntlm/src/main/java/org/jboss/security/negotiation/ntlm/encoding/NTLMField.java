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

/**
 * Representation of a field with a length, max length and offset.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 8th August 2008
 */
public class NTLMField
{

   private int length;

   private int maxLength;

   private int offset;

   public int getLength()
   {
      return length;
   }

   public void setLength(int length)
   {
      this.length = length;
   }

   public int getMaxLength()
   {
      return maxLength;
   }

   public void setMaxLength(int maxLength)
   {
      this.maxLength = maxLength;
   }

   public int getOffset()
   {
      return offset;
   }

   public void setOffset(int offset)
   {
      this.offset = offset;
   }

   @Override
   public String toString()
   {
      StringBuilder sb = new StringBuilder();
      sb.append("{length=").append(length).append("}");
      sb.append("{maxLength=").append(maxLength).append("}");
      sb.append("{offset=").append(offset).append("}");

      return sb.toString();
   }

}
