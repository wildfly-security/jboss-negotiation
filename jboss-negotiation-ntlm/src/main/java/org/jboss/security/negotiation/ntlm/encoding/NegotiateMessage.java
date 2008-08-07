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
 * Representation of an NTLM NEGOTIATIE_MESSAGE
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiateMessage
{

   private NegotiateFlags negotiateFlags;

   private String domainName;

   private String workstationName;

   public NegotiateFlags getNegotiateFlags()
   {
      return negotiateFlags;
   }

   public void setNegotiateFlags(NegotiateFlags negotiateFlags)
   {
      this.negotiateFlags = negotiateFlags;
   }

   public String getDomainName()
   {
      return domainName;
   }

   public void setDomainName(String domainName)
   {
      this.domainName = domainName;
   }

   public String getWorkstationName()
   {
      return workstationName;
   }

   public void setWorkstationName(String workstationName)
   {
      this.workstationName = workstationName;
   }

}
