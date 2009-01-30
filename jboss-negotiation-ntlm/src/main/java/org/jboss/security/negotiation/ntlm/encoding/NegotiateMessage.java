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

import java.io.IOException;
import java.io.OutputStream;

import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.util.NotImplementedException;

/**
 * Representation of an NTLM NEGOTIATIE_MESSAGE
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiateMessage extends NegotiationMessage
{

   private NegotiateFlags negotiateFlags;

   private NTLMField domainNameFields;

   private String domainName;

   private byte[] version;

   private NTLMField workstationFields;

   private String workstationName;

   public NegotiateFlags getNegotiateFlags()
   {
      return negotiateFlags;
   }

   public void setNegotiateFlags(NegotiateFlags negotiateFlags)
   {
      this.negotiateFlags = negotiateFlags;
   }

   public byte[] getVersion()
   {
      return version;
   }

   public void setVersion(byte[] version)
   {
      this.version = version;
   }

   public NTLMField getDomainNameFields()
   {
      return domainNameFields;
   }

   public void setDomainNameFields(NTLMField domainNameFields)
   {
      this.domainNameFields = domainNameFields;
   }

   public String getDomainName()
   {
      return domainName;
   }

   public void setDomainName(String domainName)
   {
      this.domainName = domainName;
   }

   public NTLMField getWorkstationFields()
   {
      return workstationFields;
   }

   public void setWorkstationFields(NTLMField workstationFields)
   {
      this.workstationFields = workstationFields;
   }

   public String getWorkstationName()
   {
      return workstationName;
   }

   public void setWorkstationName(String workstationName)
   {
      this.workstationName = workstationName;
   }

   @Override
   public String toString()
   {
      StringBuilder sb = new StringBuilder();
      sb.append("{domainName=").append(domainName).append("}");
      sb.append("{domainNameFields=").append(domainNameFields).append("}");
      sb.append("{workstationName=").append(workstationName).append("}");
      sb.append("{workstationNameFields=").append(workstationFields).append("}");
      sb.append("{negotiateFlags=").append(negotiateFlags).append("}");

      return sb.toString();
   }

   @Override
   public void writeTo(OutputStream os) throws IOException
   {
      throw new NotImplementedException();
   }

   @Override
   public String getMessageType()
   {
      return "NTLM";
   }

}
