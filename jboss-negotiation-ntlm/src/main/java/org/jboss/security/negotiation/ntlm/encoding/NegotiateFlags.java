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

import java.lang.reflect.Field;

/**
 * Representation of NTLM NegotiateFlags
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NegotiateFlags
{

   private boolean encryption56Bit;

   private boolean explicitKeyExchange;

   private boolean sessionKeyExchange128Bit;

   private boolean negotiateVersion;

   private boolean targetInfo;

   private boolean requestNonNTSessionKey;

   private boolean identify;

   private boolean ntlm2;

   private boolean targetTypeShare;

   private boolean targetTypeServer;

   private boolean targetTypeDomain;

   private boolean alwaysSign;

   private boolean oemWorkstationSupplied;

   private boolean oemDomainSupplied;

   private boolean ntOnly;

   private boolean ntlm;

   private boolean lmKey;

   private boolean datagram;

   private boolean seal;

   private boolean sign;

   private boolean requestTarget;

   private boolean oem;

   private boolean unicode;

   public boolean isEncryption56Bit()
   {
      return encryption56Bit;
   }

   public void setEncryption56Bit(boolean encryption56Bit)
   {
      this.encryption56Bit = encryption56Bit;
   }

   public boolean isExplicitKeyExchange()
   {
      return explicitKeyExchange;
   }

   public void setExplicitKeyExchange(boolean explicitKeyExchange)
   {
      this.explicitKeyExchange = explicitKeyExchange;
   }

   public boolean isSessionKeyExchange128Bit()
   {
      return sessionKeyExchange128Bit;
   }

   public void setSessionKeyExchange128Bit(boolean sessionKeyExchange128Bit)
   {
      this.sessionKeyExchange128Bit = sessionKeyExchange128Bit;
   }

   public boolean isNegotiateVersion()
   {
      return negotiateVersion;
   }

   public void setNegotiateVersion(boolean negotiateVersion)
   {
      this.negotiateVersion = negotiateVersion;
   }

   public boolean isTargetInfo()
   {
      return targetInfo;
   }

   public void setTargetInfo(boolean targetInfo)
   {
      this.targetInfo = targetInfo;
   }

   public boolean isRequestNonNTSessionKey()
   {
      return requestNonNTSessionKey;
   }

   public void setRequestNonNTSessionKey(boolean requestNonNTSessionKey)
   {
      this.requestNonNTSessionKey = requestNonNTSessionKey;
   }

   public boolean isIdentify()
   {
      return identify;
   }

   public void setIdentify(boolean identify)
   {
      this.identify = identify;
   }

   public boolean isNtlm2()
   {
      return ntlm2;
   }

   public void setNtlm2(boolean ntlm2)
   {
      this.ntlm2 = ntlm2;
   }

   public boolean isTargetTypeShare()
   {
      return targetTypeShare;
   }

   public void setTargetTypeShare(boolean targetTypeShare)
   {
      this.targetTypeShare = targetTypeShare;
   }

   public boolean isTargetTypeServer()
   {
      return targetTypeServer;
   }

   public void setTargetTypeServer(boolean targetTypeServer)
   {
      this.targetTypeServer = targetTypeServer;
   }

   public boolean isTargetTypeDomain()
   {
      return targetTypeDomain;
   }

   public void setTargetTypeDomain(boolean targetTypeDomain)
   {
      this.targetTypeDomain = targetTypeDomain;
   }

   public boolean isAlwaysSign()
   {
      return alwaysSign;
   }

   public void setAlwaysSign(boolean alwaysSign)
   {
      this.alwaysSign = alwaysSign;
   }

   public boolean isOemWorkstationSupplied()
   {
      return oemWorkstationSupplied;
   }

   public void setOemWorkstationSupplied(boolean oemWorkstationSupplied)
   {
      this.oemWorkstationSupplied = oemWorkstationSupplied;
   }

   public boolean isOemDomainSupplied()
   {
      return oemDomainSupplied;
   }

   public void setOemDomainSupplied(boolean oemDomainSupplied)
   {
      this.oemDomainSupplied = oemDomainSupplied;
   }

   public boolean isNtOnly()
   {
      return ntOnly;
   }

   public void setNtOnly(boolean ntOnly)
   {
      this.ntOnly = ntOnly;
   }

   public boolean isNtlm()
   {
      return ntlm;
   }

   public void setNtlm(boolean ntlm)
   {
      this.ntlm = ntlm;
   }

   public boolean isLmKey()
   {
      return lmKey;
   }

   public void setLmKey(boolean lmKey)
   {
      this.lmKey = lmKey;
   }

   public boolean isDatagram()
   {
      return datagram;
   }

   public void setDatagram(boolean datagram)
   {
      this.datagram = datagram;
   }

   public boolean isSeal()
   {
      return seal;
   }

   public void setSeal(boolean seal)
   {
      this.seal = seal;
   }

   public boolean isSign()
   {
      return sign;
   }

   public void setSign(boolean sign)
   {
      this.sign = sign;
   }

   public boolean isRequestTarget()
   {
      return requestTarget;
   }

   public void setRequestTarget(boolean requestTarget)
   {
      this.requestTarget = requestTarget;
   }

   public boolean isOem()
   {
      return oem;
   }

   public void setOem(boolean oem)
   {
      this.oem = oem;
   }

   public boolean isUnicode()
   {
      return unicode;
   }

   public void setUnicode(boolean unicode)
   {
      this.unicode = unicode;
   }

   @Override
   public String toString()
   {
      StringBuilder sb = new StringBuilder();

      Field[] fields = getClass().getDeclaredFields();

      for (Field current : fields)
      {
         if (current.getType().equals(boolean.class))
         {
            try
            {
               boolean value = current.getBoolean(this);
               if (value == true)
               {
                  sb.append("(").append(current.getName()).append(")");
               }
            }
            catch (Exception ignored)
            {
               // Access should not be a problem.
            }
         }
      }

      return sb.toString();
   }

}
