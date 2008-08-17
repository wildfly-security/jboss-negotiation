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

package org.jboss.security.negotiation.spnego.encoding;

import java.io.IOException;
import java.io.OutputStream;

import org.ietf.jgss.Oid;

/**
 * Representation of NegTokenTarg.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenTarg extends SPNEGOMessage
{
   public static final Integer ACCEPT_COMPLETED = new Integer(1);

   public static final Integer ACCEPT_INCOMPLETE = new Integer(2);

   public static final Integer REJECTED = new Integer(3);

   private Integer negResult = null;

   private Oid supportedMech = null;

   private byte[] responseToken = null;

   private byte[] mechListMIC = null;

   public Integer getNegResult()
   {
      return negResult;
   }

   public void setNegResult(Integer negResult)
   {
      this.negResult = negResult;
   }

   public Oid getSupportedMech()
   {
      return supportedMech;
   }

   public void setSupportedMech(Oid supportedMech)
   {
      this.supportedMech = supportedMech;
   }

   public byte[] getResponseToken()
   {
      return responseToken;
   }

   public void setResponseToken(byte[] responseToken)
   {
      this.responseToken = responseToken;
   }

   public byte[] getMechListMIC()
   {
      return mechListMIC;
   }

   public void setMechListMIC(byte[] mechListMIC)
   {
      this.mechListMIC = mechListMIC;
   }

   @Override
   public void writeTo(final OutputStream os) throws IOException
   {
      // TODO Auto-generated method stub
      
   }

   
}
