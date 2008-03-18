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

import java.util.LinkedList;
import java.util.List;

import org.ietf.jgss.Oid;

/**
 * Representation of NegTokenInit.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class NegTokenInit
{

   private Oid messageOid;

   private final List<Oid> mechTypes = new LinkedList<Oid>();

   private byte[] reqFlags;

   private byte[] mechToken;

   private byte[] mechListMIC;

   public Oid getMessageOid()
   {
      return messageOid;
   }

   public void setMessageOid(final Oid messageOid)
   {
      this.messageOid = messageOid;
   }

   public List<Oid> getMechTypes()
   {
      return mechTypes;
   }

   public void addMechType(final Oid mechType)
   {
      mechTypes.add(mechType);
   }

   public byte[] getMechToken()
   {
      return mechToken;
   }

   
   public byte[] getReqFlags()
   {
      return reqFlags;
   }

   public void setReqFlags(byte[] reqFlags)
   {
      this.reqFlags = reqFlags;
   }

   public void setMechToken(byte[] mechToken)
   {
      this.mechToken = mechToken;
   }

   public byte[] getMechListMIC()
   {
      return mechListMIC;
   }

   public void setMechListMIC(byte[] mechListMIC)
   {
      this.mechListMIC = mechListMIC;
   }

}
