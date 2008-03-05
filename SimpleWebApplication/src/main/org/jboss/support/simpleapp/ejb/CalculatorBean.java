/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2007, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.support.simpleapp.ejb;

import javax.ejb.SessionBean;
import javax.ejb.SessionContext;

import org.apache.log4j.Logger;

/**
 * The Calculator EJB implementation.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class CalculatorBean implements SessionBean
{

   private static final long serialVersionUID = -4924100303363049831L;

   private static final Logger log = Logger.getLogger(CalculatorBean.class);

   private SessionContext sessionContext;

   public void ejbCreate()
   {
   }

   public int add(final int a, final int b)
   {      
      log.info("Caller Principal " + sessionContext.getCallerPrincipal());

      return a + b;
   }

   public void ejbActivate()
   {
   }

   public void ejbPassivate()
   {
   }

   public void ejbRemove()
   {
   }

   public void setSessionContext(final SessionContext sessionContext)
   {
      this.sessionContext = sessionContext;
   }

}
