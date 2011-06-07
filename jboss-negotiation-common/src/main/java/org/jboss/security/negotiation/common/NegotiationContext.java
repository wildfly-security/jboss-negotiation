/*
 * JBoss, Home of Professional Open Source.
 * 
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
package org.jboss.security.negotiation.common;

import org.jboss.logging.Logger;
import org.jboss.security.negotiation.NegotiationMessage;

/**
 * The NegotiationContext is the holder to contain the state of the current authentication 
 * process and is used to transfer data between the authenticator valve and the login 
 * module.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class NegotiationContext
{

   private static final Logger log = Logger.getLogger(NegotiationContext.class);

   private static final ThreadLocal<NegotiationContext> negotiationContext = new ThreadLocal<NegotiationContext>();

   private String username;
   
   private boolean authenticated = false;

   private String authenticationMethod;

   private NegotiationMessage requestMessage = null;

   private NegotiationMessage responseMessage = null;

   private Object schemeContext = null;

   public static NegotiationContext getCurrentNegotiationContext()
   {
      return negotiationContext.get();
   }

   public void associate()
   {
      if (log.isTraceEnabled())
         log.trace("associate " + this.hashCode());
      negotiationContext.set(this);
   }

   /**
    * Clear any information that is not required to be retained between invocations.
    */
   public void clear()
   {
      if (log.isTraceEnabled())
         log.trace("clear " + this.hashCode());
      requestMessage = null;
      responseMessage = null;
      negotiationContext.remove();
   }

   public String getUsername()
   {
      return username;
   }

   public void setUsername(String username)
   {
      this.username = username;
   }

   public boolean isAuthenticated()
   {
      return authenticated;
   }

   public void setAuthenticated(boolean authenticated)
   {
      this.authenticated = authenticated;
   }

   public String getAuthenticationMethod()
   {
      return authenticationMethod;
   }

   public void setAuthenticationMethod(String authenticationMethod)
   {
      this.authenticationMethod = authenticationMethod;
   }

   public NegotiationMessage getRequestMessage()
   {
      return requestMessage;
   }

   public void setRequestMessage(NegotiationMessage requestMessage)
   {
      this.requestMessage = requestMessage;
   }

   public NegotiationMessage getResponseMessage()
   {
      return responseMessage;
   }

   public void setResponseMessage(NegotiationMessage responseMessage)
   {
      this.responseMessage = responseMessage;
   }

   public Object getSchemeContext()
   {
      return schemeContext;
   }

   public void setSchemeContext(Object schemeContext)
   {
      this.schemeContext = schemeContext;
   }

}
