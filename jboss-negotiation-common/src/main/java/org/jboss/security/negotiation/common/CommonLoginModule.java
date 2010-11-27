/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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

import java.security.Principal;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import org.jboss.security.auth.spi.AbstractServerLoginModule;

/**
 * A base login module for the other login modules within
 * JBoss Negotiation. 
 * 
 * @author darran.lofthouse@jboss.com
 * @since 27th November 2010
 */
public abstract class CommonLoginModule extends AbstractServerLoginModule
{

   /*
    * Module State
    */
   /** The login identity */
   private Principal identity;

   /** The proof of login identity */
   private char[] credential;

   @Override
   protected Principal getIdentity()
   {
      return identity;
   }
   
   protected void setIdentity(final Principal identity)
   {
      this.identity = identity;
   }
   
   protected char[] getCredential()
   {
      return credential;
   }
   
   /**
    * Either retrieve existing values based on useFirstPass or use 
    * CallBackHandler to obtain the values.
    */
   protected void processIdentityAndCredential() throws LoginException
   {
      if (super.login() == true)
      {
         Object username = sharedState.get("javax.security.auth.login.name");
         if (username instanceof Principal)
            identity = (Principal) username;
         else
         {
            String name = username.toString();
            try
            {
               identity = createIdentity(name);
            }
            catch (Exception e)
            {
               if (log.isDebugEnabled())
                  log.debug("Failed to create principal", e);
               throw new LoginException("Failed to create principal: " + e.getMessage());
            }
         }
         // We have no further use for a credential so no need to retrieve it.
      }
      else
      {
         try
         {
            NameCallback nc = new NameCallback("User name: ", "guest");
            PasswordCallback pc = new PasswordCallback("Password: ", false);
            Callback[] callbacks =
            {nc, pc};

            callbackHandler.handle(callbacks);
            String username = nc.getName();
            identity = createIdentity(username);
            credential = pc.getPassword();
            pc.clearPassword();
         }
         catch (Exception e)
         {
            LoginException le = new LoginException("Unable to obtain username/credential");
            le.initCause(e);
            throw le;
         }

      }
   }

}
