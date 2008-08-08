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
package org.jboss.security.negotiation.spnego;

import java.io.IOException;
import java.security.Principal;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;
import org.jboss.security.negotiation.common.NegotiationContext;

/**
 * An authenticator to manage SPNEGO authentication in connection with the
 * SPNEGO login module.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class SPNEGOAuthenticator extends AuthenticatorBase
{

   private static final Logger log = Logger.getLogger(SPNEGOAuthenticator.class);

   private static final String SPNEGO = "SPNEGO";

   private static final String SPNEGO_CONTEXT = "SPNEGO_CONTEXT";

   @Override
   protected boolean authenticate(final Request request, final Response response, final LoginConfig config)
         throws IOException
   {
      log.trace("Authenticating user");

      Principal principal = request.getUserPrincipal();
      if (principal != null)
      {
         if (log.isTraceEnabled())
            log.trace("Already authenticated '" + principal.getName() + "'");
         return true;
      }

      log.info("Header - " + request.getHeader("Authorization"));
      String authHeader = request.getHeader("Authorization");
      if (authHeader == null)
      {
         log.debug("No Authorization Header, sending 401");
         response.setHeader("WWW-Authenticate", "Negotiate");
         response.sendError(401);

         return false;
      }
      else if (authHeader.startsWith("Negotiate ") == false)
      {
         throw new IOException("Invalid 'Authorization' header.");
      }

      Session session = request.getSessionInternal();
      NegotiationContext spnegoContext = (NegotiationContext) session.getNote(SPNEGO_CONTEXT);
      if (spnegoContext == null)
      {
         log.debug("Creating new SPNEGOContext");
         {
            spnegoContext = new NegotiationContext();
            session.setNote(SPNEGO_CONTEXT, spnegoContext);
         }
      }

      // TODO - Probably not good if session reused.
      //        Maybe create arbitary ID or use SSO ID.
      String username = session.getId();
      try
      {
         // Set the ThreadLocal association.
         spnegoContext.associate();
         spnegoContext.setRequestHeader(authHeader.substring(10));

         Realm realm = context.getRealm();

         principal = realm.authenticate(username, (String) null);

         if (log.isDebugEnabled())
            log.debug("authenticated principal = " + principal);

         String responseHeader = spnegoContext.getResponseHeader();
         if (responseHeader != null)
         {
            response.setHeader("WWW-Authenticate", "Negotiate " + responseHeader);
         }

      }
      finally
      {
         // Clear the headers and remove the ThreadLocal association.
         spnegoContext.clear();
      }

      if (principal == null)
      {
         response.sendError(Response.SC_UNAUTHORIZED);
      }
      else
      {
         register(request, response, principal, SPNEGO, username, null);
      }

      return (principal != null);
   }
}
