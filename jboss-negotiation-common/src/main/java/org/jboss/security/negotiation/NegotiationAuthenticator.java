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
package org.jboss.security.negotiation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Principal;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.picketbox.commons.cipher.Base64;

/**
 * An authenticator to manage Negotiation based authentication in connection with the
 * Negotiation login module.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class NegotiationAuthenticator extends AuthenticatorBase
{

   private static final Logger log = Logger.getLogger(NegotiationAuthenticator.class);

   private static final String NEGOTIATE = "Negotiate";

   private static final String NEGOTIATION_CONTEXT = "NEGOTIATION_CONTEXT";

   protected String getNegotiateScheme()
   {
      return NEGOTIATE;
   }

   @Override
   protected boolean authenticate(final Request request, final Response response, final LoginConfig config)
         throws IOException
   {

      boolean DEBUG = log.isDebugEnabled();
      log.trace("Authenticating user");

      Principal principal = request.getUserPrincipal();
      if (principal != null)
      {
         if (log.isTraceEnabled())
            log.trace("Already authenticated '" + principal.getName() + "'");
         return true;
      }

      String negotiateScheme = getNegotiateScheme();

      if (DEBUG)
         log.debug("Header - " + request.getHeader("Authorization"));
      String authHeader = request.getHeader("Authorization");
      if (authHeader == null)
      {

         log.debug("No Authorization Header, sending 401");
         response.setHeader("WWW-Authenticate", negotiateScheme);
         response.sendError(401);

         return false;
      }
      else if (authHeader.startsWith(negotiateScheme + " ") == false)
      {
         throw new IOException("Invalid 'Authorization' header.");
      }

      String authTokenBase64 = authHeader.substring(negotiateScheme.length() + 1);
      byte[] authToken = Base64.decode(authTokenBase64);
      ByteArrayInputStream authTokenIS = new ByteArrayInputStream(authToken);
      MessageTrace.logRequestBase64(authTokenBase64);
      MessageTrace.logRequestHex(authToken);

      Session session = request.getSessionInternal();
      NegotiationContext negotiationContext = (NegotiationContext) session.getNote(NEGOTIATION_CONTEXT);
      if (negotiationContext == null)
      {

         log.debug("Creating new NegotiationContext");
         negotiationContext = new NegotiationContext();
         session.setNote(NEGOTIATION_CONTEXT, negotiationContext);
      }

      String username = session.getId();
      String authenticationMethod = "";
      try
      {
         // Set the ThreadLocal association.
         negotiationContext.associate();

         MessageFactory mf = MessageFactory.newInstance();
         if (mf.accepts(authTokenIS) == false)
         {
            throw new IOException("Unsupported negotiation mechanism.");
         }

         NegotiationMessage requestMessage = mf.createMessage(authTokenIS);
         negotiationContext.setRequestMessage(requestMessage);

         Realm realm = context.getRealm();
         principal = realm.authenticate(username, (String) null);

         authenticationMethod = negotiationContext.getAuthenticationMethod();

         if (DEBUG && principal != null)
            log.debug("authenticated principal = " + principal);

         NegotiationMessage responseMessage = negotiationContext.getResponseMessage();
         if (responseMessage != null)
         {
            ByteArrayOutputStream responseMessageOS = new ByteArrayOutputStream();
            responseMessage.writeTo(responseMessageOS, true);
            String responseHeader = responseMessageOS.toString();

            MessageTrace.logResponseBase64(responseHeader);

            response.setHeader("WWW-Authenticate", negotiateScheme + " " + responseHeader);
         }

      }
      catch (NegotiationException e)
      {
         IOException ioe = new IOException("Error processing " + negotiateScheme + " header.");
         ioe.initCause(e);
         throw ioe;
      }
      finally
      {
         // Clear the headers and remove the ThreadLocal association.
         negotiationContext.clear();
      }

      if (principal == null)
      {
         response.sendError(Response.SC_UNAUTHORIZED);
      }
      else
      {
         register(request, response, principal, authenticationMethod, username, null);
      }

      return (principal != null);
   }
}
