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

import static org.apache.catalina.authenticator.Constants.FORM_ACTION;
import static org.apache.catalina.authenticator.Constants.FORM_PASSWORD;
import static org.apache.catalina.authenticator.Constants.FORM_PRINCIPAL_NOTE;
import static org.apache.catalina.authenticator.Constants.FORM_USERNAME;
import static org.apache.catalina.authenticator.Constants.SESS_PASSWORD_NOTE;
import static org.apache.catalina.authenticator.Constants.SESS_USERNAME_NOTE;
import static org.apache.catalina.authenticator.Constants.REQ_SSOID_NOTE;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Principal;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.CharChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.jboss.logging.Logger;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.jboss.servlet.http.HttpEvent;
import org.picketbox.commons.cipher.Base64;

/**
 * An authenticator to manage Negotiation based authentication in connection with the
 * Negotiation login module.
 *
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class NegotiationAuthenticator extends FormAuthenticator
{

   public static final String BASIC_KEY =  NegotiationAuthenticator.class.getName() + ".BasicAuthFallBack";

   private static final Logger log = Logger.getLogger(NegotiationAuthenticator.class);

   private static final String NEGOTIATE = "Negotiate";

   private static final String BASIC = "Basic";

   private static final String NEGOTIATION_CONTEXT = "NEGOTIATION_CONTEXT";

   private static final String DELEGATION_CREDENTIAL = "DELEGATION_CREDENTIAL";

   private static final String FORM_METHOD = "FORM";

   protected String getNegotiateScheme()
   {
      return NEGOTIATE;
   }

   protected String getBasicScheme(){
       return BASIC;
   }

   @Override
   public boolean authenticate(final Request request, final HttpServletResponse response, final LoginConfig config)
         throws IOException
   {

      boolean DEBUG = log.isDebugEnabled();
      log.trace("Authenticating user");

      Principal principal = request.getUserPrincipal();
      String ssoId = (String) request.getNote(REQ_SSOID_NOTE);
      if (principal != null)
      {
         if (log.isTraceEnabled())
            log.trace("Already authenticated '" + principal.getName() + "'");

         // Associate the session with any existing SSO session
         if (ssoId != null)
            associate(ssoId, request.getSessionInternal(true));

         // Is this the re-submit of the original request URI after successful
         // authentication?  If so, forward the *original* request instead.
         if( matchRequest(request) )
         {
            Session session = request.getSessionInternal(true);
            log.trace("Restore request from session '"
                       + session.getIdInternal()
                       + "'");
            restoreRequest(request, session);
         }

         return true;
      }

      // Is there an SSO session against which we can try to reauthenticate?
      if (ssoId != null) {
          log.trace("SSO Id " + ssoId + " set; attempting " + "reauthentication");
          // Try to reauthenticate using data cached by SSO.  If this fails,
          // either the original SSO logon was of DIGEST or SSL (which
          // we can't reauthenticate ourselves because there is no
          // cached username and password), or the realm denied
          // the user's reauthentication for some reason.
          // In either case we have to prompt the user for a logon */
          if (reauthenticateFromSSO(ssoId, request))
              return true;
      }

      String contextPath = request.getContextPath();
      String requestURI = request.getDecodedRequestURI();
      boolean loginAction = requestURI.startsWith(contextPath) && requestURI.endsWith(FORM_ACTION);
      if (loginAction)
      {
         Realm realm = context.getRealm();
         String username = request.getParameter(FORM_USERNAME);
         String password = request.getParameter(FORM_PASSWORD);
         principal = realm.authenticate(username, password);
         if (principal == null)
         {
            RequestDispatcher disp = context.getServletContext().getRequestDispatcher(config.getErrorPage());
            try
            {
               disp.forward(request.getRequest(), response);
            }
            catch (ServletException e)
            {
               IOException ex = new IOException("Unable to forward to error page.");
               ex.initCause(e);

               throw ex;
            }
            return false;
         }

         Session session = request.getSessionInternal();
         requestURI = savedRequestURL(session);

         session.setNote(FORM_PRINCIPAL_NOTE, principal);
         session.setNote(SESS_USERNAME_NOTE, username);
         session.setNote(SESS_PASSWORD_NOTE, password);

         register(request, response, principal, FORM_METHOD, username, password);
         response.sendRedirect(response.encodeRedirectURL(requestURI));

         return false;
      }

      String negotiateScheme = getNegotiateScheme();

      if (DEBUG)
      {
         log.debug("Header - " + request.getHeader("Authorization"));
      }
      String authHeader = request.getHeader("Authorization");

      if (authHeader == null)
      {
         log.debug("No Authorization Header, initiating negotiation");
         initiateNegotiation(request, response, config);

         return false;
      }
      else if (authHeader.startsWith(negotiateScheme + " ") == false)
      {
          final String basicScheme = getBasicScheme();
          if (authHeader.startsWith(basicScheme + " ")) {

              MessageBytes messagebytes = request.getCoyoteRequest().getMimeHeaders().getValue("Authorization");
              messagebytes.toBytes();
              ByteChunk byteChunk = messagebytes.getByteChunk();

              boolean successfulAuthenticated = false;
              if (byteChunk.startsWithIgnoreCase(basicScheme + " ", 0)) {
                int offsetLength = basicScheme.length() + 1;
                byteChunk.setOffset(byteChunk.getOffset() + offsetLength);
                CharChunk charChunk = messagebytes.getCharChunk();
                org.apache.catalina.util.Base64.decode(byteChunk, charChunk);

                successfulAuthenticated = handleBasic(request, response, charChunk);

                byteChunk.setOffset(byteChunk.getOffset() - offsetLength);
                return successfulAuthenticated;
              }
          }
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

      String username = negotiationContext.getUsername();
      if (username == null || username.length() == 0)
      {
         username = session.getId() + "_" + String.valueOf(System.currentTimeMillis());
         negotiationContext.setUsername(username);
      }
      String authenticationMethod = "";
      try
      {
         // Set the ThreadLocal association.
         negotiationContext.associate();

         MessageFactory mf = MessageFactory.newInstance();
         if (mf.accepts(authTokenIS) == false)
         {
        	 if (basicSupported())
        	 {
        	     initiateBasic(request,response,config);
                 response.sendError(Response.SC_UNAUTHORIZED);
                 response.flushBuffer();
                 return false;
        	 }
        	 throw new IOException("Unsupported negotiation mechanism.");
         }

         NegotiationMessage requestMessage = mf.createMessage(authTokenIS);

         if ("NTLM".equals(requestMessage.getMessageType())) {
        	 if (basicSupported())
        	 {
        	     initiateBasic(request,response,config);
                 response.sendError(Response.SC_UNAUTHORIZED);
                 response.flushBuffer();
                 return false;
        	 }
         }

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
         // Instead of returning a 401 here...attempt to fallback to form, otherwise return a 401
         log.debug("SPNEGO based authentication failed...initiating negotiation");
         initiateNegotiation(request, response, config);
      }
      else
      {
         Object schemeContext = negotiationContext.getSchemeContext();
         if (schemeContext instanceof GSSContext)
         {
            GSSContext gssContext = (GSSContext) schemeContext;
            if (gssContext.getCredDelegState())
            {
               try
               {
                  GSSCredential delegCredential = gssContext.getDelegCred();
                  session.setNote(DELEGATION_CREDENTIAL, delegCredential);
               }
               catch (GSSException e)
               {
                  log.warn("Unable to obtain delegation credential.", e);
               }
            }
         }

         register(request, response, principal, authenticationMethod, username, null);
      }

      return (principal != null);
   }

   private boolean basicSupported() {
	   return Boolean.parseBoolean(context.findParameter(BASIC_KEY));
   }

    /**
     * @param config
     * @param response
     * @param request
     * @throws IOException
     *
     */
    private void initiateBasic(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        StringBuilder basicHeader = new StringBuilder();
        basicHeader.append(getBasicScheme());
        basicHeader.append(" realm=\"");
        if (config.getRealmName() == null) {
            basicHeader.append(request.getServerName());
            basicHeader.append(':');
            basicHeader.append(Integer.toString(request.getServerPort()));
        } else {
            basicHeader.append(config.getRealmName().toUpperCase());
        }
        basicHeader.append("\"");
        response.addHeader("WWW-Authenticate", basicHeader.toString());// L-Bank
    }

    protected boolean handleBasic(Request request, HttpServletResponse response, CharChunk charchunk) {
          String username;
          String password;
          username = null;
          password = null;
          int i = charchunk.indexOf(':');
          if (i < 0) {
              username = charchunk.toString();
          } else {
              char ac[] = charchunk.getBuffer();
              username = new String(ac, 0, i);
              password = new String(ac, i + 1, charchunk.getEnd() - i - 1);
          }
          try {
              Realm realm = context.getRealm();
              Principal principal = realm.authenticate(username, password);

              if (principal == null) {
                  response.sendError(Response.SC_UNAUTHORIZED);
                  return false;
              }

              register(request, response, principal, getBasicScheme(), username, password);
              return true;

          } catch (Exception e) {
              log.info("Could not verify password - wrong password given or maybe LoginModule is misconfigured!", e);
              return false;
          }
      }

   private void initiateNegotiation(final Request request, final HttpServletResponse response, final LoginConfig config)
         throws IOException
   {
      String loginPage = config.getLoginPage();
      if (loginPage != null)
      {
         // TODO - Logic to cache and restore request.
         ServletContext servletContext = context.getServletContext();
         RequestDispatcher disp = servletContext.getRequestDispatcher(loginPage);

         try
         {
            Session session = request.getSessionInternal();
            saveRequest(request, session);

            disp.include(request.getRequest(), response);
            response.setHeader("WWW-Authenticate", getNegotiateScheme());
            response.setStatus(Response.SC_UNAUTHORIZED);
            response.setContentType("text/html");
         }
         catch (ServletException e)
         {
            IOException ex = new IOException("Unable to include loginPage");
            ex.initCause(e);

            throw ex;
         }

      }
      else
      {
         response.setHeader("WWW-Authenticate", getNegotiateScheme());
         if (basicSupported()) {
        	 initiateBasic(request, response, config);
         }

         response.sendError(Response.SC_UNAUTHORIZED);
      }

      response.flushBuffer();
   }

   @Override
   public void setNext(final Valve nextValve)
   {
      super.setNext(new WrapperValve(nextValve));
   }

   private static class WrapperValve implements Valve
   {

      private Valve nextValve;

      private WrapperValve(final Valve nextValve)
      {
         this.nextValve = nextValve;
      }

      public String getInfo()
      {
         return nextValve.getInfo();
      }

      public Valve getNext()
      {
         return nextValve;
      }

      public void setNext(Valve valve)
      {
         nextValve = valve;

      }

      public void backgroundProcess()
      {
         nextValve.backgroundProcess();
      }

      public void invoke(Request request, Response response) throws IOException, ServletException
      {
         Session session = request.getSessionInternal();
         GSSCredential credential = (GSSCredential) session.getNote(DELEGATION_CREDENTIAL);
         try
         {
            DelegationCredentialManager.setDelegationCredential(credential);
            nextValve.invoke(request, response);
         }
         finally
         {
            DelegationCredentialManager.removeDelegationCredential();
         }
      }

      public void event(Request request, Response response, HttpEvent event) throws IOException, ServletException
      {
         nextValve.event(request, response, event);
      }

   }

   private static class DelegationCredentialManager extends DelegationCredentialContext
   {

      private static void setDelegationCredential(final GSSCredential credential)
      {
         currentCredential.set(credential);
      }

      private static void removeDelegationCredential()
      {
         currentCredential.remove();
      }

   }

}
