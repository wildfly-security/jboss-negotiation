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

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInit;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInitDecoder;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTarg;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTargDecoder;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTargEncoder;
import org.jboss.util.Base64;

/**
 * Login module to work in conjunction with SPNEGOAuthenticator to handle the 
 * authentication requirements. 
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class SPNEGOLoginModule extends AbstractServerLoginModule
{

   private static final Oid kerberos;

   // TODO - Pick a name for a default domain?
   private String serverSecurityDomain;

   private LoginContext serverLoginContext = null;

   private Principal identity = null;

   static
   {
      try
      {
         kerberos = new Oid("1.2.840.113554.1.2.2");
      }
      catch (GSSException e)
      {
         throw new RuntimeException("Unable to initialise Oid", e);
      }
   }

   @Override
   public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map sharedState,
         final Map options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      // Which security domain to authenticate the server.
      serverSecurityDomain = (String) options.get("serverSecurityDomain");
      log.debug("serverSecurityDomain=" + serverSecurityDomain);
   }

   @Override
   public boolean login() throws LoginException
   {
      if (super.login() == true)
      {
         log.debug("super.login()==true");
         return true;
      }

      super.loginOk = false;

      NegotiationContext spnegoContext = NegotiationContext.getCurrentSPNEGOContext();

      try
      {
         Subject server = getServerSubject();
         AcceptSecContext action = new AcceptSecContext(spnegoContext);
         Object result = Subject.doAs(server, action);

         log.trace("Result - " + result);

         if (result instanceof Boolean)
         {
            if (Boolean.TRUE.equals(result))
            {
               super.loginOk = true;
               if (getUseFirstPass() == true)
               {
                  String userName = identity.getName();
                  log.debug("Storing username '" + userName + "' and empty password");
                  // Add the username and a null password to the shared state map
                  sharedState.put("javax.security.auth.login.name", identity);
                  sharedState.put("javax.security.auth.login.password", "");
               }
            }
         }
         else if (result instanceof Exception)
         {
            Exception e = (Exception) result;
            log.error("Unable to authenticate", e);
            throw new LoginException("Unable to authenticate - " + e.getMessage());
         }

      }
      finally
      {
         if (serverLoginContext != null)
         {
            // TODO - We may not actually want to logout as if we use cache this may clear it,
            serverLoginContext.logout();
         }
      }

      log.trace("super.loginOk " + super.loginOk);
      if (super.loginOk == true)
      {
         return true;
      }
      else
      {
         throw new LoginException("Continuation Required.");

      }

   }

   @Override
   protected Principal getIdentity()
   {
      return identity;
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {

      Group roles = new SimpleGroup("Roles");
      Group callerPrincipal = new SimpleGroup("CallerPrincipal");
      Group[] groups =
      {roles, callerPrincipal};
      callerPrincipal.addMember(identity);
      return groups;
   }

   protected Subject getServerSubject() throws LoginException
   {
      LoginContext lc = new LoginContext(serverSecurityDomain);
      lc.login();
      // Cache so we can log out.
      serverLoginContext = lc;

      Subject serverSubject = serverLoginContext.getSubject();
      log.debug("Subject = " + serverSubject);
      log.debug("Logged in '" + serverSecurityDomain + "' LoginContext");

      return serverSubject;
   }

   private class AcceptSecContext implements PrivilegedAction
   {

      private final NegotiationContext spnegoContext;

      public AcceptSecContext(final NegotiationContext spnegoContext)
      {
         this.spnegoContext = spnegoContext;
      }

      public Object run()
      {
         try
         {
            String requestHeader = spnegoContext.getRequestHeader();
            byte[] reqToken = Base64.decode(requestHeader);

            MessageTrace.logRequestBase64(spnegoContext.getRequestHeader());
            MessageTrace.logRequestHex(reqToken);
            byte[] gssToken = null;

            // TODO - If Section from MY Code!!
            if (reqToken[0] == 0x60)
            {
               NegTokenInit negTokenInit = NegTokenInitDecoder.decode(reqToken);
               List<Oid> mechList = negTokenInit.getMechTypes();

               if (mechList.get(0).equals(kerberos))
               {
                  gssToken = negTokenInit.getMechToken();
               }
               else
               {
                  boolean kerberosSupported = false;

                  Iterator<Oid> it = mechList.iterator();
                  while (it.hasNext() && kerberosSupported == false)
                  {
                     kerberosSupported = it.next().equals(kerberos);
                  }

                  NegTokenTarg negTokenTarg = new NegTokenTarg();

                  if (kerberosSupported)
                  {
                     negTokenTarg.setNegResult(NegTokenTarg.ACCEPT_INCOMPLETE);
                     negTokenTarg.setSupportedMech(kerberos);
                  }
                  else
                  {
                     negTokenTarg.setNegResult(NegTokenTarg.REJECTED);
                  }

                  byte[] respSpnego = NegTokenTargEncoder.encode(negTokenTarg);
                  String respEncoded = Base64.encodeBytes(respSpnego);

                  MessageTrace.logResponseBase64(respEncoded);
                  MessageTrace.logResponseHex(respSpnego);

                  spnegoContext.setResponseHeader(respEncoded);

                  return Boolean.FALSE;
               }

            }
            else if (reqToken[0] == (byte) 0xa1)
            {
               NegTokenTarg negTokenTarg = NegTokenTargDecoder.decode(reqToken);

               gssToken = negTokenTarg.getResponseToken();
            }
            else
            {
               // TODO - Detect NTLM to specific error can be reported.
               throw new LoginException("Unsupported negotiation mechanism.");
            }

            Object schemeContext = spnegoContext.getSchemeContext();
            if (schemeContext != null && schemeContext instanceof GSSContext == false)
            {
               throw new IllegalStateException("The schemeContext is not a GSSContext");
            }

            GSSContext gssContext = (GSSContext) schemeContext;
            if (gssContext == null)
            {
               log.debug("Creating new GSSContext.");
               GSSManager manager = GSSManager.getInstance();
               gssContext = manager.createContext((GSSCredential) null);

               spnegoContext.setSchemeContext(gssContext);
            }

            if (gssContext.isEstablished())
            {
               log.warn("Authentication was performed despite already being authenticated!");
               identity = new KerberosPrincipal(gssContext.getSrcName().toString());

               log.debug("context.getCredDelegState() = " + gssContext.getCredDelegState());
               log.debug("context.getMutualAuthState() = " + gssContext.getMutualAuthState());
               log.debug("context.getSrcName() = " + gssContext.getSrcName().toString());

               spnegoContext.setAuthenticated(true);

               return Boolean.TRUE;
            }

            byte[] respToken = gssContext.acceptSecContext(gssToken, 0, gssToken.length);

            if (respToken != null)
            {
               NegTokenTarg negTokenTarg = new NegTokenTarg();
               negTokenTarg.setResponseToken(respToken);

               byte[] respSpnego = NegTokenTargEncoder.encode(negTokenTarg);
               String respEncoded = Base64.encodeBytes(respSpnego);

               MessageTrace.logResponseBase64(respEncoded);
               MessageTrace.logResponseHex(respSpnego);

               spnegoContext.setResponseHeader(respEncoded);
            }

            if (gssContext.isEstablished() == false)
            {
               return Boolean.FALSE;
            }
            else
            {
               identity = new KerberosPrincipal(gssContext.getSrcName().toString());

               log.debug("context.getCredDelegState() = " + gssContext.getCredDelegState());
               log.debug("context.getMutualAuthState() = " + gssContext.getMutualAuthState());
               log.debug("context.getSrcName() = " + gssContext.getSrcName().toString());

               spnegoContext.setAuthenticated(true);
               return Boolean.TRUE;
            }

         }
         catch (Exception e)
         {
            return e;
         }

      }
   }
}
