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

import static org.jboss.security.negotiation.Constants.KERBEROS_V5;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.jboss.security.SimpleGroup;
import org.jboss.security.negotiation.Constants;
import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.security.negotiation.common.CommonLoginModule;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInit;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTarg;
import org.jboss.security.negotiation.spnego.encoding.SPNEGOMessage;

/**
 * Login module to work in conjunction with SPNEGOAuthenticator to handle the 
 * authentication requirements. 
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class SPNEGOLoginModule extends CommonLoginModule
{

   /*
    * Configuration Option Constants 
    */

   // If true drop the @REALM from the identity.
   private static final String REMOVE_REALM_FROM_PRINCIPAL = "removeRealmFromPrincipal";

   // The security domain to authenticate to obtain the servers identity.
   private static final String SERVER_SECURITY_DOMAIN = "serverSecurityDomain";

   // The security domain to delegate username/password authentication to.
   private static final String USERNAME_PASSWORD_DOMAIN = "usernamePasswordDomain";

   /*
    *  General Constants
    */

   private static final String SPNEGO = "SPNEGO";

   private static final Oid kerberos = KERBEROS_V5;

   /*
    * Configuration Options
    */

   private boolean removeRealmFromPrincipal;

   // TODO - Pick a name for a default domain?
   private String serverSecurityDomain;

   private String usernamePasswordDomain;

   /*
    * Module State
    */

   private LoginContext serverLoginContext = null;

   @Override
   public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map sharedState,
         final Map options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      String temp;
      // Which security domain to authenticate the server.
      serverSecurityDomain = (String) options.get(SERVER_SECURITY_DOMAIN);
      // Which security domain to delegate username/password authentication to.
      usernamePasswordDomain = (String) options.get(USERNAME_PASSWORD_DOMAIN);
      temp = (String) options.get(REMOVE_REALM_FROM_PRINCIPAL);
      removeRealmFromPrincipal = Boolean.valueOf(temp);
      if (removeRealmFromPrincipal == false && principalClassName == null)
      {
         principalClassName = KerberosPrincipal.class.getName();
      }
      if (log.isDebugEnabled())
      {
         log.debug("removeRealmFromPrincipal=" + removeRealmFromPrincipal);
         log.debug("serverSecurityDomain=" + serverSecurityDomain);
         log.debug("usernamePasswordDomain=" + usernamePasswordDomain);
      }
   }

   @Override
   public boolean login() throws LoginException
   {
      boolean TRACE = log.isTraceEnabled();
      if (super.login() == true)
      {
         log.debug("super.login()==true");
         return true;
      }

      super.loginOk = false;

      Object result = innerLogin();

      if (TRACE)
         log.trace("Result - " + result);

      if (result instanceof Boolean)
      {
         if (Boolean.TRUE.equals(result))
         {
            super.loginOk = true;
            if (getUseFirstPass() == true)
            {
               Principal identity = getIdentity();
               String userName = identity.getName();
               if (log.isDebugEnabled())
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

      if (TRACE)
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

   protected Object innerLogin() throws LoginException
   {
      NegotiationContext negotiationContext = NegotiationContext.getCurrentNegotiationContext();

      if (negotiationContext == null)
      {
         if (usernamePasswordDomain == null)
         {
            throw new LoginException("No NegotiationContext and no usernamePasswordDomain defined.");
         }

         return usernamePasswordLogin();
      }
      else
      {
         return spnegoLogin(negotiationContext);
      }

   }

   private Object usernamePasswordLogin() throws LoginException
   {
      log.debug("Falling back to username/password authentication");

      LoginContext lc = new LoginContext(usernamePasswordDomain, callbackHandler);
      lc.login();

      Subject userSubject = lc.getSubject();
      Set principals = userSubject.getPrincipals();
      if (principals.isEmpty())
      {
         throw new LoginException("No principal returned after login.");
      }
      else if (principals.size() > 1)
      {
         log.warn("Multiple principals returned, using first principal in set.");
      }

      Principal identity = (Principal) principals.iterator().next();
      setIdentity(identity);

      return Boolean.TRUE;
   }

   private Object spnegoLogin(NegotiationContext negotiationContext) throws LoginException
   {
      NegotiationMessage requestMessage = negotiationContext.getRequestMessage();
      if (requestMessage instanceof SPNEGOMessage == false && requestMessage instanceof KerberosMessage == false)
      {
         String message = "Unsupported negotiation mechanism '" + requestMessage.getMessageType() + "'.";
         log.warn(message);
         throw new LoginException(message);
      }

      try
      {
         Subject server = getServerSubject();
         AcceptSecContext action = new AcceptSecContext(negotiationContext);
         Object result = Subject.doAs(server, action);

         return result;
      }
      finally
      {
         if (serverLoginContext != null)
         {
            // TODO - We may not actually want to logout as if we use cache this may clear it,
            serverLoginContext.logout();
         }
      }

   }
   

   @Override
   protected Principal createIdentity(final String username) throws Exception
   {
      if (removeRealmFromPrincipal)
      {
         return super.createIdentity(username.substring(0, username.indexOf("@")));
      }
      else
      {
         return super.createIdentity(username);
      }

   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {

      Group roles = new SimpleGroup("Roles");
      Group callerPrincipal = new SimpleGroup("CallerPrincipal");
      Group[] groups =
      {roles, callerPrincipal};
      callerPrincipal.addMember(getIdentity());
      return groups;
   }

   protected Subject getServerSubject() throws LoginException
   {
      LoginContext lc = new LoginContext(serverSecurityDomain);
      lc.login();
      // Cache so we can log out.
      serverLoginContext = lc;

      Subject serverSubject = serverLoginContext.getSubject();
      if (log.isDebugEnabled())
      {
         log.debug("Subject = " + serverSubject);
         log.debug("Logged in '" + serverSecurityDomain + "' LoginContext");
      }

      return serverSubject;
   }

   private class AcceptSecContext implements PrivilegedAction
   {

      private final NegotiationContext negotiationContext;

      public AcceptSecContext(final NegotiationContext negotiationContext)
      {
         this.negotiationContext = negotiationContext;
      }

      public Object run()
      {
         boolean DEBUG = log.isDebugEnabled();
         try
         {
            // The message type will have already been checked before this point so we know it is
            // a SPNEGO message.
            NegotiationMessage requestMessage = negotiationContext.getRequestMessage();

            // TODO - Ensure no way to fall through with gssToken still null.
            byte[] gssToken = null;
            if (requestMessage instanceof NegTokenInit)
            {
               NegTokenInit negTokenInit = (NegTokenInit) requestMessage;
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
                  negotiationContext.setResponseMessage(negTokenTarg);

                  return Boolean.FALSE;
               }

            }
            else if (requestMessage instanceof NegTokenTarg)
            {
               NegTokenTarg negTokenTarg = (NegTokenTarg) requestMessage;

               gssToken = negTokenTarg.getResponseToken();
            }
            else if (requestMessage instanceof KerberosMessage)
            {
               KerberosMessage kerberosMessage = (KerberosMessage) requestMessage;
               
               gssToken = kerberosMessage.getToken();
            }

            Object schemeContext = negotiationContext.getSchemeContext();
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
               
               negotiationContext.setSchemeContext(gssContext);
            }

            if (gssContext.isEstablished())
            {
               log.warn("Authentication was performed despite already being authenticated!");

               // TODO - Refactor to only do this once.
               setIdentity(new KerberosPrincipal(gssContext.getSrcName().toString()));

               if (DEBUG)
               {
                  log.debug("context.getCredDelegState() = " + gssContext.getCredDelegState());
                  log.debug("context.getMutualAuthState() = " + gssContext.getMutualAuthState());
                  log.debug("context.getSrcName() = " + gssContext.getSrcName().toString());
               }

               negotiationContext.setAuthenticationMethod(SPNEGO);
               negotiationContext.setAuthenticated(true);

               return Boolean.TRUE;
            }

            byte[] respToken = gssContext.acceptSecContext(gssToken, 0, gssToken.length);

            if (respToken != null)
            {
               NegotiationMessage response;
               if (requestMessage instanceof KerberosMessage)
               {
                  response = new KerberosMessage(Constants.KERBEROS_V5, respToken);
               }
               else
               {
                  NegTokenTarg negTokenTarg = new NegTokenTarg();
                  negTokenTarg.setResponseToken(respToken);

                  response = negTokenTarg;
               }

               negotiationContext.setResponseMessage(response);
            }

            if (gssContext.isEstablished() == false)
            {
               return Boolean.FALSE;
            }
            else
            {
               setIdentity(createIdentity(gssContext.getSrcName().toString()));

               if (DEBUG)
               {
                  log.debug("context.getCredDelegState() = " + gssContext.getCredDelegState());
                  log.debug("context.getMutualAuthState() = " + gssContext.getMutualAuthState());
                  log.debug("context.getSrcName() = " + gssContext.getSrcName().toString());
               }

               // TODO - Get these two in synch - maybe isAuthenticated based on an authentication method been set?
               negotiationContext.setAuthenticationMethod(SPNEGO);
               negotiationContext.setAuthenticated(true);
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
