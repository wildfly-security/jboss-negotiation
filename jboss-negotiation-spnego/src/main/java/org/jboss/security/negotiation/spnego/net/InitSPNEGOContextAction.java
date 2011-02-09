/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.negotiation.spnego.net;

import static org.jboss.security.negotiation.Constants.SPNEGO;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.jboss.logging.Logger;
import org.jboss.security.SecurityContext;

/**
 * A {@link PrivilegedAction} that establishes the {@link GSSContext} according to GSS API.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class InitSPNEGOContextAction implements PrivilegedAction<Object>
{
   
   protected static Logger log = Logger.getLogger(InitSPNEGOContextAction.class);
   
   private Socket socket;
   
   private LoginContext lc;

   /**
    * Default constructor
    * 
    * @param socket {@link Socket} used to exchange the tokens.
    * @param lc {@link LoginContext} with the authenticated Subject who will execute the action
    */
   InitSPNEGOContextAction(Socket socket, LoginContext lc)
   {
      this.socket = socket;
      this.lc = lc;
   }

   /**
    * @see PrivilegedAction#run()
    */
   public Object run()
   {
      boolean DEBUG = log.isDebugEnabled();
      byte[] token = new byte[0];
      GSSManager manager = GSSManager.getInstance();
      GSSContext context = null;
      try
      {
         DataInputStream inStream = new DataInputStream(socket.getInputStream());
         DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());

         Oid oid = SPNEGO;
         String nameStr = SecurityActions.getServerName();
         if (nameStr == null)
            throw new IllegalArgumentException("Server name must be set using the org.jboss.security.negotiation.server.principal system property");
         GSSName serverName = manager.createName(nameStr, null);
         context = manager.createContext(serverName, oid, null, GSSContext.DEFAULT_LIFETIME);
         while (!context.isEstablished())
         {
            token = context.initSecContext(token, 0, token.length);
            if (token != null)
            {
               if (DEBUG)
                  log.debug("Sending token of length " + token.length);
               outStream.writeInt(token.length);
               outStream.write(token);
               outStream.flush();
            }

            if (!context.isEstablished())
            {
               token = new byte[inStream.readInt()];
               if (DEBUG)
                  log.debug("Receiving token of length " + token.length);
               inStream.readFully(token);
            }
         }
         if (DEBUG)
            log.trace("GSSContext established");
         Subject subject = lc.getSubject();
         Principal principal = (Principal)subject.getPrincipals().iterator().next();
         try
         {
            setSecurityContext(principal, null, subject, "CLIENT");
         }
         catch (Exception e)
         {
            log.error("Error setting the SecurityContext: " + e.getMessage(), e);
         }
      }
      catch (GSSException gsse)
      {
         log.error("Error establishing GSSContext: " + gsse.getMessage(), gsse);
      }
      catch (IOException ioe)
      {
         log.error("Error reading/writing token: " + ioe.getMessage(), ioe);
      }
      finally
      {
         if (context != null)
         {
            try
            {
               context.dispose();
            }
            catch (GSSException gsse)
            {
               log.error("Error dispoing GSSContext: " + gsse.getMessage(), gsse);
            }
         }
      }
      return null;
   }
   
   /**
    * Performs JBoss specific security context association.
    * 
    * @param principal {@link Principal} of the user
    * @param credential Credentials of the user
    * @param subject {@link Subject} of the user
    * @param securityDomain Security domain of the context
    * @throws Exception if an error occurs while setting the security context
    */
   protected void setSecurityContext(Principal principal, Object credential, Subject subject, String securityDomain) throws Exception
   {
      SecurityContext sc = SecurityActions.createSecurityContext(principal, null, subject, securityDomain);
      SecurityActions.setSecurityContext(sc);
   }
}
