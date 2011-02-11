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
package org.jboss.security.negotiation.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.jboss.logging.Logger;
import org.jboss.security.auth.callback.SecurityAssociationHandler;

/**
 * An implementation of {@link Socket} that tries to establish a {@link GSSContext}
 * when connecting to a {@link ServerSocket}
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class SPNEGOSocket extends Socket
{

   protected static Logger log = Logger.getLogger(SPNEGOSocket.class);

   private LoginContext lc;

   /**
    * @see Socket#Socket()
    */
   public SPNEGOSocket()
   {
      super();
      if (log.isTraceEnabled())
         log.trace("Creating " + this.getClass().getName());
   }

   /**
    * @see Socket#Socket(InetAddress, int, InetAddress, int)
    */
   public SPNEGOSocket(InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException
   {
      super(address, port, localAddr, localPort);
   }

   /**
    * @see Socket#Socket(InetAddress, int)
    */
   public SPNEGOSocket(InetAddress address, int port) throws IOException
   {
      super(address, port);
   }

   /**
    * @see Socket#Socket(String, int, InetAddress, int)
    */
   public SPNEGOSocket(String host, int port, InetAddress localAddr, int localPort) throws IOException
   {
      super(host, port, localAddr, localPort);
   }

   /**
    * @see Socket#Socket(String, int)
    */
   public SPNEGOSocket(String host, int port) throws UnknownHostException, IOException
   {
      super(host, port);
   }

   /**
    * @see Socket#connect(SocketAddress)
    */
   public void connect(SocketAddress endpoint) throws IOException
   {
      super.connect(endpoint);
   }

   /**
    * Tries to establish a {@link GSSContext} with the server using the tokens.
    * 
    * @see Socket#connect(SocketAddress, int)
    */
   public void connect(SocketAddress endpoint, int timeout) throws IOException
   {
      boolean TRACE = log.isTraceEnabled();
      if (TRACE)
         log.trace(this.getClass().getName() + ".connect()");
      super.connect(endpoint, timeout);

      Subject subject = null;
      try
      {
         if (TRACE)
            log.trace("Invoking login");
         subject = login();
         if (TRACE)
            log.trace("Login was successful");
      }
      catch (LoginException le)
      {
         log.error("Failed to login: " + le.getMessage(), le);
      }
      if (subject != null)
      {
         if (TRACE)
            log.trace("Running PrivilegedAction");
         PrivilegedAction<Object> action = getPrivilegedAction();
         Subject.doAs(subject, action);
      }
      try
      {
         if (TRACE)
            log.trace("Invoking logout");
         logout();
         if (TRACE)
            log.trace("Logout was successful");
      }
      catch (LoginException le)
      {
         log.error("Failed to logout: " + le.getMessage(), le);
      }
   }

   /**
    * Performs a JAAS login on the client side.
    *  
    * @return a {@link Subject}
    * @throws LoginException if the login fails
    */
   protected Subject login() throws LoginException
   {
      String securityDomainName = SecurityActions.getClientSecurityDomain();
      lc = new LoginContext(securityDomainName, new SecurityAssociationHandler());
      lc.login();
      return lc.getSubject();
   }

   /**
    * Performs a JAAS logout on the client side.
    * 
    * @throws LoginException if the logout fails
    */
   protected void logout() throws LoginException
   {
      if (lc != null)
         lc.logout();
   }

   /**
    * Instantiates a {@link PrivilegedAction}. 
    * 
    * @return {@link PrivilegedAction} implementation that will establish the {@link GSSContext}
    */
   protected PrivilegedAction<Object> getPrivilegedAction()
   {
      return new InitSPNEGOContextAction(this, lc);
   }

}
