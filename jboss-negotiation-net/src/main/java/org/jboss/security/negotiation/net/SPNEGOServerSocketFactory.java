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

import javax.net.ServerSocketFactory;

import org.jboss.logging.Logger;

/**
 * An implementation of {@link ServerSocketFactory} that uses {@link SPNEGOServerSocket} as 
 * the sockets.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class SPNEGOServerSocketFactory extends ServerSocketFactory
{

   private String securityDomain = "other";
   
   private String hostSecurityDomain = "host";
   
   private static Logger log = Logger.getLogger(SPNEGOServerSocketFactory.class);

   /**
    * Default constructor.
    */
   public SPNEGOServerSocketFactory()
   {
      super();
      if (log.isTraceEnabled())
         log.trace("Creating " + this.getClass().getName());
   }
   
   /**
    * Constructor that sets the security domain
    * 
    * @param securityDomain
    */
   public SPNEGOServerSocketFactory(String securityDomain, String hostSecurityDomain)
   {
      this();
      if (log.isTraceEnabled())
         log.trace("Setting security domain: " + securityDomain + ". Setting host security domain: " + hostSecurityDomain);
      this.securityDomain = securityDomain;
      this.hostSecurityDomain = hostSecurityDomain;
   }

   /**
    * Some resources require this static getDefault method
    * 
    * @return an instance of {@link SPNEGOServerSocketFactory}
    */
   public static ServerSocketFactory getDefault()
   {
      return new SPNEGOServerSocketFactory();
   }

   /**
    * @see ServerSocketFactory#createServerSocket()
    */
   public ServerSocket createServerSocket() throws IOException
   {
      SPNEGOServerSocket socket = new SPNEGOServerSocket();
      socket.setSecurityDomain(securityDomain);
      socket.setHostSecurityDomain(hostSecurityDomain);
      return socket;
   }

   /**
    * @see ServerSocketFactory#createServerSocket(int)
    */
   public ServerSocket createServerSocket(int port) throws IOException
   {
      SPNEGOServerSocket socket = new SPNEGOServerSocket(port);
      socket.setSecurityDomain(securityDomain);
      socket.setHostSecurityDomain(hostSecurityDomain);
      return socket;
   }

   /**
    * @see ServerSocketFactory#createServerSocket(int, int))
    */
   public ServerSocket createServerSocket(int port, int backlog) throws IOException
   {
      SPNEGOServerSocket socket = new SPNEGOServerSocket(port, backlog);
      socket.setSecurityDomain(securityDomain);
      socket.setHostSecurityDomain(hostSecurityDomain);
      return socket;
   }

   /**
    * @see ServerSocketFactory#createServerSocket(int, int, InetAddress))
    */
   public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException
   {
      SPNEGOServerSocket socket = new SPNEGOServerSocket(port, backlog, ifAddress);
      socket.setSecurityDomain(securityDomain);
      socket.setHostSecurityDomain(hostSecurityDomain);
      return socket;
   }

}
