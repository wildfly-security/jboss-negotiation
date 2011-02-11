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
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import org.jboss.logging.Logger;

/**
 * An implementation of {@link SocketFactory} that uses {@link SPNEGOSocket} as
 * the sockets.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class SPNEGOSocketFactory extends SocketFactory
{

   private static Logger log = Logger.getLogger(SPNEGOSocketFactory.class);

   /**
    * Default constructor
    */
   public SPNEGOSocketFactory()
   {
      super();
      if (log.isTraceEnabled())
         log.trace("Creating " + this.getClass().getName());
   }

   /**
    * Some resources require this static getDefault method
    * 
    * @return an instance of {@link SPNEGOSocketFactory}
    */
   public static SocketFactory getDefault()
   {
      return new SPNEGOSocketFactory();
   }

   /**
    * @see SocketFactory#createSocket()
    */
   public Socket createSocket() throws IOException
   {
      return new SPNEGOSocket();
   }

   /**
    * @see SocketFactory#createSocket(String, int))
    */
   public Socket createSocket(String host, int port) throws IOException, UnknownHostException
   {
      return new SPNEGOSocket(host, port);
   }

   /**
    * @see SocketFactory#createSocket(InetAddress, int))
    */
   public Socket createSocket(InetAddress host, int port) throws IOException
   {
      return new SPNEGOSocket(host, port);
   }

   /**
    * @see SocketFactory#createSocket(String, int, InetAddress, int))
    */
   public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException,
         UnknownHostException
   {
      return new SPNEGOSocket(host, port, localHost, localPort);
   }

   /**
    * @see SocketFactory#createSocket(InetAddress, int, InetAddress, int))
    */
   public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
         throws IOException
   {
      return new SPNEGOSocket(address, port, localAddress, localPort);
   }

}
