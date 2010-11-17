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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Principal;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.jboss.logging.Logger;
import org.jboss.mx.util.MBeanServerLocator;
import org.jboss.security.SecurityConstants;
import org.jboss.security.auth.callback.SecurityAssociationHandler;
import org.jboss.security.negotiation.MessageFactory;
import org.jboss.security.negotiation.NegotiationException;
import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInit;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTarg;
import org.jboss.security.negotiation.spnego.encoding.TokenParser;
import org.jboss.security.plugins.JaasSecurityManager;

/**
 *  An implementation of {@link ServerSocket} that tries to establish a {@link GSSContext}
 *  when a {@link Socket} connects to it.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class SPNEGOServerSocket extends ServerSocket
{

   private static Logger log = Logger.getLogger(SPNEGOServerSocket.class);
   
   private Principal principal;
   
   private String securityDomain;
   
   private String hostSecurityDomain;
   
   private LoginContext lc;
   
   private Subject subject;

   /**
    * @see ServerSocket#ServerSocket()
    */
   public SPNEGOServerSocket() throws IOException
   {
      super();
      if (log.isTraceEnabled())
         log.trace("Creating " + this.getClass().getName());
   }

   /**
    * @see ServerSocket#ServerSocket(int)
    */
   public SPNEGOServerSocket(int port) throws IOException
   {
      super(port);
   }

   /**
    * @see ServerSocket#ServerSocket(int, int)
    */
   public SPNEGOServerSocket(int port, int backlog) throws IOException
   {
      super(port, backlog);
   }

   /**
    * @see ServerSocket#ServerSocket(int, int, InetAddress)
    */
   public SPNEGOServerSocket(int port, int backlog, InetAddress bindAddr) throws IOException
   {
      super(port, backlog, bindAddr);
   }

   /**
    * Tries to establish a {@link GSSContext} with the client using the tokens
    * provided.
    * 
    * @see ServerSocket#accept()
    */
   public Socket accept() throws IOException
   {
      boolean TRACE = log.isTraceEnabled();
      if (TRACE)
         log.trace(this.getClass().getName() + ".accept()");
      Socket socket = super.accept();

      if (TRACE)
         log.trace("Creating new NegotiationContext");
      NegotiationContext negotiationContext = new NegotiationContext();
      try
      {
         negotiationContext.associate();
         acceptSocket(socket, negotiationContext);
      }
      catch (Exception e)
      {
         // re-throw the Exception as a IOException
         throw new IOException(e);
      }
      finally
      {
         negotiationContext.clear();
      }

      return socket;
   }
   
   /**
    * @see ServerSocket#close()
    */
   public void close() throws IOException
   {
      try
      {
         logout();
      }
      catch (LoginException le)
      {
         // just logs error
         log.error("Error during logout: " + le.getMessage(), le);
      }
      super.close();
   }

   /**
    * Accepts a {@link Socket} connection by trying to do a JAAS Kerberos login using the tokens exchanged
    * with the client.
    * 
    * @param socket Client {@link Socket}
    * @param negotiationContext {@link NegotiationContext} to be used for the JAAS login
    * @throws IOException
    * @throws NegotiationException
    * @throws NamingException
    */
   protected void acceptSocket(Socket socket, NegotiationContext negotiationContext) throws Exception
   {
      boolean TRACE = log.isTraceEnabled();
      
      byte[] token = new byte[0];
      DataInputStream inStream = new DataInputStream(socket.getInputStream());
      // first reads the size of the client's token
      token = new byte[inStream.readInt()];
      if (TRACE)
         log.debug("Receiving token of length " + token.length);
      // then reads the client's token
      inStream.readFully(token);
      MessageTrace.logRequestHex(token);
      
      ByteArrayInputStream authTokenIS = new ByteArrayInputStream(token);
      MessageFactory mf = MessageFactory.newInstance();
      if (mf.accepts(authTokenIS) == false)
      {
         throw new IOException("Unsupported negotiation mechanism.");
      }
      NegotiationMessage requestMessage = mf.createMessage(authTokenIS);
      authTokenIS.close();
      // AP_REQ token
      byte[] kerberosToken = ((NegTokenInit) requestMessage).getMechToken();
      // need to pass the full token and let JDK classes parse it
      ((NegTokenInit) requestMessage).setMechToken(token);
      negotiationContext.setRequestMessage(requestMessage);
      
      // retrieve client principal from the kerberos token
      if (subject == null)
      {
         if (TRACE)
            log.trace("Starting host login");
         subject = login();
         if (TRACE)
            log.trace("Host login successful");
      }
      principal = getClientPrincipal(kerberosToken, subject);
      // need to flush the cache first and let the tokens be validated every time
      if (TRACE)
         log.trace("Flushing cache");
      flushPrincipalFromCache(principal, securityDomain);
      
      // authenticates using the token
      isValid(principal, null, securityDomain);
      
      NegotiationMessage responseMessage = negotiationContext.getResponseMessage();
      DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());
      // need to pass the full token and let JDK classes parse it
      token = ((NegTokenTarg) responseMessage).getResponseToken();
      if (TRACE)
         log.debug("Sending token of length " + token.length);
      MessageTrace.logResponseHex(token);
      // first writes the size of the token
      outStream.writeInt(token.length);
      // then writes the token
      outStream.write(token);
      outStream.flush();
   }

   /**
    * Performs a JAAS login.
    * 
    * @param principal User {@link Principal} to login
    * @param credential Credentials of the user
    * @param securityDomain Name of the JAAS security domain
    * @return true if authentication succeeds, false otherwise
    * @throws Exception if an error occurs
    */
   protected boolean isValid(Principal principal, Object credential, String securityDomain) throws Exception
   {
      InitialContext ctx = new InitialContext();
      JaasSecurityManager jsm = (JaasSecurityManager) ctx.lookup(SecurityConstants.JAAS_CONTEXT_ROOT + "/" + securityDomain);
      return jsm.isValid(principal, credential);
   }
   
   /**
    * Removes the user entry from the authentication cache.
    * 
    * @param principal User {@link Principal} to remove from cache
    * @param securityDomain Name of the JAAS security domain
    * @throws Exception if an error occurs
    */
   protected void flushPrincipalFromCache(Principal principal, String securityDomain) throws Exception
   {
      MBeanServer server = MBeanServerLocator.locateJBoss();
      ObjectName jaasMgr = new ObjectName("jboss.security:service=JaasSecurityManager");
      Object[] params = {securityDomain, principal};
      String[] signature = {String.class.getName(), Principal.class.getName()};
      server.invoke(jaasMgr, "flushAuthenticationCache", params, signature);
   }
   
   /**
    * Returns the security domain securing the EJBs.
    * 
    * @return name of the security domain
    */
   public String getSecurityDomain()
   {
      return securityDomain;
   }

   /**
    * Sets the security domain securing the EJBs.
    * 
    * @param securityDomain name of the security domain
    */
   public void setSecurityDomain(String securityDomain)
   {
      this.securityDomain = securityDomain;
   }
   
   /**
    * Returns the Kerberos security domain. 
    * 
    * @return name of the security domain
    */
   public String getHostSecurityDomain()
   {
      return hostSecurityDomain;
   }
   
   /**
    * Sets the Kerberos security domain.
    * 
    * @param hostSecurityDomain name of the security domain
    */
   public void setHostSecurityDomain(String hostSecurityDomain)
   {
      this.hostSecurityDomain = hostSecurityDomain;
   }
   
   /**
    * Performs a JAAS login on the client side.
    *  
    * @return a {@link Subject}
    * @throws LoginException if the login fails
    */
   protected Subject login() throws LoginException
   {
      if (lc == null)
         lc = new LoginContext(hostSecurityDomain, new SecurityAssociationHandler());
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
      subject = null;
   }
   
   /**
    * Decodes and parses the ticket to retrieve the client {@link Principal}.
    * 
    * @param ticket Kerberos ticket
    * @param subject Subject containing the server private key
    * @return client {@link Principal}
    */
   protected Principal getClientPrincipal(byte[] ticket, Subject subject)
   {
      TokenParser tp = new TokenParser();
      try
      {
         tp.parseToken(ticket, subject);
      }
      catch (Exception e)
      {
         log.error("Error parsing/decoding ticket: " + e.getMessage(), e);
         return null;
      }
      String principalName = tp.getPrincipalName();
      
      return new KerberosPrincipal(principalName);
   }
}
