/*
 * Copyright © 2008  Red Hat Middleware, LLC. or third-party contributors as indicated 
 * by the @author tags or express copyright attribution statements applied by the 
 * authors. All third-party contributions are distributed under license by Red Hat 
 * Middleware LLC.
 *
 * This copyrighted material is made available to anyone wishing to use, modify, copy, 
 * or redistribute it subject to the terms and conditions of the GNU Lesser General 
 * Public License, v. 2.1. This program is distributed in the hope that it will be 
 * useful, but WITHOUT A WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for 
 * more details. You should have received a copy of the GNU Lesser General Public License, 
 * v.2.1 along with this distribution; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

package com.darranl.tomcat.gss;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.jboss.security.negotiation.spnego.encoding.DebugHelper;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInit;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInitDecoder;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTarg;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTargDecoder;
import org.jboss.security.negotiation.spnego.encoding.NegTokenTargEncoder;

/**
 * A SPNEGOValve for Kerberos authentication for web
 * applications.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 * @version $Revision$
 */
public class SPNEGOValve implements Valve
{

   private static final Logger log = Logger.getLogger(SPNEGOValve.class);

   private final Oid spnego;

   private final Oid kerberosLegacy;

   private final Oid kerberos;

   private Valve next;

   public SPNEGOValve() throws GSSException
   {
      spnego = new Oid("1.3.6.1.5.5.2");
      kerberosLegacy = new Oid("1.2.840.48018.1.2.2");
      kerberos = new Oid("1.2.840.113554.1.2.2");
   }

   public String getInfo()
   {
      return "SPNEGO Authentication Valve";
   }

   public Valve getNext()
   {
      return next;
   }

   public void setNext(final Valve next)
   {
      this.next = next;
   }

   public void backgroundProcess()
   {
      //log.info("backgroundProcess()");
   }

   public void invoke(final Request request, final Response response) throws IOException, ServletException
   {
      log.info("invoke");

      boolean authenticated;
      try
      {
         authenticated = authenticate(request, response);
         log.info("authenticated=" + authenticated);
      }
      catch (Exception e)
      {
         log.warn("Authenticate Failed", e);
         throw new IOException("Authentication failure - " + e.getMessage());
      }

      if (authenticated)
      {
         getNext().invoke(request, response);
      }

   }

   protected boolean authenticate(final Request request, final Response response) throws Exception
   {
      Principal user = request.getUserPrincipal();

      if (user != null)
      {
         log.info("There is a user");
         return true;
      }

      // Do this early so we can get header from client before we have to authenticate.
      String authHeader = request.getHeader("Authorization");

      if (authHeader == null)
      {
         log.debug("No Authorization Header, sending 401");
         response.setHeader("WWW-Authenticate", "Negotiate");

         response.sendError(401);

         return false;
      }
      // End Early

      Subject server = getServerSubject();

      AcceptSecContext action = new AcceptSecContext(request, response);

      Object result = Subject.doAs(server, action);

      if (result instanceof Exception)
      {
         log.info("Throwing Exception", (Exception) result);
         throw (Exception) result;
      }
      else if (result instanceof Boolean)
      {
         return ((Boolean) result).booleanValue();
      }

      log.info("Default return false");
      return false;
   }

   protected Subject getServerSubject() throws LoginException
   {
      log.info("getServerSubject");
      LoginContext lc = new LoginContext("host");
      lc.login();

      log.info("Subject = " + lc.getSubject());
      log.info("Logged in 'host' LoginContext");

      return lc.getSubject();
   }

   private class AcceptSecContext implements PrivilegedAction
   {

      private final Request request;

      private final Response response;

      AcceptSecContext(final Request request, final Response response)
      {
         this.request = request;
         this.response = response;
      }

      public Object run()
      {
         try
         {
            String authHeader = request.getHeader("Authorization");

            if (authHeader == null)
            {
               log.debug("No Authorization Header, sending 401");
               response.setHeader("WWW-Authenticate", "Negotiate");

               response.sendError(401);

               return Boolean.FALSE;
            }

            if (authHeader.startsWith("Negotiate ") == false)
            {
               return new IOException("Invalid 'Authorization' header.");
            }

            String reqEncoded = authHeader.substring(10);

            log.info("Encoded '" + reqEncoded + "'");

            byte[] reqToken = Base64.decodeBase64(reqEncoded.getBytes());
            byte[] gssToken = null;

            String reqHex = DebugHelper.convertToHex(reqToken);
            log.info("Request Token '" + reqHex + "'");

            if (reqToken[0] == 0x60)
            {
               NegTokenInit negTokenInit = NegTokenInitDecoder.decode(reqToken);
               List mechList = negTokenInit.getMechTypes();

               if (mechList.get(0).equals(kerberos))
               {
                  gssToken = negTokenInit.getMechToken();
               }
               else
               {
                  boolean kerberosSupported = false;

                  Iterator it = mechList.iterator();
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
                  String respSpnegoHex = DebugHelper.convertToHex(respSpnego);
                  log.info("SPNEGO Response '" + respSpnegoHex + "'");

                  String respEncoded = new String(Base64.encodeBase64(respSpnego));
                  response.setHeader("WWW-Authenticate", "Negotiate " + respEncoded);

                  response.sendError(401);

                  return Boolean.FALSE;
               }

            }
            else if (reqToken[0] == (byte) 0xa1)
            {
               NegTokenTarg negTokenTarg = NegTokenTargDecoder.decode(reqToken);

               gssToken = negTokenTarg.getResponseToken();
            }

            HttpSession session = request.getSession();

            GSSContext context = (GSSContext) session.getAttribute("GSSContext");

            if (context == null)
            {
               GSSManager manager = GSSManager.getInstance();
               context = manager.createContext((GSSCredential) null);

               session.setAttribute("GSSContext", context);
            }

            if (context.isEstablished())
            {
               return Boolean.TRUE;
            }

            String gssTokenHex = DebugHelper.convertToHex(gssToken);
            log.info("GSS Token '" + gssTokenHex + "'");

            byte[] respToken = context.acceptSecContext(gssToken, 0, gssToken.length);

            if (respToken != null)
            {
               NegTokenTarg negTokenTarg = new NegTokenTarg();
               negTokenTarg.setResponseToken(respToken);

               byte[] respSpnego = NegTokenTargEncoder.encode(negTokenTarg);
               String respSpnegoHex = DebugHelper.convertToHex(respSpnego);

               log.info("SPNEGO Response '" + respSpnegoHex + "'");

               String respEncoded = new String(Base64.encodeBase64(respSpnego));
               response.setHeader("WWW-Authenticate", "Negotiate " + respEncoded);
            }

            if (context.isEstablished() == false)
            {
               response.sendError(401);

               return Boolean.FALSE;
            }
            else
            {
               log.info("context.getCredDelegState() = " + context.getCredDelegState());
               log.info("context.getMutualAuthState() = " + context.getMutualAuthState());
               log.info("context.getSrcName() = " + context.getSrcName().toString());
            }

         }
         catch (Exception e)
         {
            return e;
         }

         return Boolean.TRUE;

      }
   }

   protected void debug(final NegTokenInit negTokenInit)
   {
      log.info("Message OID - " + negTokenInit.getMessageOid());
      Iterator it = negTokenInit.getMechTypes().iterator();
      while (it.hasNext())
      {
         Oid current = (Oid) it.next();
         log.info("Supported Mech - " + current);
      }
   }

}
