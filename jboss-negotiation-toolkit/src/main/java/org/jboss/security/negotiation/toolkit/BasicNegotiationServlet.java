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
package org.jboss.security.negotiation.toolkit;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.util.Base64;
import org.apache.log4j.Logger;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.jboss.security.negotiation.OidNameUtil;
import org.jboss.security.negotiation.common.DebugHelper;
import org.jboss.security.negotiation.ntlm.Constants;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInit;
import org.jboss.security.negotiation.spnego.encoding.NegTokenInitDecoder;

/**
 * A basic servlet to test that if prompted the client browser will return a SPNEGO
 * header rather than an NTLM header.
 * 
 * Clients that return an NTLM header do not trust the server sufficiently so the KDC
 * configuration will need to be checked.
 * 
 * NTLM responses received will be forwarded to the NTLMNegotiationServlet for display.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class BasicNegotiationServlet extends HttpServlet
{

   private static final long serialVersionUID = 7269693410644316525L;

   private static final Logger log = Logger.getLogger(BasicNegotiationServlet.class);

   @Override
   protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      String authHeader = req.getHeader("Authorization");
      if (authHeader == null)
      {
         log.info("No Authorization Header, sending 401");
         resp.setHeader("WWW-Authenticate", "Negotiate");
         resp.sendError(401);

         return;
      }

      log.info("Authorization header received - formatting web page response.");

      /* At this stage no further negotiation will take place so the information */
      /* can be output in the servlet response.                                  */

      PrintWriter writer = resp.getWriter();

      writer.println("<html>");
      writer.println("  <head>");
      writer.println("    <title>Negotiation Toolkit</title>");
      writer.println("  </head>");
      writer.println("  <body>");
      writer.println("    <h1>Negotiation Toolkit</h1>");
      writer.println("    <h2>Basic Negotiation</h2>");

      // Output the raw header.
      writer.println("    <p>WWW-Authenticate - ");
      writer.println(authHeader);
      writer.println("    </p>");

      String requestHeader = "";
      if (authHeader.startsWith("Negotiate "))
      {
         // Drop the 'Negotiate ' from the header.
         requestHeader = authHeader.substring(10);
      }
      else if (authHeader.startsWith("NTLM "))
      {
         // Drop the 'NTLM ' from the header.
         requestHeader = authHeader.substring(5);
      }

      if (requestHeader.length() == 0)
      {
         writer.println("<p><b>Header WWW-Authenticate does not beging with 'Negotiate' or 'NTLM'!</b></p>");
      }
      else
      {
         byte[] reqToken = Base64.decode(requestHeader);

         byte[] ntlmSignature = Constants.SIGNATURE;
         if (reqToken.length > 8)
         {
            byte[] reqHeader = new byte[8];
            System.arraycopy(reqToken, 0, reqHeader, 0, 8);

            if (Arrays.equals(ntlmSignature, reqHeader))
            {

               RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/NTLMNegotiation");
               dispatcher.forward(req, resp);

               return;
            }
         }

         try
         {
            writeHeaderDetail(reqToken, writer);
         }
         catch (Exception e)
         {
            if (e instanceof RuntimeException)
            {
               throw (RuntimeException) e;
            }
            else
            {
               throw new ServletException("Unable to writeHeaderDetail", e);
            }
         }
      }

      writer.println("  </body>");
      writer.println("</html>");
      writer.flush();
   }

   @Override
   protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      // Handle POST as GET.
      doGet(req, resp);
   }

   private void writeHeaderDetail(final byte[] reqToken, final PrintWriter writer) throws IOException, GSSException
   {

      if (reqToken[0] == 0x60)
      {
         NegTokenInit negTokenInit = NegTokenInitDecoder.decode(reqToken);
         writer.println("<h3>NegTokenInit</h3>");

         writer.print("<b>Message Oid - </b>");
         writer.print(OidNameUtil.getName(negTokenInit.getMessageOid()));
         writer.println("<br>");

         List<Oid> mechTypes = negTokenInit.getMechTypes();
         writer.print("<b>Mech Types -</b>");
         for (Oid current : mechTypes)
         {
            writer.print(" {");
            writer.print(OidNameUtil.getName(current));
            writer.print("}");
         }
         writer.println("<br>");

         writer.print("<b>Req Flags -</b>");
         byte[] reqFlags = negTokenInit.getReqFlags();
         if (reqFlags != null && reqFlags.length > 0)
         {
            writer.print(DebugHelper.convertToHex(reqFlags));
         }
         writer.println("<br>");

         writer.print("<b>Mech Token -</b>");
         byte[] mechToken = negTokenInit.getMechToken();
         if (mechToken != null && mechToken.length > 0)
         {
            writer.print(new String(Base64.encodeBytes(mechToken)));
         }
         writer.println("<br>");

         writer.print("<b>Mech List Mic -</b>");
         byte[] mechTokenMic = negTokenInit.getMechListMIC();
         if (mechTokenMic != null && mechTokenMic.length > 0)
         {
            writer.print(new String(Base64.encodeBytes(mechTokenMic)));
         }
         writer.println("<br>");

         return;
      }

      if (reqToken[0] == (byte) 0xa1)
      {
         writer.println("<p><b>Unexpected NegTokenTarg, first token should be NegTokenInit!</b></p>");
         return;
      }

      writer.println("<p><b>Unsupported negotiation mechanism</b></p>");
   }

}
