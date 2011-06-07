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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;

/**
 * A servlet to test that the security domain required by the authenticator
 * can successfully authenticate.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class SecurityDomainTestServlet extends HttpServlet
{

   private static final long serialVersionUID = -3129778766905747055L;

   private static final Logger log = Logger.getLogger(SecurityDomainTestServlet.class);

   @Override
   protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      String securityDomain = req.getParameter("securityDomain");

      PrintWriter writer = resp.getWriter();

      writer.println("<html>");
      writer.println("  <head>");
      writer.println("    <title>Negotiation Toolkit</title>");
      writer.println("  </head>");
      writer.println("  <body>");
      writer.println("    <h1>Negotiation Toolkit</h1>");
      writer.println("    <h2>Security Domain Test</h2>");

      if (securityDomain == null)
      {
         displayForm(writer);
      }
      else
      {
         testDomain(securityDomain, writer);
      }

      writer.println("  </body>");
      writer.println("</html>");
      writer.flush();
   }

   private void displayForm(final PrintWriter writer)
   {
      writer
            .println("    <p>Please enter the name of the security-domain used for the server to authenticate itself.</p>");
      writer.println("    <p>");
      writer.println("      <form method='get'>");
      writer.println("        Security Domain <input type='text' name='securityDomain' value='host'><br>");
      writer.println("        <br><input type='submit' value='Test'>");
      writer.println("      </form>");
      writer.println("    </p>");
   }

   private void testDomain(final String securityDomain, final PrintWriter writer)
   {
      writer.print("<p>Testing security-domain '");
      writer.print(securityDomain);
      writer.println("'</p>");

      try
      {
         LoginContext context = new LoginContext(securityDomain);
         log.debug("Obtained LoginContext for '" + securityDomain + "' security-domain.");

         context.login();
         writer.println("<h4>Authenticated</h4>");         

         Subject subject = context.getSubject();

         ByteArrayInputStream bais = new ByteArrayInputStream(String.valueOf(subject).getBytes());
         InputStreamReader isr = new InputStreamReader(bais);
         BufferedReader br = new BufferedReader(isr);

         writer.println("<code>");
         String currentLine;
         while ((currentLine = br.readLine()) != null)
         {
            writer.print(currentLine);
            writer.println("<br>");
         }
         writer.println("</code>");
         
         context.logout();
         log.debug("logged out.");
      }
      catch (Exception e)
      {
         // TODO - Output full exception detail.
         writer.println("<h5>Failed!</h5>");
         writer.print("<p>");
         writer.print(e.getClass().getName());
         writer.print(" - ");
         writer.print(e.getMessage());
         writer.println("</p>");

         log.error("testDomain Failed", e);
      }
   }

   @Override
   protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      // Handle POST the same as GET.
      doGet(req, resp);
   }
}
