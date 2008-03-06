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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * A basic servlet to test that if prompted the client browser will return a SPNEGO
 * header rather than an NTLM header.
 * 
 * Clients that return an NTLM header do not trust the server sufficiently so the KDC
 * configuration will need to be checked.
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
      log.info("Authorization '" + authHeader + "'");
      if (authHeader == null)
      {
         log.info("No Authorization Header, sending 401");
         resp.setHeader("WWW-Authenticate", "Negotiate");
         resp.sendError(401);

         return;
      }

      // TODO Auto-generated method stub
      super.doGet(req, resp);
   }

   @Override
   protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException,
         IOException
   {
      doGet(req, resp);
   }

}
