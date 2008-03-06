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
package org.jboss.security.negotiation;

import org.jboss.logging.Logger;

import com.darranl.spnego.DebugHelper;

/**
 * Handle message tracing hierarchy.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class MessageTrace
{

   private static final String BASE_CLASS = MessageTrace.class.getName();

   private static final Logger REQUEST_BASE64 = Logger.getLogger(BASE_CLASS + ".Request.Base64");

   private static final Logger REQUEST_HEX = Logger.getLogger(BASE_CLASS + ".Request.Hex");

   private static final Logger RESPONSE_BASE64 = Logger.getLogger(BASE_CLASS + ".Response.Base64");

   private static final Logger RESPONSE_HEX = Logger.getLogger(BASE_CLASS + ".Response.HEX");

   public static void logRequestBase64(final String request)
   {
      REQUEST_BASE64.trace(request);
   }

   public static void logRequestHex(final byte[] request)
   {
      if (REQUEST_HEX.isTraceEnabled())
      {
         REQUEST_HEX.trace(DebugHelper.convertToHex(request));
      }
   }

   public static void logResponseBase64(final String response)
   {
      RESPONSE_BASE64.trace(response);
   }

   public static void logResponseHex(final byte[] response)
   {
      if (RESPONSE_HEX.isTraceEnabled())
      {
         RESPONSE_HEX.trace(DebugHelper.convertToHex(response));
      }
   }

}
