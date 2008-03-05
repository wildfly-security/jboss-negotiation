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
import java.util.Enumeration;

import javax.servlet.ServletException;

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.log4j.Logger;

/**
 * A simple valve which logs request and response information.
 * 
 * @author <a href="darranlofthouse@hotmail.com">Darran Lofthouse</a>
 */
public class SimpleValve implements Valve
{

   private static final Logger log = Logger.getLogger(SimpleValve.class);

   private Valve next;

   public SimpleValve()
   {
      /*
       * log.info("Constructor Stack Trace", new Exception()); new
       * Exception().printStackTrace();
       */
   }

   public void invoke(final Request request, final Response response) throws IOException, ServletException
   {
      // log.info("Valve Object Name '" + getObjectName().toString());
      System.out.println("Invoke  SimpleValve");
      log.info("URI " + request.getDecodedRequestURI());
      log.debug("Current Stack Trace", new Exception());

      Enumeration e1 = request.getAttributeNames();
      while (e1.hasMoreElements())
      {
         Object element = e1.nextElement();
         log.info("Attribute " + element);
      }

      Enumeration e2 = request.getHeaderNames();
      while (e2.hasMoreElements())
      {
         String name = (String) e2.nextElement();
         Enumeration e2_1 = request.getHeaders(name);
         while (e2_1.hasMoreElements())
         {
            String value = (String) e2_1.nextElement();
            log.info("+ Request header " + name + "=" + value);
         }
      }

      Enumeration e3 = request.getParameterNames();
      while (e3.hasMoreElements())
      {
         Object element = e3.nextElement();
         log.info("Parameter " + element);
      }

      log.info("** Incoke Next");
      getNext().invoke(request, response);
      log.info("** Incoke Next - Complete");

      for (String name : response.getHeaderNames())
      {
         for (String value : response.getHeaderValues(name))
         {
            log.info("- Response header " + name + "=" + value);
         }
      }
   }

   public String getInfo()
   {
      return "";
   }

   public Valve getNext()
   {
      return next;
   }

   public void backgroundProcess()
   {
   }

   public void setNext(final Valve valve)
   {
      this.next = valve;
   }


}
