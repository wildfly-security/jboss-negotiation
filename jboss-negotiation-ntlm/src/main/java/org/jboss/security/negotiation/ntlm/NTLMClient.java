/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.negotiation.ntlm;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;

/**
 * A simple client to test calling an NTLM enabled web application.
 * 
 * Based on the example in: -
 *   http://java.sun.com/javase/6/docs/technotes/guides/net/http-auth.html
 * 
 * @author darran.lofthouse@jboss.com
 * @since 7th August 2008
 */
public class NTLMClient
{
   public static final String USERNAME = "darran";

   public static final String PASSWORD = "password";

   public static final String URL = "http://localhost:8080/jboss-negotiation-toolkit/BasicNegotiation";

   static class NTLMAuthenticator extends Authenticator
   {

      @Override
      protected URL getRequestingURL()
      {
         return super.getRequestingURL();
      }

      @Override
      protected RequestorType getRequestorType()
      {
         return super.getRequestorType();
      }

      @Override
      protected PasswordAuthentication getPasswordAuthentication()
      {
         return new PasswordAuthentication(USERNAME, PASSWORD.toCharArray());
      }
   }

   public static void main(String[] args) throws Exception
   {
      Authenticator.setDefault(new NTLMAuthenticator());
      URL url = new URL(NTLMClient.URL);
      InputStream ins = url.openConnection().getInputStream();
      BufferedReader reader = new BufferedReader(new InputStreamReader(ins));
      String str;
      while ((str = reader.readLine()) != null)
      {
         System.out.println(str);
      }
   }

}
