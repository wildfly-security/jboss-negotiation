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

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import com.sun.security.auth.callback.TextCallbackHandler;

/**
 * Utility to be called from the command line to verify that it is possible
 * to authenticate against the KDC when providing the username and password.
 * 
 * @author darran.lofthouse@jboss.com
 * @version $Revision$
 */
public class UsernamePasswordLogon
{

   /**
    * Utility entry point.
    */
   public static void main(String[] args) throws Exception
   {      
      System.out.println(" * * UserNamePasswordLogin * *");
      LoginContext login = new LoginContext("UsernamePasswordSample", new TextCallbackHandler());
      login.login();

      System.out.println("Authenticated");

      Subject subject = login.getSubject();

      System.out.println("Subject - " + String.valueOf(subject));
   }
}
