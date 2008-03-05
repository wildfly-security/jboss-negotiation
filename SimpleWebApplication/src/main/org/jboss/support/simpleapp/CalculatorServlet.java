package org.jboss.support.simpleapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.jboss.support.simpleapp.ejb.CalculatorHome;
import org.jboss.support.simpleapp.ejb.CalculatorRemote;

public class CalculatorServlet extends HttpServlet
{

   /**
    * 
    */
   private static final long serialVersionUID = -2859406369812457187L;

   private static final Logger log = Logger.getLogger(CalculatorServlet.class);

   @Override
   protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException,
         IOException
   {
      String a = request.getParameter("a");
      String b = request.getParameter("b");

      String remoteUser = request.getRemoteUser();
      log.info("Remote User - '" + remoteUser + "'");
      Principal userPrincipal = request.getUserPrincipal();
      log.info("User Principal - '" + userPrincipal + "' " + userPrincipal.getClass().getName());

      log.info("a='" + a + "'");
      log.info("b='" + b + "'");

      PrintWriter writer = response.getWriter();

      if (a == null || b == null)
      {
         displayForm(writer);
      }
      else
      {
         try
         {
            displayResult(writer, a, b);
         }
         catch (Exception e)
         {
            throw new ServletException("Unable to calculate result", e);
         }
      }

   }

   private void displayForm(final PrintWriter writer)
   {

      writer.println("<html>");
      writer.println("  <head>");
      writer.println("    <title>Calculator</title>");
      writer.println("  </head>");
      writer.println("  <body>");
      writer.println("    <h1>Calculator</h1>");
      writer.println("    <p>Please enter two numbers you would like to add together.</p>");
      writer.println("    <p>");
      writer.println("      <form method='get'>");
      writer.println("        A <input type='text' name='a' value='0'><br>");
      writer.println("        B <input type='text' name='b' value='0'><br>");
      writer.println("        <br><input type='submit' value='Add'>");
      writer.println("      </form>");
      writer.println("    </p>");
      writer.println("  </body>");
      writer.println("</html>");
      writer.flush();
   }

   private void displayResult(final PrintWriter writer, final String a, final String b) throws Exception
   {
      Context ctx = new InitialContext();
      Object homeObj = ctx.lookup("CalculatorBean");

      log.info("CH " + CalculatorHome.class.getName());
      log.info("CH " + CalculatorHome.class.getClassLoader());

      for (Class clazz : homeObj.getClass().getInterfaces())
      {
         log.info(clazz.getName());
         log.info(clazz.getClassLoader());
      }
      //CalculatorHome home = (CalculatorHome) PortableRemoteObject.narrow(homeObj, CalculatorHome.class);
      CalculatorHome home = (CalculatorHome) homeObj;

      int result = -1;
      CalculatorRemote remote = null;
      try
      {
         remote = home.create();
         int aint = Integer.valueOf(a).intValue();
         int bint = Integer.valueOf(b).intValue();

         result = remote.add(aint, bint);

      }
      finally
      {
         if (remote != null)
            remote.remove();
      }

      writer.println("<html>");
      writer.println("  <head>");
      writer.println("    <title>Calculator</title>");
      writer.println("  </head>");
      writer.println("  <body>");
      writer.println("    <h1>Calculator</h1>");
      writer.println("    <p>" + a + " + " + b + " = " + result + "</p>");
      writer.println("  </body>");
      writer.println("</html>");
      writer.flush();
   }

}
