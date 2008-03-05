<html>
  <head></head>
  <body>
    <%
      String name = request.getParameter("name");
      try {
      javax.naming.InitialContext initialContext = new javax.naming.InitialContext();
      java.lang.Object o =
      initialContext.lookup(name);
      out.print(o);
      }
      catch (Exception e) {
      e.printStackTrace(System.out);
      }
    %>
  </body>
</html>