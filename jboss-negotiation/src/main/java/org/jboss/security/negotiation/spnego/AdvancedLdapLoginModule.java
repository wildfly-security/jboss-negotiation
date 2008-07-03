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
package org.jboss.security.negotiation.spnego;

import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Map.Entry;

import javax.management.ObjectName;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.jboss.security.negotiation.prototype.DecodeAction;

/**
 * Another LDAP LoginModule to take into account requirements
 * for different authentication mechanisms and full support
 * for password-stacking set to useFirstPass.
 * 
 * This is essentially a complete refactoring of the LdapExtLoginModule
 * but with enough restructuring to seperate out the three login steps: -
 *  -1 Find the user
 *  -2 Authenticate as the user
 *  -3 Find the users roles
 * Configuration should allow for any of the three actions to be
 * skipped based on the requirements for the environment making
 * use of this login module. 
 *
 * 
 * @author darran
 *
 */
public class AdvancedLdapLoginModule extends AbstractServerLoginModule
{

   /*
    * Configuration Option Constants 
    */

   // Search Context Settings
   private static final String BIND_AUTHENTICATION = "bindAuthentication";

   private static final String BIND_DN = "bindDN";

   private static final String BIND_CREDENTIAL = "bindCredential";

   private static final String SECURITY_DOMAIN = "jaasSecurityDomain";

   // User Search Settings
   private static final String BASE_CTX_DN = "baseCtxDN";

   private static final String BASE_FILTER = "baseFilter";

   private static final String SEARCH_TIME_LIMIT = "searchTimerolesCtxDNLimit";

   // Role Search Settings
   private static final String ROLES_CTS_DN = "rolesCtxDN";

   private static final String ROLE_FILTER = "roleFilter";

   private static final String RECURSE_ROLES = "recurseRoles";

   private static final String ROLE_ATTRIBUTE_ID = "roleAttributeID";

   private static final String ROLE_ATTRIBUTE_IS_DN = "roleAttributeIsDN";

   private static final String ROLE_NAME_ATTRIBUTE_ID = "roleNameAttributeID";

   /*
    * Other Constants
    */

   private static final String AUTH_TYPE_GSSAPI = "GSSAPI";

   private static final String AUTH_TYPE_SIMPLE = "simple";

   private static final String DEFAULT_LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

   private static final String DEFAULT_URL = "ldap://localhost:389";

   private static final String DEFAULT_SSL_URL = "ldap://localhost:686";

   private static final String PROTOCOL_SSL = "SSL";

   /*
    * Configuration Options
    */
   // Search Context Settings
   protected String bindAuthentication;

   protected String bindDn;

   protected String bindCredential;

   protected String jaasSecurityDomain;

   // User Search Settings
   protected String baseCtxDN;

   protected String baseFilter;

   protected int searchTimeLimit = 10000;

   protected SearchControls userSearchControls;

   // Role Search Settings
   protected String rolesCtxDN;

   protected String roleFilter;

   protected boolean recurseRoles;

   protected SearchControls roleSearchControls;

   protected String roleAttributeID;

   protected boolean roleAttributeIsDN;

   protected String roleNameAttributeID;

   /*
    * Module State 
    */
   /** The login identity */
   private Principal identity;

   /** The proof of login identity */
   private char[] credential;

   private transient SimpleGroup userRoles = new SimpleGroup("Roles");

   @Override
   public void initialize(Subject subject, CallbackHandler handler, Map sharedState, Map options)
   {
      super.initialize(subject, handler, sharedState, options);

      // Search Context Settings
      bindAuthentication = (String) options.get(BIND_AUTHENTICATION);
      bindDn = (String) options.get(BIND_DN);
      bindCredential = (String) options.get(BIND_CREDENTIAL);
      jaasSecurityDomain = (String) options.get(SECURITY_DOMAIN);

      // User Search Settings
      baseCtxDN = (String) options.get(BASE_CTX_DN);
      baseFilter = (String) options.get(BASE_FILTER);

      String temp = (String) options.get(SEARCH_TIME_LIMIT);
      if (temp != null)
      {
         try
         {
            searchTimeLimit = Integer.parseInt(temp);
         }
         catch (NumberFormatException e)
         {
            log.warn("Failed to parse: " + temp + ", using searchTimeLimit=" + searchTimeLimit);
         }
      }

      userSearchControls = new SearchControls();
      userSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      userSearchControls.setReturningAttributes(new String[0]);
      userSearchControls.setTimeLimit(searchTimeLimit);

      rolesCtxDN = (String) options.get(ROLES_CTS_DN);
      roleFilter = (String) options.get(ROLE_FILTER);

      temp = (String) options.get(RECURSE_ROLES);
      recurseRoles = Boolean.parseBoolean(temp);

      roleSearchControls = new SearchControls();
      roleSearchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
      roleSearchControls.setReturningAttributes(new String[0]);
      roleSearchControls.setTimeLimit(searchTimeLimit);

      roleAttributeID = (String) options.get(ROLE_ATTRIBUTE_ID);

      temp = (String) options.get(ROLE_ATTRIBUTE_IS_DN);
      roleAttributeIsDN = Boolean.parseBoolean(temp);

      roleNameAttributeID = (String) options.get(ROLE_NAME_ATTRIBUTE_ID);

   }

   @Override
   public boolean login() throws LoginException
   {
      /*
       * The super.login() check is required to decide if
       * the current user needs to be authenticated, however
       * the actual user and roles search should proceed based
       * on their own options.
       */

      Boolean result = null;

      AuthorizeAction action = new AuthorizeAction();
      if (AUTH_TYPE_GSSAPI.equals(bindAuthentication))
      {
         log.trace("Using GSSAPI to connect to LDAP");
         LoginContext lc = new LoginContext(jaasSecurityDomain);
         lc.login();
         Subject serverSubject = lc.getSubject();

         if (log.isDebugEnabled())
         {
            log.debug("Subject = " + serverSubject);
            log.debug("Logged in '" + lc + "' LoginContext");
         }

         result = (Boolean) Subject.doAs(serverSubject, action);
         lc.logout();
      }
      else
      {
         result = action.run();
      }

      return result.booleanValue();

   }

   @Override
   protected Principal getIdentity()
   {
      return identity;
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {
      Group[] roleSets =
      {userRoles};
      return roleSets;
   }

   protected Boolean authorize() throws Exception
   {
      /*
       * TODO - General failures should throw LoginException, an
       * actual failed authentication should throw FailedLoginException.
       */

      // Obtain the username and password
      processIdentityAndCredential();
      log.trace("Identity - " + getIdentity().getName());
      // Initialise search ctx
      String bindCredential = this.bindCredential;
      if (AUTH_TYPE_GSSAPI.equals(bindAuthentication) == false)
      {
         if (jaasSecurityDomain != null)
         {
            ObjectName serviceName = new ObjectName(jaasSecurityDomain);
            char[] tmp = DecodeAction.decode(bindCredential, serviceName);
            bindCredential = new String(tmp);
         }
      }

      LdapContext searchContext = null;

      try
      {
         searchContext = constructLdapContext(bindDn, bindCredential, bindAuthentication);
         log.debug("Obtained LdapContext");

         // Search for user in LDAP
         String userDN = findUserDN(searchContext);

         // If authentication required authenticate as user
         // TODO

         // Search for roles in LDAP
         rolesSearch(searchContext, userDN);
      }
      finally
      {
         if (searchContext != null)
            searchContext.close();
      }
      return Boolean.TRUE;
   }

   /**
    * Either retrieve existing values based on useFirstPass or use 
    * CallBackHandler to obtain the values.
    */
   protected void processIdentityAndCredential() throws Exception
   {
      if (super.login() == true)
      {
         Object username = sharedState.get("javax.security.auth.login.name");
         if (username instanceof Principal)
            identity = (Principal) username;
         else
         {
            String name = username.toString();
            try
            {
               identity = createIdentity(name);
            }
            catch (Exception e)
            {
               log.debug("Failed to create principal", e);
               throw new LoginException("Failed to create principal: " + e.getMessage());
            }
         }
         // We have no further use for a credential so no need to retrieve it.
      }
      else
      {
         NameCallback nc = new NameCallback("User name: ", "guest");
         PasswordCallback pc = new PasswordCallback("Password: ", false);
         Callback[] callbacks =
         {nc, pc};
         String password = null;

         callbackHandler.handle(callbacks);
         String username = nc.getName();
         identity = createIdentity(username);
         credential = pc.getPassword();
         pc.clearPassword();

      }
   }

   protected LdapContext constructLdapContext(String dn, Object credential, String authentication)
         throws NamingException
   {
      Properties env = new Properties();
      Iterator iter = options.entrySet().iterator();
      while (iter.hasNext())
      {
         Entry entry = (Entry) iter.next();
         env.put(entry.getKey(), entry.getValue());
      }

      // Set defaults for key values if they are missing
      String factoryName = env.getProperty(Context.INITIAL_CONTEXT_FACTORY);
      if (factoryName == null)
      {
         factoryName = DEFAULT_LDAP_CTX_FACTORY;
         env.setProperty(Context.INITIAL_CONTEXT_FACTORY, factoryName);
      }

      // If this method is called with an authentication type then use that.
      if (authentication != null && authentication.length() > 0)
      {
         env.setProperty(Context.SECURITY_AUTHENTICATION, authentication);
      }
      else
      {
         String authType = env.getProperty(Context.SECURITY_AUTHENTICATION);
         if (authType == null)
            env.setProperty(Context.SECURITY_AUTHENTICATION, AUTH_TYPE_SIMPLE);
      }

      String protocol = env.getProperty(Context.SECURITY_PROTOCOL);
      String providerURL = (String) options.get(Context.PROVIDER_URL);
      if (providerURL == null)
      {
         if (PROTOCOL_SSL.equals(protocol))
         {
            providerURL = DEFAULT_SSL_URL;
         }
         else
         {
            providerURL = DEFAULT_URL;
         }
         env.setProperty(Context.PROVIDER_URL, providerURL);
      }

      // Assume the caller of this method has checked the requirements for the principal and
      // credentials.
      if (dn != null)
         env.setProperty(Context.SECURITY_PRINCIPAL, dn);
      if (credential != null)
         env.put(Context.SECURITY_CREDENTIALS, credential);
      traceLdapEnv(env);
      return new InitialLdapContext(env, null);
   }

   protected String findUserDN(LdapContext ctx) throws Exception
   {

      NamingEnumeration results = null;

      Object[] filterArgs =
      {getIdentity().getName()};
      results = ctx.search(baseCtxDN, baseFilter, filterArgs, userSearchControls);
      if (results.hasMore() == false)
      {
         results.close();
         throw new NamingException("Search of baseDN(" + baseCtxDN + ") found no matches");
      }

      SearchResult sr = (SearchResult) results.next();
      String name = sr.getName();
      String userDN = null;
      if (sr.isRelative() == true)
         userDN = name + "," + baseCtxDN;
      else
         throw new NamingException("Can't follow referal for authentication: " + name);

      results.close();
      results = null;

      log.trace("findUserDN - " + userDN);
      return userDN;
   }

   protected void rolesSearch(LdapContext searchContext, String dn) throws NamingException
   {
      Object[] filterArgs =
      {getIdentity().getName(), dn};

      NamingEnumeration results = searchContext.search(rolesCtxDN, roleFilter, filterArgs, roleSearchControls);
      try
      {
         while (results.hasMore())
         {
            SearchResult sr = (SearchResult) results.next();
            String resultDN = canonicalize(sr.getName());

            log.debug("resultDN = " + resultDN);

            String[] attrNames =
            {roleAttributeID};

            Attributes result = searchContext.getAttributes(resultDN, attrNames);
            if (result != null && result.size() > 0)
            {
               Attribute roles = result.get(roleAttributeID);
               for (int n = 0; n < roles.size(); n++)
               {
                  String roleName = (String) roles.get(n);
                  if (roleAttributeIsDN)
                  {
                     // Query the roleDN location for the value of roleNameAttributeID
                     String roleDN = roleName;
                     String[] returnAttribute =
                     {roleNameAttributeID};
                     log.trace("Using roleDN: " + roleDN);
                     try
                     {
                        Attributes result2 = searchContext.getAttributes(roleDN, returnAttribute);
                        Attribute roles2 = result2.get(roleNameAttributeID);
                        if (roles2 != null)
                        {
                           for (int m = 0; m < roles2.size(); m++)
                           {
                              roleName = (String) roles2.get(m);
                              addRole(roleName);
                           }
                        }
                     }
                     catch (NamingException e)
                     {
                        log.trace("Failed to query roleNameAttrName", e);
                     }
                  }
                  else
                  {
                     // The role attribute value is the role name
                     addRole(roleName);
                  }
               }

            }
         }
      }
      finally
      {
         if (results != null)
            results.close();
      }

   }

   protected void traceLdapEnv(Properties env)
   {
      if (log.isTraceEnabled())
      {
         Properties tmp = new Properties();
         tmp.putAll(env);
         String credentials = tmp.getProperty(Context.SECURITY_CREDENTIALS);
         if (credentials != null && credentials.length() > 0)
            tmp.setProperty(Context.SECURITY_CREDENTIALS, "***");
         log.trace("Logging into LDAP server, env=" + tmp.toString());
      }
   }

   private String canonicalize(String searchResult)
   {
      String result = searchResult;
      int len = searchResult.length();

      if (searchResult.endsWith("\""))
      {
         result = searchResult.substring(0, len - 1) + "," + rolesCtxDN + "\"";
      }
      else
      {
         result = searchResult + "," + rolesCtxDN;
      }
      return result;
   }

   private void addRole(String roleName)
   {
      if (roleName != null)
      {
         try
         {
            Principal p = super.createIdentity(roleName);
            if (log.isTraceEnabled())
               log.trace("Assign user '" + getIdentity().getName() + "' to role " + roleName);
            userRoles.addMember(p);
         }
         catch (Exception e)
         {
            log.debug("Failed to create principal: " + roleName, e);
         }
      }
   }

   private class AuthorizeAction implements PrivilegedAction<Boolean>
   {

      public Boolean run()
      {
         try
         {
            return authorize();
         }
         catch (Exception e)
         {
            throw new RuntimeException(e);
         }
      }

   }

}
