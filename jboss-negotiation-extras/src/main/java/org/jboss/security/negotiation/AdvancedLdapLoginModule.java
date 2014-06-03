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
package org.jboss.security.negotiation;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Map.Entry;

import javax.management.ObjectName;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ReferralException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.CompositeName;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jboss.security.SimpleGroup;
import org.jboss.security.negotiation.common.CommonLoginModule;
import org.jboss.security.negotiation.prototype.DecodeAction;

/**
 * Another LDAP LoginModule to take into account requirements
 * for different authentication mechanisms and full support
 * for password-stacking set to useFirstPass.
 *
 * This is essentially a complete refactoring of the LdapExtLoginModule
 * but with enough restructuring to separate out the three login steps: -
 *  -1 Find the user
 *  -2 Authenticate as the user
 *  -3 Find the users roles
 * Configuration should allow for any of the three actions to be
 * skipped based on the requirements for the environment making
 * use of this login module.
 *
 *
 * @author darran.lofthouse@jboss.com
 * @since 3rd July 2008
 */
public class AdvancedLdapLoginModule extends CommonLoginModule
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
   private static final String SEARCH_TIME_LIMIT = "searchTimeLimit";

   // Role Search Settings
   private static final String ROLES_CTS_DN = "rolesCtxDN";
   private static final String ROLE_FILTER = "roleFilter";
   private static final String RECURSE_ROLES = "recurseRoles";
   private static final String ROLE_ATTRIBUTE_ID = "roleAttributeID";
   private static final String ROLE_ATTRIBUTE_IS_DN = "roleAttributeIsDN";
   private static final String ROLE_NAME_ATTRIBUTE_ID = "roleNameAttributeID";
   private static final String ROLE_SEARCH_SCOPE = "searchScope";
   private static final String REFERRAL_USER_ATTRIBUTE_ID_TO_CHECK = "referralUserAttributeIDToCheck";

   // Authentication Settings
   private static final String ALLOW_EMPTY_PASSWORD = "allowEmptyPassword";

   /*
    * Other Constants
    */
   private static final String AUTH_TYPE_GSSAPI = "GSSAPI";
   private static final String AUTH_TYPE_SIMPLE = "simple";
   private static final String DEFAULT_LDAP_CTX_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
   private static final String DEFAULT_URL = "ldap://localhost:389";
   private static final String DEFAULT_SSL_URL = "ldap://localhost:686";
   private static final String PROTOCOL_SSL = "SSL";
   private static final String OBJECT_SCOPE = "OBJECT_SCOPE";
   private static final String ONELEVEL_SCOPE = "ONELEVEL_SCOPE";
   private static final String SUBTREE_SCOPE = "SUBTREE_SCOPE";


   private static final String[] ALL_VALID_OPTIONS =
   {
      BIND_AUTHENTICATION,BIND_DN,BIND_CREDENTIAL,SECURITY_DOMAIN,
      BASE_CTX_DN,BASE_FILTER,SEARCH_TIME_LIMIT,
      ROLES_CTS_DN,ROLE_FILTER,RECURSE_ROLES,ROLE_ATTRIBUTE_ID,ROLE_ATTRIBUTE_IS_DN,ROLE_NAME_ATTRIBUTE_ID,ROLE_SEARCH_SCOPE,
      ALLOW_EMPTY_PASSWORD,REFERRAL_USER_ATTRIBUTE_ID_TO_CHECK,

      Context.INITIAL_CONTEXT_FACTORY,
      Context.OBJECT_FACTORIES,
      Context.STATE_FACTORIES,
      Context.URL_PKG_PREFIXES,
      Context.PROVIDER_URL,
      Context.DNS_URL,
      Context.AUTHORITATIVE,
      Context.BATCHSIZE,
      Context.REFERRAL,
      Context.SECURITY_PROTOCOL,
      Context.SECURITY_AUTHENTICATION,
      Context.SECURITY_PRINCIPAL,
      Context.SECURITY_CREDENTIALS,
      Context.LANGUAGE,
      Context.APPLET
   };

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

   protected String referralUserAttributeIDToCheck = null;

   // Authentication Settings
   protected boolean allowEmptyPassword;

   // inner state fields
   private String referralUserDNToCheck;

   /*
    * Module State
    */
   private SimpleGroup userRoles = new SimpleGroup("Roles");

   private Set<String> processedRoleDNs = new HashSet<String>();

   private boolean trace;

   @Override
   public void initialize(Subject subject, CallbackHandler handler, Map sharedState, Map options)
   {
      addValidOptions(ALL_VALID_OPTIONS);
      super.initialize(subject, handler, sharedState, options);
      trace = log.isTraceEnabled();

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
      referralUserAttributeIDToCheck = (String) options.get(REFERRAL_USER_ATTRIBUTE_ID_TO_CHECK);

      temp = (String) options.get(RECURSE_ROLES);
      recurseRoles = Boolean.parseBoolean(temp);

      int searchScope = SearchControls.SUBTREE_SCOPE;
      temp = (String) options.get(ROLE_SEARCH_SCOPE);
      if (OBJECT_SCOPE.equalsIgnoreCase(temp))
      {
         searchScope = SearchControls.OBJECT_SCOPE;
      }
      else if (ONELEVEL_SCOPE.equalsIgnoreCase(temp))
      {
         searchScope = SearchControls.ONELEVEL_SCOPE;
      }
      if (SUBTREE_SCOPE.equalsIgnoreCase(temp))
      {
         searchScope = SearchControls.SUBTREE_SCOPE;
      }

      roleSearchControls = new SearchControls();
      roleSearchControls.setSearchScope(searchScope);
      roleSearchControls.setTimeLimit(searchTimeLimit);

      roleAttributeID = (String) options.get(ROLE_ATTRIBUTE_ID);

      temp = (String) options.get(ROLE_ATTRIBUTE_IS_DN);
      roleAttributeIsDN = Boolean.parseBoolean(temp);

      roleNameAttributeID = (String) options.get(ROLE_NAME_ATTRIBUTE_ID);
      
      ArrayList<String> roleSearchAttributeList = new ArrayList<String>(3); 
      if (roleAttributeID != null) 
      {
          roleSearchAttributeList.add(roleAttributeID);
      }
      if (roleNameAttributeID != null)
      {
          roleSearchAttributeList.add(roleNameAttributeID);
      } 
      if (referralUserAttributeIDToCheck != null)
      {
          roleSearchAttributeList.add(referralUserAttributeIDToCheck);
      } 
      roleSearchControls.setReturningAttributes(roleSearchAttributeList.toArray(new String[0]));
      
      temp = (String) options.get(ALLOW_EMPTY_PASSWORD);
      allowEmptyPassword = Boolean.parseBoolean(temp);

   }

   @Override
   public boolean login() throws LoginException
   {
      Object result = null;

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

         result = Subject.doAs(serverSubject, action);
         lc.logout();
      }
      else
      {
         result = action.run();
      }

      if (result instanceof LoginException)
      {
         throw (LoginException) result;
      }

      return ((Boolean) result).booleanValue();
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {
      Group[] roleSets =
      {userRoles};
      return roleSets;
   }

   protected Boolean innerLogin() throws LoginException
   {
      // Obtain the username and password
      processIdentityAndCredential();
      if (trace) {
         log.trace("Identity - " + getIdentity().getName());
      }
      // Initialise search ctx
      String bindCredential = this.bindCredential;
      if (AUTH_TYPE_GSSAPI.equals(bindAuthentication) == false)
      {
         if (jaasSecurityDomain != null && jaasSecurityDomain.length() > 0)
         {
            try
            {
               ObjectName serviceName = new ObjectName(jaasSecurityDomain);
               char[] tmp = DecodeAction.decode(bindCredential, serviceName);
               bindCredential = new String(tmp);
            }
            catch (Exception e)
            {
               LoginException le = new LoginException("Unable to decode bindCredential");
               le.initCause(e);
               throw le;
            }
         }
      }

      LdapContext searchContext = null;

      try
      {
         searchContext = constructLdapContext(null, bindDn, bindCredential, bindAuthentication);
         log.debug("Obtained LdapContext");

         // Search for user in LDAP
         String userDN = findUserDN(searchContext);
         if (referralUserAttributeIDToCheck != null)
         {
            if (isUserDnAbsolute(userDN))
            {
                referralUserDNToCheck = localUserDN(userDN);
            }
            else 
            {
               referralUserDNToCheck = userDN;
            }
         }
         
         // If authentication required authenticate as user
         if (super.loginOk == false)
         {
            authenticate(userDN);
         }

         if (super.loginOk)
         {
            // Search for roles in LDAP
            rolesSearch(searchContext, userDN);
         }
      }
      finally
      {
         if (searchContext != null)
         {
            try
            {
               searchContext.close();
            }
            catch (NamingException e)
            {
               log.warn("Error closing context", e);
            }
         }
      }

      return Boolean.valueOf(super.loginOk);
   }

   private Properties constructLdapContextEnvironment(String namingProviderURL, String principalDN, Object credential, String authentication) 
   {
       Properties env = createBaseProperties();

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
       String providerURL = null;
       if (namingProviderURL != null)
       {
          providerURL = namingProviderURL;
       }
       else
       {
          providerURL = (String) options.get(Context.PROVIDER_URL);
       }
       String protocol = env.getProperty(Context.SECURITY_PROTOCOL);
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
       }
       env.setProperty(Context.PROVIDER_URL, providerURL);

       // Assume the caller of this method has checked the requirements for the principal and
       // credentials.
       if (principalDN != null)
          env.setProperty(Context.SECURITY_PRINCIPAL, principalDN);
       if (credential != null)
          env.put(Context.SECURITY_CREDENTIALS, credential);
       traceLdapEnv(env);
       return env;
   }

   protected LdapContext constructLdapContext(String namingProviderURL, String dn, Object credential, String authentication)
         throws LoginException
   {
      try
      {
          Properties env = constructLdapContextEnvironment(namingProviderURL, dn, credential, authentication);
          return new InitialLdapContext(env, null);
      }
      catch (NamingException e)
      {
         LoginException le = new LoginException("Unable to create new InitialLdapContext");
         le.initCause(e);
         throw le;
      }
   }

   protected Properties createBaseProperties()
   {
      Properties env = new Properties();
      Iterator iter = options.entrySet().iterator();
      while (iter.hasNext())
      {
         Entry entry = (Entry) iter.next();
         env.put(entry.getKey(), entry.getValue());
      }

      return env;
   }

   protected String findUserDN(LdapContext ctx) throws LoginException
   {

      if (baseCtxDN == null)
      {
         return getIdentity().getName();
      }

      try
      {
         NamingEnumeration results = null;

         Object[] filterArgs =
         {getIdentity().getName()};
         
         LdapContext ldapCtx = ctx;

         boolean referralsLeft = true;
         SearchResult sr = null;
         while (referralsLeft) 
         {
            try 
            {
               results = ldapCtx.search(baseCtxDN, baseFilter, filterArgs, userSearchControls);
               while (results.hasMore()) 
               {
                  sr = (SearchResult) results.next();
                  break;
               }
               referralsLeft = false;
            }
            catch (ReferralException e) 
            {
               ldapCtx = (LdapContext) e.getReferralContext();
               if (results != null) 
               {
                  results.close();
               }
            }
         }
         
         if (sr == null)
         {
            results.close();
            throw new LoginException("Search of baseDN(" + baseCtxDN + ") found no matches");
         }
         
         String name = sr.getName();
         String userDN = null;
         if (sr.isRelative() == true) 
         {
            userDN = new CompositeName(name).get(0) + "," + baseCtxDN;
         }
         else
         {
            userDN = sr.getName();
         }

         results.close();
         results = null;

         if (trace) {
            log.trace("findUserDN - " + userDN);
         }
         return userDN;
      }
      catch (NamingException e)
      {
         LoginException le = new LoginException("Unable to find user DN");
         le.initCause(e);
         throw le;
      }
   }
   
   private void referralAuthenticate(String absoluteName, Object credential)
           throws LoginException
   {
       URI uri;
       try 
       {
           uri = new URI(absoluteName);
       } 
       catch (URISyntaxException e)  
       {
           LoginException le = new LoginException("Unable to find user DN in referral LDAP");
           le.initCause(e);
           throw le;
       }
       String name = localUserDN(absoluteName);
       String namingProviderURL = uri.getScheme() + "://" + uri.getAuthority();
       
       InitialLdapContext refCtx = null;
       
       try 
       {
          Properties refEnv = constructLdapContextEnvironment(namingProviderURL, name, credential, null);
          refCtx = new InitialLdapContext(refEnv, null);
          refCtx.close();

       }
       catch (NamingException e)
       {
          LoginException le = new LoginException("Unable to create referral LDAP context");
          le.initCause(e);
          throw le;   
       }
       
   }

   private String localUserDN(String absoluteDN) {
      try 
      {
         URI userURI = new URI(absoluteDN);
         return userURI.getPath().substring(1);
      }
      catch (URISyntaxException e)
      {
         return null;
      }  
   }
   
   /**
    * Checks whether userDN is absolute URI, like the one pointing to an LDAP referral.
    * @param userDN
    * @return
    */
   private Boolean isUserDnAbsolute(String userDN) {
      try 
      {
         URI userURI = new URI(userDN);
         return userURI.isAbsolute();
      }
      catch (URISyntaxException e)
      {
         return false;
      }  
   }
   
   protected void authenticate(String userDN) throws LoginException
   {
      char[] credential = getCredential();
      if (credential.length == 0)
      {
         if (allowEmptyPassword == false)
         {
            log.trace("Rejecting empty password.");
            return;
         }
      }

      if (isUserDnAbsolute(userDN))
      {
         // user object resides in referral 
         referralAuthenticate(userDN, credential);
      }
      else 
      {
         // non referral user authentication 
         try
         {
            LdapContext authContext = constructLdapContext(null, userDN, credential, null);
            authContext.close();
         }
         catch (NamingException ne)
         {
            if (log.isDebugEnabled())
               log.debug("Authentication failed - " + ne.getMessage());
            LoginException le = new LoginException("Authentication failed");
            le.initCause(ne);
            throw le;
         }
      }
      super.loginOk = true;
      if (getUseFirstPass() == true)
      { // Add the username and password to the shared state map
         sharedState.put("javax.security.auth.login.name", getIdentity().getName());
         sharedState.put("javax.security.auth.login.password", credential);
      }

   }

   protected void rolesSearch(LdapContext searchContext, String dn) throws LoginException
   {
      /*
       * The distinguished name passed into this method is expected to be unquoted.
       */
      Object[] filterArgs = null;
      if (isUserDnAbsolute(dn))
      {
         filterArgs = new Object[] {getIdentity().getName(), localUserDN(dn)};
      }
      else
      {
         filterArgs = new Object[] {getIdentity().getName(), dn};
      }

      NamingEnumeration results = null;
      try
      {
         if (trace) {
            log.trace("rolesCtxDN=" + rolesCtxDN + " roleFilter=" + roleFilter + " filterArgs[0]=" + filterArgs[0]
               + " filterArgs[1]=" + filterArgs[1]);
         }

         if (roleFilter != null && roleFilter.length() > 0)
         {
            boolean referralsExist = true;
            while (referralsExist)
            {
               try
               {
                  results = searchContext.search(rolesCtxDN, roleFilter, filterArgs, roleSearchControls);
                  while (results.hasMore())
                  {
                     SearchResult sr = (SearchResult) results.next();
                     String resultDN = null;
                     if (sr.isRelative())
                     {
                        resultDN = canonicalize(sr.getName());
                     }
                     else
                     {
                        resultDN = sr.getNameInNamespace();
                     }
                     /*
                      * By this point if the distinguished name needs to be quoted for attribute
                      * searches it will have been already.
                      */
                     obtainRole(searchContext, resultDN, sr);
                  }
                  referralsExist = false;
               }
               catch (ReferralException e)
               {
                  searchContext = (LdapContext) e.getReferralContext();
               }
            }
         }
         else
         {
            /*
             * As there was no search based on the distinguished name it would not have been
             * auto-quoted - do that here to be safe.
             */
            obtainRole(searchContext, quoted(dn), null);
         }
      }
      catch (NamingException e)
      {
         LoginException le = new LoginException("Error finding roles");
         le.initCause(e);
         throw le;
      }
      finally
      {
         if (results != null)
         {
            try
            {
               results.close();
            }
            catch (NamingException e)
            {
               log.warn("Problem closing results", e);
            }
         }
      }

   }

   private String quoted(final String dn) {
       String temp = dn.trim();

       if (temp.startsWith("\"") && temp.endsWith("\"")) {
           return temp;
       }

       return "\"" + temp + "\"";
   }

   protected void obtainRole(LdapContext searchContext, String dn, SearchResult sr) throws NamingException, LoginException
   {
      if (trace) {
         log.trace("rolesSearch resultDN = " + dn);
      }

      String[] attrNames =
      {roleAttributeID};

      Attributes result = null;
      if (sr == null || sr.isRelative())
      {
         result = searchContext.getAttributes(dn, attrNames);
      }
      else
      {
         result = getAttributesFromReferralEntity(sr);
      }
      if (result != null && result.size() > 0)
      {
         Attribute roles = result.get(roleAttributeID);
         for (int n = 0; n < roles.size(); n++)
         {
            String roleName = (String) roles.get(n);
            if (roleAttributeIsDN)
            {
               // Query the roleDN location for the value of roleNameAttributeID
               String roleDN = "\"" + roleName + "\"";

               loadRoleByRoleNameAttributeID(searchContext, roleDN);
               recurseRolesSearch(searchContext, roleName);
            }
            else
            {
               // The role attribute value is the role name
               addRole(roleName);
            }
         }
      }
   }

   private Attributes getAttributesFromReferralEntity(SearchResult sr) throws NamingException
   {
      Attributes result = sr.getAttributes();
      boolean chkSuccessful = false;
      if (referralUserAttributeIDToCheck != null)
      {
         Attribute usersToCheck = result.get(referralUserAttributeIDToCheck);
         for (int i = 0; usersToCheck != null && i < usersToCheck.size(); i++)
         {
            String userDNToCheck = (String) usersToCheck.get(i);
            if (userDNToCheck.equals(referralUserDNToCheck))
            {
               chkSuccessful = true;
               break;
            }
            if (userDNToCheck.equals(getIdentity().getName()))
            {
               chkSuccessful = true;
               break;
            }
         }
      }
      return (chkSuccessful ? result : null);
   }

   protected void loadRoleByRoleNameAttributeID(LdapContext searchContext, String roleDN)
   {
      String[] returnAttribute = {roleNameAttributeID};
      if (trace) {
         log.trace("Using roleDN: " + roleDN);
      }
      try
      {
         Attributes result2 = searchContext.getAttributes(roleDN, returnAttribute);
         Attribute roles2 = result2.get(roleNameAttributeID);
         if (roles2 != null)
         {
            for (int m = 0; m < roles2.size(); m++)
            {
               String roleName = (String) roles2.get(m);
               addRole(roleName);
            }
         }
      }
      catch (NamingException e)
      {
         if (trace) {
            log.trace("Failed to query roleNameAttrName", e);
         }
      }
   }

   protected void recurseRolesSearch(LdapContext searchContext, String roleDN) throws LoginException
   {
      if (recurseRoles)
      {
         if (processedRoleDNs.contains(roleDN) == false)
         {
            processedRoleDNs.add(roleDN);
            if (trace) {
               log.trace("Recursive search for '" + roleDN + "'");
            }
            rolesSearch(searchContext, roleDN);
         }
         else
         {
            if (trace) {
               log.trace("Already visited role '" + roleDN + "' ending recursion.");
            }
         }
      }
   }

   protected void traceLdapEnv(Properties env)
   {
      if (trace)
      {
         Properties tmp = new Properties();
         tmp.putAll(env);
         String credentials = tmp.getProperty(Context.SECURITY_CREDENTIALS);
         if (credentials != null && credentials.length() > 0)
            tmp.setProperty(Context.SECURITY_CREDENTIALS, "***");
         log.trace("Logging into LDAP server, env=" + tmp.toString());
      }
   }

   protected String canonicalize(String searchResult)
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
            if (trace) {
               log.trace("Assign user '" + getIdentity().getName() + "' to role " + roleName);
            }
            userRoles.addMember(p);
         }
         catch (Exception e)
         {
            if (log.isDebugEnabled())
               log.debug("Failed to create principal: " + roleName, e);
         }
      }
   }

   private class AuthorizeAction implements PrivilegedAction<Object>
   {

      public Object run()
      {
         try
         {
            return innerLogin();
         }
         catch (LoginException e)
         {
            return e;
         }
      }

   }

}
