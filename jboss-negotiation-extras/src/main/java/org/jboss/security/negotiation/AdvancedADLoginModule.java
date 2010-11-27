/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc. and/or its affiliates, and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Properties;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.security.auth.login.LoginException;

import org.jboss.util.Base64;

/**
 * An extension of the AdvancedLdapLoginModule to also query the primary group
 * of the user being authenticated - this is not discoverable using the usual 
 * member and memberOf attributes.
 * 
 * @author darran.lofthouse@jboss.com
 */
public class AdvancedADLoginModule extends AdvancedLdapLoginModule
{

   private static final String PRIMARY_GROUP_ID = "primaryGroupID";

   private static final String OBJECT_SID = "objectSid";

   /*
    * The rolesSearch method is called recursively, we need to ensure it is only called once 
    * as we are only looking for the primary group of the user.
    */
   private boolean skipPrimaryGroupSearch = false;

   @Override
   protected Properties createBaseProperties()
   {
      Properties env = super.createBaseProperties();
      env.put("java.naming.ldap.attributes.binary", "objectSid");
      return env;
   }

   @Override
   protected void rolesSearch(LdapContext searchContext, String dn) throws LoginException
   {
      boolean TRACE = log.isTraceEnabled();
      if (skipPrimaryGroupSearch == false)
      {
         skipPrimaryGroupSearch = true;

         try
         {
            String[] attrNames =
            {OBJECT_SID, PRIMARY_GROUP_ID};
            Attributes result = searchContext.getAttributes(dn, attrNames);
            Attribute primaryGroupIdAttribute = result.get(PRIMARY_GROUP_ID);
            Attribute objectSidAttribute = result.get(OBJECT_SID);
            if (primaryGroupIdAttribute != null && objectSidAttribute != null)
            {
               int primaryGroupId = Integer.parseInt((String) primaryGroupIdAttribute.get());
               byte[] objectSid = (byte[]) objectSidAttribute.get();

               /*
                * The objectSid of the primary group can be found by taking the object sid
                * of the user and replacing the last four bytes with the little endian representation
                * of the primary group id - this new byte[] can then be used in the search.
                */

               byte[] searchObjectSid = new byte[objectSid.length];
               System.arraycopy(objectSid, 0, searchObjectSid, 0, objectSid.length - 4);

               ByteBuffer byteBuffer = ByteBuffer.wrap(searchObjectSid, objectSid.length - 4, 4);
               byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
               byteBuffer.putInt(primaryGroupId);

               if (TRACE)
               {
                  String objectSidBase64 = Base64.encodeBytes(objectSid);
                  String searchObjectSidBase64 = Base64.encodeBytes(searchObjectSid);
                  log.trace("Using base objectSid " + objectSidBase64 + " and replaced with primary group id "
                        + primaryGroupId + " to create new search objectSid " + searchObjectSidBase64);
               }

               String primaryGroupFilter = "(objectSid={0})";
               Object[] filterArgs =
               {searchObjectSid};

               NamingEnumeration searchResults = searchContext.search(baseCtxDN, primaryGroupFilter, filterArgs,
                     roleSearchControls);
               if (searchResults.hasMore() == true)
               {
                  SearchResult searchResult = (SearchResult) searchResults.next();
                  String baseResultDN = canonicalize(searchResult.getName());
                  String resultDN = "\"" + baseResultDN + "\"";

                  if (TRACE)
                  {
                     log.trace("Search found primary group " + resultDN);
                  }

                  loadRoleByRoleNameAttributeID(searchContext, resultDN);
                  recurseRolesSearch(searchContext, baseResultDN);
               }

            }
            else
            {
               log.trace("primaryGroupIdAttribute or objectSidAttribute was null, skipping primary group search.");
            }

            super.rolesSearch(searchContext, dn);
         }
         catch (NamingException e)
         {
            if (TRACE)
               log.trace("Failed to load primary group", e);
         }
         finally
         {
            skipPrimaryGroupSearch = false;
         }
      }
      else
      {
         super.rolesSearch(searchContext, dn);
      }

   }
}
