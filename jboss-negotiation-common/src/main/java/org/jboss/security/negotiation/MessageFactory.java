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

package org.jboss.security.negotiation;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;

/**
 * The base message factory for reading messages from InputStreams and
 * creating the Java representation of the message.
 * 
 * @author darran.lofthouse@jboss.com
 * @since 10th August 2008
 * @version $Revision$
 */
public abstract class MessageFactory
{

   private static final Logger log = Logger.getLogger(MessageFactory.class);

   private static final String NTLM_MESSAGE_FACTORY_NAME = "org.jboss.security.negotiation.ntlm.NTLMMessageFactory";

   private static final String SPNEGO_MESSAGE_FACTORY_NAME = "org.jboss.security.negotiation.spnego.SPNEGOMessageFactory";
   
   private static final String KERBEROS_MESSAGE_FACTORY_NAME = "org.jboss.security.negotiation.spnego.KerberosMessageFactory";

   private static final Class<MessageFactory> NTLM_MESSAGE_FACTORY;

   private static final Class<MessageFactory> SPNEGO_MESSAGE_FACTORY;
   
   private static final Class<MessageFactory> KERBEROS_MESSAGE_FACTORY;

   static
   {
      NTLM_MESSAGE_FACTORY = loadClass(NTLM_MESSAGE_FACTORY_NAME);
      SPNEGO_MESSAGE_FACTORY = loadClass(SPNEGO_MESSAGE_FACTORY_NAME);
      KERBEROS_MESSAGE_FACTORY = loadClass(KERBEROS_MESSAGE_FACTORY_NAME);
   }

   /**
    * Return the specified class or null if it can not be loaded.
    */
   @SuppressWarnings("unchecked")
   private static Class<MessageFactory> loadClass(final String classname)
   {
      ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
      Class<MessageFactory> clazz = null;

      try
      {
         clazz = (Class<MessageFactory>) classLoader.loadClass(classname);
      }
      catch (Exception e)
      {
         if (log.isTraceEnabled())
            log.trace("Unable to load class '" + classname + "'", e);
      }

      return clazz;
   }

   /**
    * @return a new MessageFactory to process a message available from an InputStream.
    */
   public static MessageFactory newInstance() throws NegotiationException
   {
      MessageFactory ntlm = newInstance(NTLM_MESSAGE_FACTORY);
      MessageFactory spnego = newInstance(SPNEGO_MESSAGE_FACTORY);
      MessageFactory kerberos = newInstance(KERBEROS_MESSAGE_FACTORY);

      List<MessageFactory> delegates = new ArrayList<MessageFactory>(3);
      if (ntlm != null)
      {
         delegates.add(ntlm);
      }
      if (spnego != null)
      {
         delegates.add(spnego);
      }
      if (kerberos != null)
      {
         delegates.add(kerberos);
      }

      if (delegates.size() == 1)
      {
         return delegates.get(0);
      }
      else if (delegates.size() > 1)
      {
         return new DelegatingMessageFactory(delegates);
      }

      throw new IllegalStateException("No MessageFactories available to instantiate");
   }

   private static MessageFactory newInstance(final Class<MessageFactory> clazz) throws NegotiationException
   {
      MessageFactory response = null;

      if (clazz != null)
      {
         try
         {
            response = clazz.newInstance();
         }
         catch (Exception e)
         {
            throw new NegotiationException("Unable to instantiate '" + clazz.getName() + "'", e);
         }

      }

      return response;
   }

   /**
    * Peek at the data in the InputStream and return true if this
    * MessageFactory can handle the data.
    */
   public abstract boolean accepts(final InputStream in) throws IOException;

   /**
    * Read the message from the InputStream and create the Java
    * representation of the message.
    */
   public abstract NegotiationMessage createMessage(final InputStream in) throws IOException;

}
