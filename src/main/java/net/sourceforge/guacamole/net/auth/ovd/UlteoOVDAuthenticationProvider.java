package net.sourceforge.guacamole.net.auth.ovd;

/*
 *  Guacamole - Clientless Remote Desktop
 *  Copyright (C) 2010  Michael Jumper
 *  Copyright (C) 2012  ULTEO-LICENSE-TODO
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.BufferedReader;
import net.sourceforge.guacamole.net.auth.AuthenticationProvider;
import net.sourceforge.guacamole.net.auth.Credentials;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.ContentHandler;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.cookie.CookiePolicy;
import org.apache.commons.httpclient.methods.GetMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

/**
 * Authenticates users against a static list of username/password pairs. Each
 * username/password may be associated with exactly one configuration. This list
 * is stored in an XML file which is reread if modified.
 * 
 * @author Michael Jumper
 * @author Jocelyn Delalande
 */
public class UlteoOVDAuthenticationProvider implements
		AuthenticationProvider {

	private Logger logger = LoggerFactory
			.getLogger(UlteoOVDAuthenticationProvider.class);

	@Override
	public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(
			Credentials credentials) throws GuacamoleException {

		// We store the phpSessionID in the username field, as we are forced to use a 
		// login/pass scheme for storage
		String phpSessionID = credentials.getUsername();
		String url = "http://localhost/ovd/servers.php";
		ServerFileContentHandler contentHandler;
		// Parse XML document
		try {

			// Set up XML parser
			contentHandler = new ServerFileContentHandler();
			XMLReader parser = XMLReaderFactory.createXMLReader();
			parser.setContentHandler(contentHandler);

			// Fetch XML from webclient server
			logger.info("Reading servers.xml from "+url);
			HttpClient client = new HttpClient();
	        HttpMethod method = new GetMethod(url);
	        method.getParams().setCookiePolicy(CookiePolicy.IGNORE_COOKIES);
	        method.setRequestHeader("Cookie", "PHPSESSID="+phpSessionID);
	        
	        client.executeMethod(method);
	        

	        
			// Fetch read and parse file
			Reader reader = new BufferedReader(new InputStreamReader(method.getResponseBodyAsStream()));
			parser.parse(new InputSource(reader));
			reader.close();


		} catch (IOException e) {
			throw new GuacamoleException(
					"Error fetching XML from webclient server at "+url, e);
		} catch (SAXException e) {
			throw new GuacamoleException(
						     "Error parsing webclient server XML file : " + e.getMessage(), e);
		}



		Map<String, GuacamoleConfiguration> configs = contentHandler.getConfigs();
		if  (configs.containsKey("DEFAULT")) {
			return configs;
		} else {
			// No config for that phpsessid
			return null;
		}	
	}

	private static class ServerFileContentHandler extends DefaultHandler {

		private enum State {
			ROOT, SESSION, SETTINGS, SETTING, USER, APPLICATION, MIME, SERVER, PARAMETER, END, PROFILE;
		}

		private State state = State.ROOT;
		private Map<String, GuacamoleConfiguration> configs = new HashMap<String, GuacamoleConfiguration>();

		@Override
		public void endElement(String uri, String localName, String qName)
				throws SAXException {

			switch (state) {

			case SESSION:
				if (localName.equals("session")) {
					state = State.END;
					return;
				}

			case SETTINGS:
				if (localName.equals("settings")) {
					state = State.SESSION;
					return;
				}

			case SETTING:
				if (localName.equals("setting")) {
					state = State.SETTINGS;
					return;
				}

			case SERVER:
				if (localName.equals("server")) {
					state = State.SESSION;
					return;
				}

			case APPLICATION:
				if (localName.equals("application")) {
					state = State.SERVER;
					return;
				}
			case MIME:
				if (localName.equals("mime")) {
					state = State.APPLICATION;
					return;
				}
			case USER:
				if (localName.equals("user")) {
					state = State.SESSION;
					return;
				}
			case PROFILE:
				if (localName.equals("profile")) {
					state = State.SESSION;
					return;
				}


			}
			throw new SAXException("Unexpected closing: " + localName);
		}

		@Override
		public void startElement(String uri, String localName, String qName,
				Attributes attributes) throws SAXException {

			switch (state) {

			// Document must be <user-mapping>
			case ROOT:

				if (localName.equals("session")) {
					state = State.SESSION;
					return;
				}

				// Only <authorize> tags allowed in main document
			case SESSION:

				if (localName.equals("server")) {
					GuacamoleConfiguration config = new GuacamoleConfiguration();
					
					// RDP-plugin accepted parameters are in libguac-client-rdp/src/client.c
					config.setProtocol("rdp");
					config.setParameter("hostname", attributes.getValue("fqdn"));
					config.setParameter("username", attributes.getValue("login"));
					config.setParameter("password", attributes.getValue("password"));
					

					//FIXME: for seamless, do not just put one server as default...
					configs.put("DEFAULT", config);
					
					// Next state
					state = State.SERVER;
					return;

				} else if (localName.equals("settings")) {
					state = State.SETTINGS;
					return;
				} else if (localName.equals("user")) {
					state = State.USER;
					return;
				} else if (localName.equals("profile")) {
					state = State.PROFILE;
					return;
				}

			case SETTINGS:
				if (localName.equals("setting")) {
					// Next state
					state = State.SETTING;
					return;
				}

			case SERVER:
				if (localName.equals("application")) {
					state = State.APPLICATION;
					return;
				}

			case APPLICATION:
				if (localName.equals("mime")) {
					state = State.MIME;
					return;
				}

			}
			throw new SAXException("Unexpected tag : " + localName);
		}

	
		/**
		 * @return hashmap of RDP servers credentials. One of the map key is "DEFAULT"
		 * @FIXME here can be handled properly multiple servers for seamless
		 */
        public Map<String, GuacamoleConfiguration> getConfigs() {
            return Collections.unmodifiableMap(this.configs);
        }

	}

}
