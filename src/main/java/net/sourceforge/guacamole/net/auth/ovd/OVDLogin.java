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

import net.sourceforge.guacamole.net.auth.AuthenticationProvider;
import net.sourceforge.guacamole.net.auth.Credentials;

import java.io.IOException;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Queries RDP credentials from Ulteo OVD SessionManager for a given SessionManager HTTP SESSID
 * 
 * All authorized configurations will be stored in the current HttpSession.
 * 
 * Success and failure are logged.
 * 
 * @author Michael Jumper, Jocelyn Delalande
 */
public class OVDLogin extends HttpServlet {
    /**
     * The session attribute holding the map of configurations.
     */
    private static final String CONFIGURATIONS_ATTRIBUTE = "GUAC_CONFIGS";
    
    /**
     * The session attribute holding the credentials authorizing this session.
     */
    private static final String CREDENTIALS_ATTRIBUTE = "GUAC_CREDS";
	
    //TODO
    private Logger logger = LoggerFactory.getLogger(OVDLogin.class);
    
    private AuthenticationProvider authProvider;

    @Override
    public void init() throws ServletException {

        // Get auth provider instance

            authProvider = new UlteoOVDAuthenticationProvider();

    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
    throws IOException {

        HttpSession httpSession = request.getSession(true);

		// We store the phpSessionID in the username field, as we are forced to use a 
		// login/pass scheme for storage
    	Credentials credentials = new Credentials();
    	
        // Retrieve the session ID used with PHP OVD webservices
        String webClientSessionID = request.getParameter("webclient_PHPSESSID");
        
        // Get authorized configs
        Map<String, GuacamoleConfiguration> configs;
        try {
        	credentials.setUsername(webClientSessionID);
            configs = authProvider.getAuthorizedConfigurations(credentials);
        }
        catch (GuacamoleException e) {
            logger.error(e.getMessage());
            logger.error("Error retrieving configuration(s) for webclient webservices with PHPSESSID {}{}", webClientSessionID);
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        
        if (configs == null) {
            logger.warn("Failed to get RDP details from {} for PHP SESSION\"{}\".", request.getRemoteAddr(), webClientSessionID);
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        logger.info("Successful fetching of RDP details from {} for Session ID {}.", request.getRemoteAddr(), webClientSessionID);

		// Set client-side resolution
        GuacamoleConfiguration defaultConfig = configs.get("DEFAULT");
        if (request.getParameter("width") != null && request.getParameter("height") != null) {	
        	configs.get("DEFAULT").setParameter("width", request.getParameter("width"));
        	configs.get("DEFAULT").setParameter("height", request.getParameter("height"));
        } else {
        	logger.info("No dimensions specified...");
        }
        	
        // Associate configs with session
        httpSession.setAttribute(CONFIGURATIONS_ATTRIBUTE, configs);
        httpSession.setAttribute(CREDENTIALS_ATTRIBUTE, credentials);

    }

}

