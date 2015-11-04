package net.wasdev.securemicroservices;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

/*
 * This end point is protected by the APIKey class
 * 
 * Copyright 2015 IBM Corp.
 */

@Path("/Name")
public class NameService {

	@GET
	public String getMessage(final @QueryParam("serviceID") String svcid, final @QueryParam("id") String id) {
		String msg = "Received params : \n\tserviceID = " + svcid + "\n\tid = " + id + "\nResponse to client : \n\t";
		/*
		 * Optionally at this point you would check that the service
		 * is entitled to make this call
		 */
		if(id == null) {
			return msg + "unknown user";
		}
		if(id.equals("1")) {
			return msg + "Number 1";
		}
		return msg + "normal user";
	}
	
}
