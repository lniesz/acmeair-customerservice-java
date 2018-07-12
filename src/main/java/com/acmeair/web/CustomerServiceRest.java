/*******************************************************************************
 * Copyright (c) 2013 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package com.acmeair.web;

import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import com.acmeair.service.CustomerService;
import com.acmeair.web.dto.AddressInfo;
import com.acmeair.web.dto.CustomerInfo;

import javax.annotation.security.RolesAllowed;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.metrics.annotation.Timed;

@Path("/")
public class CustomerServiceRest {

  @Inject
  CustomerService customerService;
 
  @Inject
  private JsonWebToken jwt;

  private static final Logger logger = Logger.getLogger(CustomerServiceRest.class.getName());

  private static final JsonReaderFactory rfactory = Json.createReaderFactory(null);

  /**
   * Get customer info.
   */
  @GET
  @RolesAllowed({ "admin", "user" })
  @Path("/byid/{custid}")
  @Produces("text/plain")
  @Timed(name="com.acmeair.web.CustomerServiceRest.getCustomer", tags = "app=customerservice-java")
  public Response getCustomer(@PathParam("custid") String customerid, 
      @CookieParam("jwt_token") String jwtToken) {
    
    if (logger.isLoggable(Level.FINE)) {
      logger.fine("getCustomer : userid " + customerid);
    }

    if (!jwt.getGroups().contains("admin") && !customerid.equals(jwt.getSubject())) {
      return Response.status(Response.Status.FORBIDDEN).build();
    }

    return Response.ok(customerService.getCustomerByUsername(customerid)).build();

  } 

/**
 * Update customer.
 */
@POST
@RolesAllowed({ "admin", "user" })
@Path("/byid/{custid}")
@Produces("text/plain")
@Timed(name="com.acmeair.web.CustomerServiceRest.putCustomer", tags = "app=customerservice-java")
public Response putCustomer(CustomerInfo customer, @CookieParam("jwt_token") String jwtToken,
    @PathParam("custid") String customerid ) {

  String username = customer.get_id();       

  if (!jwt.getGroups().contains("admin") && !customerid.equals(jwt.getSubject())) {
    return Response.status(Response.Status.FORBIDDEN).build();
  }

  String customerFromDb = customerService
      .getCustomerByUsernameAndPassword(username, customer.getPassword());

  if (logger.isLoggable(Level.FINE)) {
    logger.fine("putCustomer : " + customerFromDb);
  }

  if (customerFromDb == null) {
    // either the customer doesn't exist or the password is wrong
    return Response.status(Response.Status.FORBIDDEN).build();
  }

  customerService.updateCustomer(username, customer);

  // Retrieve the latest results
  customerFromDb = customerService
      .getCustomerByUsernameAndPassword(username, customer.getPassword());

  return Response.ok(customerFromDb).build();
}

/**
 * Validate user/password.
 */
@POST
@RolesAllowed({ "admin"})
@Path("/validateid")
@Consumes({ "application/x-www-form-urlencoded" })
@Produces("application/json")
@Timed(name="com.acmeair.web.CustomerServiceRest.validateCustomer", tags = "app=customerservice-java")
public LoginResponse validateCustomer(@FormParam("login") String login, @FormParam("password") String password) {

  if (logger.isLoggable(Level.FINE)) {
    logger.fine("validateid : login " + login + " password " + password);
  }
  
  if (!customerService.isPopulated()) {
    throw new RuntimeException("Customer DB has not been populated");
  }

  
  
  Boolean validCustomer = customerService.validateCustomer(login, password);

  return new LoginResponse(validCustomer); 
}

/**
 * Update reward miles.
 */
@POST
@RolesAllowed({ "admin", "user" })
@Path("/updateCustomerTotalMiles/{custid}")
@Consumes({ "application/x-www-form-urlencoded" })
@Produces("application/json")
@Timed(name="com.acmeair.web.CustomerServiceRest.updateCustomerTotalMiles", tags = "app=customerservice-java")
public MilesResponse updateCustomerTotalMiles(@PathParam("custid") String customerid, @FormParam("miles") Long miles) {

  if (!jwt.getGroups().contains("admin") && !customerid.equals(jwt.getSubject())) {
    return null;
  }
  
  JsonReader jsonReader = rfactory.createReader(new StringReader(customerService
      .getCustomerByUsername(customerid)));

  JsonObject customerJson = jsonReader.readObject();
  jsonReader.close();


  JsonObject addressJson = customerJson.getJsonObject("address");

  String streetAddress2 = null;

  if (addressJson.get("streetAddress2") != null 
      && !addressJson.get("streetAddress2").toString().equals("null")) {
    streetAddress2 = addressJson.getString("streetAddress2");
  }

  AddressInfo addressInfo = new AddressInfo(addressJson.getString("streetAddress1"), 
      streetAddress2,
      addressJson.getString("city"), 
      addressJson.getString("stateProvince"),
      addressJson.getString("country"),
      addressJson.getString("postalCode"));

  Long milesUpdate = customerJson.getInt("total_miles") + miles;
  CustomerInfo customerInfo = new CustomerInfo(customerid, 
      null, 
      customerJson.getString("status"),
      milesUpdate.intValue(), 
      customerJson.getInt("miles_ytd"), 
      addressInfo, 
      customerJson.getString("phoneNumber"),
      customerJson.getString("phoneNumberType"));

  customerService.updateCustomer(customerid, customerInfo);

  return new MilesResponse(milesUpdate);

}

@GET
public Response status() {
  return Response.ok("OK").build();

}
}
