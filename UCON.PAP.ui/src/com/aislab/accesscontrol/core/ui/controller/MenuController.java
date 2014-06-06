/******************************************************************************
 * Project:    Extensible Access Control Framework for Cloud based Applications.
 *                     http://ais.seecs.nust.edu.pk/project/ 
 * Developed by: KTH- Applied Information Security Lab (AIS), 
 *                       NUST-SEECS, H-12 Campus, 
 *                       Islamabad, Pakistan. 
 *                       www.ais.seecs.nust.edu.pk
 * Funded by: National ICT R&D Fund, Ministry of Information Technology & Telecom,
 *                  http://www.ictrdf.org.pk/
 * Copyright (c) 2013-2015 All Rights Reserved, AIS-SEECS NUST & National ICT R&D Fund

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy and/or modify the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/
package com.aislab.accesscontrol.core.ui.controller;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Logger;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code HomePage.xhtml}
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class MenuController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(MenuController.class.getName());
	/**
	 * A {@code String} variable to store the name of the page which is to be
	 * included in the center layout unit of the HomePage.xhtml.
	 */
	String page = "index";

	/**
	 * Returns the value of {@code page} property.
	 * 
	 * @return page
	 */
	public String getpage() {
		log.debug("Get  page: " + page);
		return this.page;
	}

	/**
	 * Sets the {@code page} property to the {@code String} argument.
	 * 
	 * @param p
	 */
	public void setpage(String p) {
		this.page = p;
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /System Learning/Subject/Subject.
	 */
	public void subject() {
		log.info("Opening /System Learning/Subject/Subject page in the center layout unit");
		this.page = "/System Learning/Subject/Subject";
		log.debug("Set  page: " + page);

	}

	/**
	 * Sets the {@code page} property to /System Learning/Resource/Resource.
	 */
	public void resource() {
		log.info("Opening /System Learning/Resource/Resource page in the center layout unit");
		this.page = "/System Learning/Resource/Resource";
		log.debug("Set  page: " + page);

	}

	/**
	 * Sets the {@code page} property to /System Learning/Action/Action.
	 */
	public void action() {
		log.info("Opening /System Learning/Action/Action page in the center layout unit");
		this.page = "/System Learning/Action/Action";
		log.debug("Set  page: " + page);

	}

	/**
	 * Sets the {@code page} property to /System
	 * Learning/Environment/Environment.
	 */
	public void environment() {
		log.info("Opening /System Learning/Environment/Environment page in the center layout unit");
		this.page = "/System Learning/Environment/Environment";
		log.debug("Set  page: " + page);
	}
	
	/**
	 * Sets the {@code page} property to /Policy Creation/Condition/Condition.
	 */
	public void condition() {
		log.info("Loading Condition.xhtml page.");
		this.page = "/Policy Creation/Condition/Condition";
	}

	/**
	 * Sets the {@code page} property to /Policy Creation/Rule/Rule.
	 */
	public void rule() {
		log.info("Opening /Policy Creation/Rule/Rule page in the center layout unit");
		this.page = "/Policy Creation/Rule/Rule";
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /Policy Creation/Target/Target.
	 */
	public void target() {
		log.info("Opening /Policy Creation/Target/Target page in the center layout unit");
		this.page = "/Policy Creation/Target/Target";
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /Policy Creation/Policy/Policy
	 */
	public void policy() {
		log.info("Opening /Policy Creation/Policy/Policy page in the center layout unit");

		this.page = "/Policy Creation/Policy/Policy";
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /Policy Creation/Policy Set/PolicySet
	 */
	public void policySet() {
		log.info("Opening /Policy Creation/Policy Set/PolicySet page in the center layout unit");

		this.page = "/Policy Creation/Policy Set/PolicySet";
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /XACML Generation/XacmlPolicyGeneration
	 */
	public void xacmlPolicy() {
		log.info("Opening /XACML Generation/XacmlPolicyGeneration page in the center layout unit");

		this.page = "/XACML Generation/XacmlPolicyGeneration";
		log.debug("Set  page: " + page);
	}

	/**
	 * Sets the {@code page} property to /XACML
	 * Generation/XacmlPolicySetGeneration
	 */
	public void xacmlPolicySet() {
		log.info("Opening /XACML Generation/XacmlPolicySetGeneration page in the center layout unit");

		this.page = "/XACML Generation/XacmlPolicySetGeneration";
		log.debug("Set  page: " + page);

	}
	public void uconPolicy(){
		System.out.println("UconPolicy Listener");
		this.page = "/Policy Creation/UCON Policy/AuthorizationAndCondition";
	}

}
