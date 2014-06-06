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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.ui.dao.ConditionDAO;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code Condition}
 * 
 * @author Salman Ansari <10besesansari@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class ConditionController {

	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(ConditionController.class.getName());

	/**
	 * An instance of {@code ConditionDAO} for using methods to access data
	 * related to {@code Condition}
	 */
	ConditionDAO dao = new ConditionDAO();
	/**
	 * An ArrayList of {@code Condition} used to display all the existing
	 * {@code Condition}s stored in the database.
	 */
	ArrayList<Condition> allCondition = new ArrayList<Condition>();
	/**
	 * An instance of {@code Condition} used to store the {@code Condition}
	 * selected by the user from the user interface.
	 */
	Condition selectedCondition = new Condition();

	/**
	 * Sets the {@code selectedCondition} property to {@code Condition} argument
	 * 
	 * @param selectedCondition
	 */
	public void setSelectedCondition(Condition selectedCondition) {
		log.debug("Condition Selected: " + selectedCondition);
		this.selectedCondition = selectedCondition;
	}

	/**
	 * Sets the {@code dao} property to {@code ConditionDAO} argument
	 * 
	 * @param dao
	 */
	public void setDao(ConditionDAO dao) {
		log.debug("Condition dao: " + dao);
		this.dao = dao;
	}

	/**
	 * Sets the {@code allCondition} property to {@code ArrayList<Condition>} argument
	 * 
	 * @param allCondition
	 */
	public void setAllCondition(ArrayList<Condition> allCondition) {
		log.debug("Condition allCondition: " + allCondition);
		this.allCondition = allCondition;
	}

	/*------------------------------------------------------------------------------------*/
	/*------------------------------------------------------------------------------------*/
	/**
	 * Returns the value of {@code dao} property
	 * 
	 * @return dao
	 */
	public ConditionDAO getDao() {
		log.debug("Get  dao: " + dao);
		return dao;
	}

	/**
	 * Returns the value of {@code selectedCondition} property
	 * 
	 * @return selectedCondition
	 */
	public Condition getSelectedCondition() {
		log.debug("Get  selectedCondition: " + selectedCondition);
		return selectedCondition;
	}

	/**
	 * Returns the value of {@code allCondition} property
	 * 
	 * @return allCondition
	 */
	public ArrayList<Condition> getAllCondition() {
		log.debug("Get  allCondition: " + allCondition);
		allCondition = (ArrayList<Condition>) dao.selectCondition();
		return allCondition;
	}

	/*------------------------------------------------------------------------------------*/
	/*------------------------------------------------------------------------------------*/
	/**
	 * Opens the {@code  /Policy Creation/Condition/AddCondition.xhtml} page for
	 * creating a new {@code Condition} instance.
	 */
	public String addCondition() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 550);
		options.put("width", 1200);
		options.put("contentHeight", 500);
		options.put("contentWidth", 1150);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Condition/AddCondition in a dialog.");

		context.openDialog("/Policy Creation/Condition/AddCondition", options,
				null);

		return null;
	}

	/*------------------------------------------------------------------------------------*/
	/*------------------------------------------------------------------------------------*/
	/**
	 * Deletes an instance of {@code Condition} stored in
	 * {@code selectedCondition} property
	 */
	public void deleteCondition() {
		log.info("Condition Deleted");
		dao.deleteCondition(selectedCondition);
	}

}
