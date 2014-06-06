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
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.ActionMatch;
import com.aislab.accesscontrol.core.entities.EnvironmentMatch;
import com.aislab.accesscontrol.core.entities.ResourceMatch;
import com.aislab.accesscontrol.core.entities.SubjectMatch;
import com.aislab.accesscontrol.core.ui.dao.TargetDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Target} instance.
 * 
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class AddTargetController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddTargetController.class.getName());

	/**
	 * A {@code String} variable to store the value of {@code description}
	 * attribute of {@code Target} instance to be created.
	 */
	private String description;

	/**
	 * A {@code String} variable to store the value of {@code targetId}
	 * attribute of {@code Target} instance to be created.
	 */
	private String targetId;

	/**
	 * An instance of {@code TargetDAO} for using methods to access data related
	 * to {@code Target}
	 */
	TargetDAO daoTarget = new TargetDAO();

	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Target} instance. By default
	 * it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the {@code operationFail} property to {@code boolean} argument.
	 * 
	 * @param operationFail
	 */
	public void setOperationFail(boolean operationFail) {
		this.operationFail = operationFail;
		log.debug("Set  operationFail: " + operationFail);
	}

	/**
	 * Sets the {@code description} property to the {@code String} argument.
	 * 
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
		log.debug("Set  description: " + description);
	}

	/**
	 * Sets the {@code targetDao} property to the {@code TargetDAO} argument.
	 * 
	 * @param targetDao
	 */
	public void setDaoTarget(TargetDAO daoTarget) {
		this.daoTarget = daoTarget;
		log.debug("Set  daoTarget: " + daoTarget);
	}

	/**
	 * Sets the {@code targetId} property to the {@code String} argument.
	 * 
	 * @param targetId
	 */
	public void setTargetId(String targetId) {
		this.targetId = targetId;
		log.debug("Set  targetId: " + targetId);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns {@code FALSE} if a {@code Save} button was pressed otherwise
	 * {@code TRUE}.
	 * 
	 * @return operationFail
	 */
	public boolean isOperationFail() {
		log.debug("Get  operationFail: " + operationFail);
		return operationFail;

	}

	/**
	 * Returns the value of {@code targetId} property.
	 * 
	 * @return targetId
	 */
	public String getTargetId() {
		log.debug("Get  targetId: " + targetId);
		return targetId;
	}

	/**
	 * Returns the value of {@code targetDao} property.
	 * 
	 * @return targetDao
	 */
	public TargetDAO getDaoTarget() {
		log.debug("Get  daoTarget: " + daoTarget);
		return daoTarget;
	}

	/**
	 * Returns the value of {@code description} property.
	 * 
	 * @return description
	 */
	public String getDescription() {
		log.debug("Get  description: " + description);
		return description;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Saves the newly created instance of {@code Target} in the database.
	 */
	public void saveAddTarget() {
		RequestContext context = RequestContext.getCurrentInstance();

		List<SubjectMatch> subjectMatch = new ArrayList<SubjectMatch>();
		List<ActionMatch> actionMatch = new ArrayList<ActionMatch>();

		List<ResourceMatch> resourceMatch = new ArrayList<ResourceMatch>();

		List<EnvironmentMatch> environmentMatch = new ArrayList<EnvironmentMatch>();

		if (targetId == null) {
			log.info("Name cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Name cannot be empty."));

		}
		if (description == null) {
			log.info("Description cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Description cannot be empty."));

		}
		if (description != null && targetId != null) {

			daoTarget.createTarget(targetId, description, subjectMatch,
					actionMatch, resourceMatch, environmentMatch);

			targetId = null;
			description = null;
			this.operationFail = false;
			log.info("Closing dialog.");
			context.closeDialog(this);
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of adding a new {@code Target } instance in the
	 * database.
	 * 
	 * @return
	 */
	public void cancelAddTarget() {
		RequestContext context = RequestContext.getCurrentInstance();

		this.operationFail = true;

		this.description = null;
		this.targetId = null;
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Target Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Target Successfully"));

			this.setOperationFail(true);
		}

	}

}
