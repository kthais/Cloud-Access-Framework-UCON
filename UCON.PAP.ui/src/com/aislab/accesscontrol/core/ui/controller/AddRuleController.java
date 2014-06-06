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

import java.util.Arrays;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;
import org.primefaces.event.SelectEvent;

import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.RuleDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Rule} instance
 * 
 * @author Salman Ahmad Ansari <10besesansari@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 */
@ManagedBean
@SessionScoped
public class AddRuleController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddRuleController.class.getName());

	/**
	 * An instance of {@code RuleDAO} for using methods to access data related
	 * to {@code Rule}
	 */
	RuleDAO daoRule = new RuleDAO();

	/**
	 * A {@code String} variable to store the value of {@code ruleId} attribute
	 * of the {@code Rule} instance to be created.
	 */
	public String name;

	/**
	 * A {@code String} variable to store the value of {@code description}
	 * attribute of the {@code Rule} instance to be created.
	 */
	public String description;
	/**
	 * A {@code Target} variable to store the value of {@code target} attribute
	 * of the {@code Rule} instance to be created.
	 */
	public Target selectedTarget = new Target();
	/**
	 * A {@code Condition} variable to store the value of {@code Condition}
	 * attribute of the {@code Rule} instance to be created.
	 */
	public Condition selectedCondition = new Condition();
	/**
	 * A {@code List} variable to store the available {@code effect}(s)
	 * applicable to the {@code Rule} instance to be created.
	 */
	List<String> effect = Arrays.asList("Permit", "Deny");

	/**
	 * A {@code String} variable to store the value of {@code effect} attribute
	 * of the {@code Rule} instance to be created.
	 */
	String selectedEffect;

	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Rule} instance. By default
	 * it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the {@code selectedTarget} property to the {@code SelectEvent}
	 * argument.
	 * 
	 * @param event
	 */
	public void onTargetSelect(SelectEvent event) {
		this.selectedTarget = (Target) event.getObject();
		log.info("Target Selected ");

	}

	/**
	 * Sets the {@code selectedCondition} property to the {@code SelectEvent}
	 * argument.
	 * 
	 * @param event
	 */
	public void onConditionSelect(SelectEvent event) {
		this.selectedCondition = (Condition) event.getObject();
		log.info("Condition Selected ");

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Unselects the {@code selectedTarget} property to null.
	 * 
	 * @param event
	 */
	public void onTargetUnSelect(SelectEvent event) {
		this.selectedTarget = new Target();
		log.info("Target Selected ");

	}

	/**
	 * Unselects the {@code selectedCondition} property to the null argument.
	 * 
	 * @param event
	 */
	public void onConditionUnSelect(SelectEvent event) {
		this.selectedCondition = new Condition();
		log.info("Condition Unselected ");

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Reinitialize local variables
	 */
	public void init() {
		name = null;
		selectedEffect = null;
		description = null;
		selectedTarget = null;
		selectedCondition = null;
		log.info("Initiliazing variables in AddRuleController");
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Sets the {@code effect} property to the {@code List} argument.
	 * 
	 * @param effect
	 */
	public void setEffect(List<String> effect) {
		this.effect = effect;
		log.debug("Set  effect: " + effect);
	}

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
	 * Sets the {@code selectedEffect} property to {@code String} argument.
	 * 
	 * @param singleCatagory
	 */
	public void setSelectedEffect(String singleCatagory) {
		this.selectedEffect = singleCatagory;
		log.debug("Set  selectedEffect: " + selectedEffect);
	}

	/**
	 * Sets the {@code selectedTarget} property to the {@code Target} argument.
	 * 
	 * @param target
	 */
	public void setSelectedTarget(Target target) {
		this.selectedTarget = target;
		log.debug("Set  selectedTarget: " + selectedTarget);
	}

	/**
	 * Sets the {@code selectedCondition} property to the {@code Condition}
	 * argument.
	 * 
	 * @param Condition
	 */
	public void setSelectedCondition(Condition condition) {
		this.selectedCondition = condition;
		log.debug("Set  selectedCondition: " + selectedCondition);
	}

	/**
	 * Sets the {@code daoRule} property to the {@code RuleDAO} argument.
	 * 
	 * @param daoSubject
	 */
	public void setDaoRule(RuleDAO daoSubject) {
		this.daoRule = daoSubject;
		log.debug("Set  daoRule: " + daoRule);
	}

	/**
	 * Sets the {@code name} property to {@code String} argument.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
		log.debug("Set  name: " + name);
	}

	/**
	 * Sets the {@code description} property to {@code String} argument.
	 * 
	 * @param description
	 */
	public void setDescription(String des) {
		this.description = des;
		log.debug("Set  description: " + description);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns the value of {@code effect} property.
	 * 
	 * @return effect
	 */
	public List<String> getEffect() {
		log.debug("Get  effect: " + effect);
		return effect;
	}

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
	 * Returns the value of {@code selectedEffect} property.
	 * 
	 * @return selectedEffect
	 */
	public String getSelectedEffect() {
		log.debug("Get  selectedEffect: " + selectedEffect);
		return selectedEffect;
	}

	/**
	 * Returns the value of {@code selectedTarget} property.
	 * 
	 * @return selectedTarget
	 */
	public Target getSelectedTarget() {
		log.debug("Get  selectedTarget: " + selectedTarget);
		return selectedTarget;
	}

	/**
	 * Returns the value of {@code selectedCondition} property.
	 * 
	 * @return selectedCondition
	 */
	public Condition getSelectedCondition() {
		log.debug("Get  selectedCondition: " + selectedCondition);
		return selectedCondition;
	}

	/**
	 * Returns the value of {@code daoRule} property.
	 * 
	 * @return daoRule
	 */
	public RuleDAO getDaoRule() {
		log.debug("Get  daoRule: " + daoRule);
		return daoRule;
	}

	/**
	 * Returns the value of {@code name} property.
	 * 
	 * @return name
	 */
	public String getName() {
		log.debug("Get  name: " + name);
		return this.name;
	}

	/**
	 * Returns the name of {@code description} property.
	 * 
	 * @return description
	 */
	public String getDescription() {
		log.debug("Get  description: " + description);
		return this.description;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Saves the newly created instance of {@code Rule} into the database.
	 */
	public void saveAddRule() {
		RequestContext context = RequestContext.getCurrentInstance();
		// Ensuring that user has entered a Name for the new Rule.
		if (this.name == null) {
			context.execute("noNameDialog.show()");
		}

		// Ensuring that user has entered a Description for the new Rule.
		if (this.description == null) {
			context.execute("noDescriptionDialog.show()");
		}

		// Ensuring that user has selected an effect for the new Rule.
		if (this.selectedEffect == null) {
			context.execute("noEffectDialog.show()");
		}
		if (this.selectedEffect != null && this.name != null
				&& this.description != null)

		{ // Creating new Rule
			new RuleDAO().createRule(selectedTarget, selectedCondition, name,
					description, selectedEffect, null);
			// Reinitializing Local Variables before redirecting.
			init();

			// Redirecting to the Homepage.

			this.operationFail = false;
			log.info("Closing dialog.");

			context.closeDialog(this);
		}
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of adding a new {@code Rule} instance into the
	 * database.
	 */
	public void cancelAddRule() {
		// Reinitializing local variables before redirection
		init();

		RequestContext context = RequestContext.getCurrentInstance();
		// Redirecting to the homepage.

		this.operationFail = true;
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful update operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Rule Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Rule Successfully"));

			this.setOperationFail(true);
		}

	}

}
