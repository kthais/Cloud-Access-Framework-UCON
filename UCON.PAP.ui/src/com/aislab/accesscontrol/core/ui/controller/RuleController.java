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

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.dao.RuleDAO;

/**
 * A session scoped, managed bean for user interfaces related to {@code Rule}
 * 
 * @author Salman Ahmad Ansari <10besesansari@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 */
@ManagedBean
@SessionScoped
public class RuleController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(RuleController.class.getName());

	/**
	 * An instance of {@code RuleDAO} for using methods to access data related
	 * to {@code Rule}
	 */
	RuleDAO daoRule = new RuleDAO();

	/**
	 * An ArrayList of {@code Rule} used to display all the existing
	 * {@code Rule} instances stored in the database.
	 */
	ArrayList<Rule> ruleList = new ArrayList<Rule>();
	/**
	 * An instance of {@code Rule} used to store the {@code Rule} selected by
	 * the user from the user interface.
	 */
	public Rule selectedRule = new Rule();
	/**
	 * An instance of {@code Target} used to store the {@code Target} selected
	 * by the user from the user interface while updating an existing
	 * {@code Rule} instance.
	 */
	public Target selectedTarget = new Target();
	/**
	 * An instance of {@code Condition} used to store the {@code Condition}
	 * selected by the user from the user interface while updating an existing
	 * {@code Rule} instance.
	 */
	public Condition selectedCondition = new Condition();

	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the {@code ruleList} property to the {@code ArrayList} argument.
	 * 
	 * @param ruleList
	 */
	public void setRuleList(ArrayList<Rule> ruleList) {
		this.ruleList = ruleList;
		log.debug("Set  ruleList: " + ruleList);

	}

	/**
	 * Sets the {@code selectedRule} property to the {@code Rule} argument.
	 * 
	 * @param selectedRule
	 */
	public void setSelectedRule(Rule selectedRule) {
		this.selectedRule = selectedRule;
		log.debug("Set  selectedRule: " + selectedRule);
	}

	/**
	 * Sets the {@code selectedTarget} property to the {@code Target} argument.
	 * 
	 * @param selectedTarget
	 */
	public void setSelectedTarget(Target selectedTarget) {
		this.selectedTarget = selectedTarget;
		log.debug("Set  selectedTarget: " + selectedTarget);
	}

	/**
	 * Sets the {@code selectedCondition} property to the {@code Condition}
	 * argument.
	 * 
	 * @param selectedCondition
	 */
	public void setSelectedCondition(Condition selectedCondition) {
		this.selectedCondition = selectedCondition;
		log.debug("Set  selectedCondition: " + selectedCondition);
	}

	/**
	 * Sets the {@code daoRule} property to the {@code RuleDAO} argument.
	 * 
	 * @param daoRule
	 */
	public void setDaoRule(RuleDAO daoRule) {
		this.daoRule = daoRule;
		log.debug("Set  daoRule: " + daoRule);
	}

	/**
	 * Sets the {@code operationFail} property to the {@code boolean} argument.
	 * 
	 * @param operationFail
	 */
	public void setOperationFail(boolean operationFail) {
		this.operationFail = operationFail;
		log.debug("Set  operationFail: " + operationFail);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns the {@code target} attribute of the {@code Rule} instance
	 * corresponding to the {@code pkRule} specified by {@code Long} argument.
	 * 
	 * @param pkRule
	 * @return target
	 */
	public Target getRuleTarget(Long pkRule) {
		Target target = daoRule.getTarget(pkRule);
		log.debug("Get  ruleTarget: " + target);
		return target;
	}

	/**
	 * Returns the @{@code description} attribute of the {@code Target} instance
	 * associated with a {@code Rule} instance corresponding to the
	 * {@code pkRule} specified by {@code Long} argument.
	 * 
	 * @param pkRule
	 * @return description
	 */
	public String getRuleTargetString(String pkRule) {
		Target t = daoRule.getTarget(Long.parseLong(pkRule));
		if (t != null) {
			log.debug("Get  ruleTargetString: " + t.getDescription());
			return t.getDescription();
		} else {
			log.debug("Get  ruleTargetString: " + "Target Empty");
			return "Target Empty";
		}
	}

	/**
	 * Returns the @{@code description} attribute of the {@code Condition}
	 * instance associated with a {@code Rule} instance corresponding to the
	 * {@code pkRule} specified by {@code Long} argument.
	 * 
	 * @param pkRule
	 * @return description
	 */
	public String getRuleConditionString(String pkRule) {
		Condition cond = daoRule.getCondition(Long.parseLong(pkRule));
		if (cond != null) {
			log.debug("Get  ruleConditionString: " + cond.getDescription());
			return cond.getDescription();
		} else {
			log.debug("Get  ruleConditionString: " + "Condition Empty");
			return "No Condition Applied";
		}
	}

	/**
	 * Returns the value of {@code selectedTarget} property.
	 * 
	 * @return selectedTarget
	 */
	public Target getSelectedTarget() {

		if (selectedRule != null && selectedRule.getTarget() != null) {
			log.debug("Getting selectedTarget ");

			return (daoRule
					.selectTarget(selectedRule.getTarget().getPkTarget()));
		}
		if (this.selectedTarget == null) {
			log.debug("Get  null: " + null);
			return null;
		}

		log.debug("Get  selectedTarget: " + selectedTarget);
		return selectedTarget;

	}

	/**
	 * Returns the value of {@code selectedCondition} property.
	 * 
	 * @return selectedCondition
	 */
	public Condition getSelectedCondition() {

		if (selectedRule != null && selectedRule.getCondition() != null) {
			log.debug("Getting selectedCondition ");

			return (daoRule.selectCondition(selectedRule.getCondition()
					.getPkCondition()));
		}
		if (this.selectedCondition == null) {
			log.debug("Get  null: " + null);
			return null;
		}

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
	 * Returns the value of {@code selectedRule} property.
	 * 
	 * @return selectedRule
	 */
	public Rule getSelectedRule() {
		log.debug("Get  selectedRule: " + selectedRule);
		return selectedRule;
	}

	/**
	 * Returns the value of {@code ruleList} property.
	 * 
	 * @return ruleList
	 */
	public ArrayList<Rule> getRuleList() {
		log.debug("Getting  ruleList");
		return (ArrayList<Rule>) daoRule.selectRule();

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Opens the {@code /Policy Creation/Rule/Add/AddRule.xhtml} file in a
	 * Primefaces {@code  Dialog} component which offers the functionality of
	 * adding a new {@code Rule} instance.
	 */

	public void addRule() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 550);
		options.put("width", 950);
		options.put("contentHeight", 540);
		options.put("contentWidth", 900);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Rule/Add/AddRule in a dialog.");

		context.openDialog("/Policy Creation/Rule/Add/AddRule", options, null);

	}

	/**
	 * Opens the {@code /Policy Creation/Rule/Update/UpdateRule.xhtml} file in a
	 * Primefaces {@code  Dialog} component which offers the functionality of
	 * updating an existing {@code Rule} instance.
	 */
	public void updateRule() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 480);
		options.put("width", 800);
		options.put("contentHeight", 465);
		options.put("contentWidth", 785);
		options.put("modal", true);
		log.info("Opening /Policy Creation/Rule/Update/UpdateRule in a dialog.");

		context.openDialog("/Policy Creation/Rule/Update/UpdateRule", options,
				null);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of updating an existing {@code Rule} instance.
	 */
	public void cancelUpdateRule() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");

		context.closeDialog(this);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Unselects the already selected {@code Target} instance while updating an
	 * existing {@code Rule} instance.
	 */
	public void onTargetUnSelect() {
		this.selectedTarget = null;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Unselects the already selected {@code Condition} instance while updating
	 * an existing {@code Rule} instance.
	 */
	public void onConditionUnSelect() {
		this.selectedCondition = null;
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Saves the updated value of an existing {@code Rule} instance specified by
	 * the {@code selectedRule} property.
	 */
	public void saveUpdateRule() {
		RequestContext context = RequestContext.getCurrentInstance();
		// Ensuring that the RuleId is not null
		if (selectedRule.getRuleId() == null
				|| selectedRule.getRuleId().equals("")) {
			context.execute("noNameDialog2.show()");

			return;
		}
		// Ensuring that the Description is not null
		if (selectedRule.getDescription() == null
				|| selectedRule.getDescription().equals("")) {
			context.execute("noDescriptionDialog2.show()");

			return;
		}
		// Ensuring that the effect of Rule is selected
		if (selectedRule.getEffect() == null
				|| selectedRule.getEffect().equals("")) {
			context.execute("noEffectDialog2.show()");

			return;
		}
		daoRule.updateRule(selectedRule.getPkRule(),
				selectedRule.getDescription(), selectedRule.getRuleId(),
				selectedRule.getEffect(), this.selectedTarget,
				this.selectedCondition);
		this.selectedRule = null;
		this.setOperationFail(false);
		log.info("Closing dialog.");
		context.closeDialog(this);
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Deletes an existing {@code Rule} instance stored in the database.
	 */
	public void deleteRule() {

		// Ensuring Rule is selected
		if (this.selectedRule != null) {
			// Delete the selected Rule
			this.daoRule.deleteRule(selectedRule.getPkRule());
			this.selectedTarget = null;
			this.selectedRule = null;
			this.selectedCondition = null;
			log.info("Deleted Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Deleted Successfully"));
		}
	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Function showing the confirmation for updation operation
	 */
	public void showUpdateMessage() {

		if (!isOperationFail()) {
			log.info("Updated Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Updated Successfully"));

			this.setOperationFail(true);
		}

	}

}
