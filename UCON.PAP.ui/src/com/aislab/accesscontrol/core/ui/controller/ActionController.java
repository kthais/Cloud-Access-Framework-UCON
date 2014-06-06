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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.ui.dao.ActAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ActionDAO;

/**
 * A session scoped, managed bean for user interfaces related to {@code Action}
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */

@ManagedBean
@SessionScoped
public class ActionController {

	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(ActionController.class.getName());

	/**
	 * A String variable to store the value of {@code actAttrId} attribute of
	 * {@code ActionAttribute} while adding a new {@code ActionAttribute}
	 * corresponding to an existing {@code Action} instance.
	 */
	String newAttributeName = null;
	/**
	 * A String variable to store the value of {@code actAttrValue} attribute of
	 * {@code ActAttrValues} while adding a new {@code ActionAttribute}
	 * corresponding to an existing {@code Action} instance.
	 */
	String newAttributeValue = null;
	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code ActionAttribute} while adding a new {@code ActionAttribute}
	 * corresponding to an exiting {@code Action} instance.
	 */
	String selectedDataType = null;

	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code ActionAttribute} corresponding to an exiting
	 * {@code Action} instance.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/**
	 * A boolean variable to check whether any {@code Action} instance is
	 * selected by the user so that the corresponding {@code ActionAttribute}
	 * instance can be added. By default it is set to {@code TRUE} so that the
	 * corresponding add button is disabled while it is becomes {@code FALSE} if
	 * any {@code Action} instance is selected in the user interface.
	 */
	boolean attrbtn = true;
	/**
	 * A boolean variable to check whether any {@code ActionAttribute} instance
	 * is selected by the user so that the corresponding {@code ActAttrValue}
	 * instance can be added. By default it is set to {@code TRUE} so that the
	 * corresponding add button is disabled while it is becomes {@code FALSE} if
	 * any {@code ActionAttribute} instance is selected in the user interface.
	 */
	boolean attrValuebtn = true;
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;

	/**
	 * An instance of {@code ActionDAO} for using methods to access data related
	 * to {@code Action}
	 */
	ActionDAO daoAction = new ActionDAO();
	/**
	 * An instance of {@code ActionAttributeDAO} for using methods to access
	 * data related to {@code ActionAttribute}
	 */
	ActionAttributeDAO daoActionAttribute = new ActionAttributeDAO();

	/**
	 * An instance of {@code ActAttrValuesDAO} for using methods to access data
	 * related to {@code ActAttrValues}
	 */

	ActAttrValuesDAO daoActionAttributeValue = new ActAttrValuesDAO();

	/**
	 * An instance of {@code Action} used to store the {@code Action} selected
	 * by the user from the user interface.
	 */
	public Action selectedAction;;
	/**
	 * An ArrayList of {@code Action} used to display all the existing
	 * {@code Action}s stored in the database.
	 */
	public ArrayList<Action> actionList = new ArrayList<Action>();

	/**
	 * An ArrayList of {@code ActionAttribute} used to display all the existing
	 * {@code ActionAttribute}(s) stored in the database. These
	 * {@code ActionAttribute}(s) are related to a particular {@code Action}
	 * instance stored in {@code selectedAction}.
	 */

	public ArrayList<ActionAttribute> actionAttributeList = new ArrayList<ActionAttribute>();
	/**
	 * An instance of {@code ActionAttribute} used to store the
	 * {@code ActionAttribute} selected by the user from the user interface.
	 */
	public ActionAttribute selectedActionAttributes;
	/**
	 * An ArrayList of {@code ActAttrValues} used to display all the existing
	 * {@code ActAttrValues}(s) stored in the database. These
	 * {@code ActAttrValues}(s) are related to a particular
	 * {@code ActionAttribute} instance stored in
	 * {@code selectedActionAttributes}.
	 */

	public ArrayList<ActAttrValues> actionAttributeValueList;

	/**
	 * An instance of {@code ActAttrValues} used to store the
	 * {@code ActAttrValues} selected by the user from the user interface.
	 */
	public ActAttrValues selectedActionAttributeValue;

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Sets the {@code selectedDataType} property to {@code String} argument
	 * 
	 * @param selectedDataType
	 */
	public void setSelectedDataType(String selectedDataType) {
		this.selectedDataType = selectedDataType;
		log.debug("Set  selectedDataType: " + selectedDataType);
	}

	/**
	 * Sets the {@code dataTypeList} property to {@code List} argument
	 * 
	 * @param dataTypeList
	 */
	public void setDataTypeList(List<String> dataTypeList) {
		this.dataTypeList = dataTypeList;
		log.debug("Set  dataTypeList: " + dataTypeList);

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
	 * Sets the {@code attrbtn} property to {@code boolean} argument.
	 * 
	 * @param attrbtn
	 */
	public void setAttrbtn(boolean attrbtn) {
		this.attrbtn = attrbtn;
		log.debug("Set  attrbtn: " + attrbtn);

	}

	/**
	 * Sets the {@code attrValuebtn} property to {@code boolean} argument.
	 * 
	 * @param attrValuebtn
	 */
	public void setAttrValuebtn(boolean attrValuebtn) {
		this.attrValuebtn = attrValuebtn;
		log.debug("Set  attrValuebtn: " + attrValuebtn);

	}

	/**
	 * Sets the {@code newAttributeValue} property to {@code String} argument.
	 * 
	 * @param newAttributeValue
	 */
	public void setNewAttributeValue(String newAttributeValue) {
		this.newAttributeValue = newAttributeValue;
		log.debug("Set  newAttributeValue: " + newAttributeValue);

	}

	/**
	 * Sets the {@code newAttributeName} property to {@code String} argument.
	 * 
	 * @param newAttributeName
	 */
	public void setNewAttributeName(String newAttributeName) {
		this.newAttributeName = newAttributeName;
		log.debug("Set  newAttributeName: " + newAttributeName);

	}

	/**
	 * Sets the {@code selectedActionAttributeValue} property to
	 * {@code ActAttrValues} argument.
	 * 
	 * @param selectedActionAttributeValue
	 */
	public void setSelectedActionAttributeValue(
			ActAttrValues selectedActionAttributeValue) {
		this.selectedActionAttributeValue = selectedActionAttributeValue;
		log.debug("Set  selectedActionAttributeValue: "
				+ selectedActionAttributeValue);

	}

	/**
	 * Sets the {@code daoAction} property to {@code ActionDAO} argument.
	 * 
	 * @param daoAction
	 */
	public void setDaoAction(ActionDAO daoAction) {
		this.daoAction = daoAction;
		log.debug("Set  daoAction: " + daoAction);

	}

	/**
	 * Sets the {@code daoActionAttribute} property to
	 * {@code ActionAttributeDAO} argument.
	 * 
	 * @param daoActionAttribute
	 */
	public void setDaoActionAttribute(ActionAttributeDAO daoActionAttribute) {
		this.daoActionAttribute = daoActionAttribute;
		log.debug("Set  daoActionAttribute: " + daoActionAttribute);

	}

	/**
	 * Sets the {@code daoActionAttributeValue} property to
	 * {@code ActAttrValuesDAO} argument.
	 * 
	 * @param daoActionAttributeValue
	 */
	public void setDaoActionAttributeValue(
			ActAttrValuesDAO daoActionAttributeValue) {
		this.daoActionAttributeValue = daoActionAttributeValue;
		log.debug("Set  daoActionAttributeValue: " + daoActionAttributeValue);

	}

	/**
	 * Sets the {@code actionList} property to {@code Action} argument.
	 * 
	 * @param actionList
	 */

	public void setActionList(ArrayList<Action> actionList) {
		this.actionList = actionList;
		log.debug("Set  actionList: " + actionList);

	}

	/**
	 * Sets the {@code actionAttributeList} property to {@code ActionAttribute}
	 * argument.
	 * 
	 * @param actionAttributeList
	 */
	public void setActionAttributeList(
			ArrayList<ActionAttribute> actionAttributeList) {
		this.actionAttributeList = actionAttributeList;
		log.debug("Set  actionAttributeList: " + actionAttributeList);

	}

	/**
	 * Sets the {@code selectedActionAttributes} property to
	 * {@code ActionAttribute} argument.
	 * 
	 * @param selectedActionAttributes
	 */
	public void setSelectedActionAttributes(
			ActionAttribute selectedActionAttributes) {
		this.setAttrValuebtn(false);
		this.selectedActionAttributes = selectedActionAttributes;
		log.debug("Set  selectedActionAttributes: " + selectedActionAttributes);

	}

	/**
	 * Sets the {@code actionAttributeValueList} property to
	 * {@code ActAttrValues} argument.
	 * 
	 * @param actionAttributeValueList
	 */
	public void setActionAttributeValueList(
			ArrayList<ActAttrValues> actionAttributeValueList) {
		this.actionAttributeValueList = actionAttributeValueList;
		log.debug("Set  actionAttributeValueList: " + actionAttributeValueList);

	}

	/**
	 * Sets the {@code selectedAction} property to {@code Action} argument.
	 * 
	 * @param selectedAction
	 */
	public void setSelectedAction(Action selectedAction) {
		this.setAttrbtn(false);
		this.actionAttributeValueList = new ArrayList<ActAttrValues>();
		this.selectedActionAttributes = null;
		this.selectedAction = selectedAction;
		log.debug("Set  selectedAction: " + selectedAction);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Returns the value of {@code selectedDataType} property
	 * 
	 * @return selectedDataType
	 */
	public String getSelectedDataType() {
		log.debug("Get  selectedDataType: " + selectedDataType);
		return selectedDataType;

	}

	/**
	 * Returns the value of {@code dataTypeList} property
	 * 
	 * @return dataTypeList
	 */
	public List<String> getDataTypeList() {
		log.debug("Get  dataTypeList: " + dataTypeList);
		return dataTypeList;
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
	 * Returns the value of {@code newAttributeName} property
	 * 
	 * @return newAttributeName
	 */
	public String getNewAttributeName() {
		log.debug("Get  newAttributeName: " + newAttributeName);
		return newAttributeName;
	}

	/**
	 * Returns the value of {@code newAttributeValue} property
	 * 
	 * @return newAttributeValue
	 */
	public String getNewAttributeValue() {
		log.debug("Get  newAttributeValue: " + newAttributeValue);
		return newAttributeValue;
	}

	/**
	 * Returns {@code FALSE} if an instance of {@code ActionAttribute} is
	 * selected by the user otherwise TRUE.
	 * 
	 * @return attrValuebtn
	 */
	public boolean isAttrValuebtn() {
		log.debug("Get  attrValuebtn: " + attrValuebtn);
		return attrValuebtn;
	}

	/**
	 * Returns {@code FALSE} if an instance of the {@code Action} is selected by
	 * the user otherwise TRUE.
	 * 
	 * @return attrbtn
	 */
	public boolean isAttrbtn() {
		log.debug("Get  attrbtn: " + attrbtn);
		return attrbtn;
	}

	/**
	 * Returns the value of {@code selectedActionAttributeValue} property
	 * 
	 * @return selectedActionAttributeValue
	 */
	public ActAttrValues getSelectedActionAttributeValue() {
		log.debug("Get  selectedActionAttributeValue: "
				+ selectedActionAttributeValue);
		return selectedActionAttributeValue;
	}

	/**
	 * Returns the value of {@code daoAction} property
	 * 
	 * @return daoAction
	 */
	public ActionDAO getDaoAction() {
		log.debug("Get  daoAction: " + daoAction);
		return daoAction;
	}

	/**
	 * Returns the value of {@code daoActionAttribute } property
	 * 
	 * @return daoActionAttribute
	 */
	public ActionAttributeDAO getDaoActionAttribute() {
		log.debug("Get  daoActionAttribute: " + daoActionAttribute);
		return daoActionAttribute;
	}

	/**
	 * Returns the value of {@code daoActionAttributeValue} property
	 * 
	 * @return daoActionAttributeValue
	 */
	public ActAttrValuesDAO getDaoActionAttributeValue() {
		log.debug("Get  daoActionAttributeValue: " + daoActionAttributeValue);
		return daoActionAttributeValue;
	}

	/**
	 * Returns the value of {@code selectedAction} property
	 * 
	 * @return selectedAction
	 */
	public Action getSelectedAction() {
		log.debug("Get  selectedAction: " + selectedAction);
		return selectedAction;

	}

	/**
	 * Returns the {@code ArrayList} of {@code Action} instances available.
	 * 
	 * @return ActionList
	 */
	public ArrayList<Action> getActionList() {
		log.debug("Getting  ActionList ");
		return (ArrayList<Action>) daoAction.selectAction();
	}

	/**
	 * Returns the value of {@code actionAttributeList } property corresponding
	 * to the {@code selectedAction}
	 * 
	 * @return actionAttributeList
	 */
	public ArrayList<ActionAttribute> getActionAttributeList() {
		if (this.selectedAction != null)
			return (ArrayList<ActionAttribute>) daoActionAttribute
					.selectActionAttributes(selectedAction.getPkAction());
		log.debug("Get  actionAttributeList: " + actionAttributeList);
		return this.actionAttributeList;

	}

	/**
	 * Returns the value of {@code selectedActionAttributes} property
	 * 
	 * @return selectedActionAttributes
	 */
	public ActionAttribute getSelectedActionAttributes() {
		log.debug("Get  selectedActionAttributes: " + selectedActionAttributes);
		return selectedActionAttributes;
	}

	/**
	 * Returns the value of {@code actionAttributeValueList} property
	 * 
	 * @return actionAttributeValueList
	 */
	public ArrayList<ActAttrValues> getActionAttributeValueList() {

		if (this.selectedActionAttributes != null)
			return (ArrayList<ActAttrValues>) new ActAttrValuesDAO()
					.populateActValueList(selectedActionAttributes
							.getPkActAttr());
		log.debug("Get  actionAttributeValueList: " + actionAttributeValueList);
		return this.actionAttributeValueList;

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Opens the {@code /System Learning/Action/Update/UpdateActionDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the name and description of an existing
	 * {@code Action} instance.
	 */
	public void updateAction() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("modal", true);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 565);
		options.put("contentHeight", 230);
		options.put("contentWidth", 550);
		log.info("Opening /System Learning/Action/Update/UpdateActionDialog in a dialog.");
		context.openDialog("/System Learning/Action/Update/UpdateActionDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /System Learning/Action/Update/UpdateActionAttributeDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the existing {@code ActionAttribute} of an
	 * {@code Action} instance.
	 */
	public void updateActionAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("modal", true);
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 150);
		options.put("width", 565);
		options.put("contentHeight", 130);
		options.put("contentWidth", 550);
		log.info("Opening /System Learning/Action/Update/UpdateActionAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Action/Update/UpdateActionAttributeDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /System Learning/Action/Update/UpdateActionAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the value of an existing @
	 * {@code ActAttrValues} corresponding to an @{code ActionAttribute} of an
	 * {@code Action} instance.
	 */
	public void updateActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 130);
		options.put("width", 580);
		options.put("contentHeight", 115);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Action/Update/UpdateActionAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Action/Update/UpdateActionAttributeValueDialog",
				options, null);

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Deletes the instance of {@code ActAttrValues} stored in
	 * {@code selectedActionAttributeValue} property
	 */
	public void deleteActionAttributeValue() {

		this.daoActionAttributeValue
				.deleteActionAttributeValue(this.selectedActionAttributeValue
						.getPkActAttrVal());
		log.info("Deleting ActionAttributeValue");

		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));

	}

	/**
	 * Deletes the instance of {@code Action} stored in {@code selectedAction}
	 * property
	 */
	public void deleteAction() {
		this.daoAction.deleteAction(this.selectedAction.getPkAction());
		log.info("Deleting Action");

		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		this.attrbtn = true;
		this.attrValuebtn = true;

	}

	/**
	 * Deletes an instance of {@code ActionAttribute} stored in
	 * {@code selectedActionAttributes} property
	 */
	public void deleteActionAttribute() {
		this.daoActionAttribute
				.deleteActionAttribute(this.selectedActionAttributes
						.getPkActAttr());
		log.info("Deleting ActionAttribute");

		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));

		this.attrValuebtn = true;

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Opens the {@code /System Learning/Action/Add/AddAction.xhtml} page for
	 * creating a new {@code Action} instance.
	 * 
	 * @return
	 */
	public void addAction() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 530);
		options.put("width", 1000);
		options.put("contentHeight", 520);
		options.put("contentWidth", 960);
		options.put("modal", true);
		log.info("Opening /System Learning/Action/Add/AddAction in a dialog.");

		context.openDialog("/System Learning/Action/Add/AddAction", options,
				null);
	}

	/**
	 * Opens the
	 * {@code /System Learning/Action/Add/AddActionAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of adding a new {@code ActAttrValues} instance
	 * corresponding to an @{code ActionAttribute} of an {@code Action}
	 * instance.
	 */
	public void addActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 130);
		options.put("width", 580);
		options.put("contentHeight", 115);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Action/Add/AddActionAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Action/Add/AddActionAttributeValueDialog",
				options, null);
		this.newAttributeValue = null;

	}

	/**
	 * Opens the
	 * {@code /System Learning/Action/Add/AddActionAttributeDialog.xhtml} file
	 * in a Primefaces {@code  Dialog} component which offers the functionality
	 * of adding a new instance of @{code ActionAttribute} corresponding to an
	 * existing {@code Action} instance.
	 */
	public void addActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 580);
		options.put("contentHeight", 230);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Action/Add/AddActionAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Action/Add/AddActionAttributeDialog",
				options, null);
		this.newAttributeName = null;

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Saves the updated value of {@code selectedActionAttributeValue} property
	 * in the database.
	 */
	public void saveUpdateActionAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();
		if (this.selectedActionAttributeValue.getActAttrValue() == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");

			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoActionAttributeValue.updateActAttrValue(
					this.selectedActionAttributeValue.getPkActAttrVal(),
					this.selectedActionAttributeValue.getActAttrValue());
			FacesContext.getCurrentInstance().getExternalContext().getFlash()
					.setKeepMessages(true);
			log.info("Updating ActionAttributeValue");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(FacesMessage.SEVERITY_INFO,
							"Successful Execution",
							"Action Attribute Value Updated Successfully."));
			log.info("Closing dialog.");
			context.closeDialog(this);
			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedActionAttributes} property in
	 * the database.
	 */
	public void saveUpdateActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedActionAttributes.getActAttrId() == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoActionAttribute.updateActionAttr(
					this.selectedActionAttributes.getPkActAttr(),
					this.selectedActionAttributes.getActAttrId());

			log.info("Closing dialog.");
			context.closeDialog(this);
			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedAction} property in the
	 * database.
	 */
	public void saveUpdateAction() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (this.selectedAction.getActionName() == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");
			return;

		} else {
			this.daoAction.updateAction(this.selectedAction.getPkAction(),
					this.selectedAction.getDescription(),
					this.selectedAction.getActionName());
			log.info("Closing dialog.");
			context.closeDialog(this);
			log.info("Updating Action");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Action Updated Successfully."));
			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code ActAttrValues}in the database
	 * corresponding to an existing {@code ActionAttribute} instance referred by
	 * {@code selectedActionAttributes}
	 */
	public void saveAddActionAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeValue == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");

			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoActionAttributeValue.createActAttrValue(
					this.selectedActionAttributes, this.newAttributeValue);
			log.info("Closing dialog.");
			context.closeDialog(this);
			log.info("Adding ActionAttributeValue");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Action Attribute Value Added Successfully."));

			this.newAttributeValue = null;
			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code ActionAttribute}in the database
	 * corresponding to an existing {@code Action} instance referred by
	 * {@code selectedAction}
	 */
	public void saveAddActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeName == null) {
			log.info("/Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoActionAttribute.createActionAttrValue(this.selectedAction,
					this.newAttributeName, this.selectedDataType,
					this.newAttributeValue);
			log.info("Closing dialog.");

			context.closeDialog(this);
			log.info("Adding ActionAttribute");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Action Attribute Added Successfull."));
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(FacesMessage.SEVERITY_INFO,
							"Successful Execution",
							"Action Attribute Added Successfull."));
			this.newAttributeName = null;
			this.newAttributeValue = null;
			this.operationFail = false;
			this.selectedDataType = null;
			return;
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of updating an existing {@code ActAttrValues}
	 * instance.
	 */
	public void cancelUpdateActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of updating an existing {@code ActionAttribute}
	 * instance.
	 */
	public void cancelUpdateActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of updating an existing {@code Action} instance.
	 */
	public void cancelUpdateAction() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of adding a new {@code ActAttrValues} corresponding
	 * to an existing {@code ActionAttribute} instance
	 */
	public void cancelAddActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeValue = null;

	}

	/**
	 * Cancels the operation of adding an existing {@code ActionAttribute}
	 * instance corresponding to an existing {@code Action} instance.
	 */
	public void cancelAddActionAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeName = null;
		this.selectedDataType = null;

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Showing success message");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Successfully"));
			this.setOperationFail(true);
		}

	}

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful update operation.
	 */
	public void showUpdateMessage() {

		if (!isOperationFail()) {
			log.info("Showing success message");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Updated Successfully"));

			this.setOperationFail(true);
		}

	}

	/*---------------------------------------------------------------------------------------*/
	/*---------------------------------------------------------------------------------------*/
	/**
	 * Disables the buttons for adding {@code ActionAttribute} and
	 * {@code ActAttrValues} instances corresponding to an existing
	 * {@code Action} instance.
	 */
	public void onActionUnSelect() {
		this.attrbtn = true;
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code ActAttrValues} instance
	 * corresponding to an existing {@code ActionAttribute} instance.
	 */
	public void onActionAttributeUnSelect() {
		this.attrbtn = true;
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code ActAttrValues} instance and enables
	 * the button for adding {@code ActionAttribute} instance whenever an
	 * {@code Action} instance is selected.
	 */
	public void onActionSelect() {
		this.attrbtn = false;
		this.attrValuebtn = true;
	}
}
