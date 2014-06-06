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
import java.util.HashSet;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.ui.dao.ActionDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Action} instance
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 * 
 * 
 */
@ManagedBean
@SessionScoped
public class AddActionController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddActionController.class.getName());

	/**
	 * A String variable to store the value of {@code actionName} attribute of
	 * {@code Action} instance to be added.
	 */
	String name;
	/**
	 * A String variable to store the value of {@code description} attribute of
	 * {@code Action} instance to be added.
	 */

	String description;
	/**
	 * A String variable to store the value of {@code actAttrId} attribute of
	 * {@code ActionAttribute} instance corresponding to the {@code Action}
	 * instance to be added.
	 */
	String attributeName;

	/**
	 * A String variable to store the value of {@code actAttrValue} attribute of
	 * {@code ActAttrValues} instance corresponding to a newly created instance
	 * of {@code ActionAttribute}.
	 */
	String attributeValueDefault;
	/**
	 * A String variable to store the value of {@code actAttrValue} attribute of
	 * any additional {@code ActAttrValues} instances corresponding to a newly
	 * created instance of {@code ActionAttribute}.
	 */
	String attributeValue = null;
	/**
	 * An instance of {@code ActionDAO} for using methods to access data related
	 * to {@code Action}
	 */
	ActionDAO daoAction = new ActionDAO();
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Action},
	 * {@code ActionAttribute} or {@code ActAttrValues} instance. By default it
	 * is set to {@code TRUE} while it is becomes {@code FALSE} if {@code Save}
	 * is pressed.
	 * 
	 */
	boolean operationFail = true;
	/**
	 * An ArrayList of {@code ActionAttribute} used to display all the
	 * {@code ActionAttribute}(s) newly created related to the new
	 * {@code Action} instance that is to be created.
	 */
	public ArrayList<ActionAttribute> actionAttributeList = new ArrayList<ActionAttribute>();
	/**
	 * An instance of {@code ActionAttribute} used to store the
	 * {@code ActionAttribute} selected by the user from the user interface.
	 */
	public ActionAttribute selectedActionAttribute;

	/**
	 * A newly created instance of {@code Action} that is to be added in the
	 * database
	 */
	public Action action = new Action();
	/**
	 * A instance of {@code ActionAttribute} used to store the relevant data
	 * when the user chooses to add a new {@code ActionAttribute} instance.
	 */
	public ActionAttribute attribute = new ActionAttribute();
	/**
	 * A instance of {@code ActAttrValues} used to store the relevant data when
	 * the user chooses to add a new {@code ActAttrValues} instance.
	 */
	public ActAttrValues value = new ActAttrValues();

	/**
	 * An {@code ArrayList} of {@code ActAttrValues} instances used to display
	 * the already added instances of {@code ActAttrValues} corresponding to the
	 * {@code ActionAttribute} selected by the user.
	 */
	public ArrayList<ActAttrValues> actionAttributeValueList = new ArrayList<ActAttrValues>();
	/**
	 * An {@code ArrayList} of {@code ActAttrValues} instances used to add
	 * additional {@code ActAttrValues} instances to an instance of
	 * {@code ActionAttribute}.
	 */
	public ArrayList<ActAttrValues> selectedAttributeValueList = new ArrayList<ActAttrValues>();

	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code ActionAttribute} while adding a new {@code ActionAttribute}
	 * corresponding to the {@code Action} instance that is to be created.
	 */
	String selectedDataType = null;

	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code ActionAttribute} corresponding to the
	 * {@code Action} instance that is to be created.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

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
	 * Sets the {@code attributeValueDefault} property to the {@code String}
	 * argument.
	 * 
	 * @param attributeValueDefault
	 */
	public void setAttributeValueDefault(String attributeValueDefault) {
		this.attributeValueDefault = attributeValueDefault;
		log.debug("Set  attributeValueDefault: " + attributeValueDefault);

	}

	/**
	 * Sets the {@code action} property to the {@code Action} argument.
	 * 
	 * @param action
	 */
	public void setAction(Action action) {
		this.action = action;
		log.debug("Set  action: " + action);

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
	 * Sets the {@code name} property to the {@code String} argument.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
		log.debug("Set  name: " + name);

	}

	/**
	 * Sets the {@code attributeValue} property to the {@code String} argument.
	 * 
	 * @param attributeValue
	 */
	public void setAttributeValue(String attributeValue) {
		this.attributeValue = attributeValue;
		log.debug("Set  attributeValue: " + attributeValue);

	}

	/**
	 * Sets the {@code attributeName} property to the {@code String} argument.
	 * 
	 * @param attributeName
	 */
	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
		log.debug("Set  attributeName: " + attributeName);

	}

	/**
	 * Sets the {@code selectedAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param selectedAttributeValueList
	 */
	public void setSelectedAttributeValueList(
			ArrayList<ActAttrValues> selectedAttributeValueList) {
		this.selectedAttributeValueList = selectedAttributeValueList;
		log.debug("Set  selectedAttributeValueList: "
				+ selectedAttributeValueList);

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
	 * Sets the {@code actionAttributeList} property to the {@code  ArrayList}
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
	 * Sets the {@code selectedActionAttribute} property to the
	 * {@code ActionAttribute} argument.
	 * 
	 * @param selectedActionAttribute
	 */
	public void setSelectedActionAttribute(
			ActionAttribute selectedActionAttribute) {
		this.selectedActionAttribute = selectedActionAttribute;
		log.debug("Set  selectedActionAttribute: " + selectedActionAttribute);

	}

	/**
	 * Sets the {@code attribute} property to the {@code ActionAttribute}
	 * argument.
	 * 
	 * @param attribute
	 */
	public void setAttribute(ActionAttribute attribute) {
		this.attribute = attribute;
		log.debug("Set  attribute: " + attribute);

	}

	/**
	 * Sets the {@code actionAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param actionAttributeValueList
	 */
	public void setActionAttributeValueList(
			ArrayList<ActAttrValues> actionAttributeValueList) {
		this.actionAttributeValueList = actionAttributeValueList;
		log.debug("Set  actionAttributeValueList: " + actionAttributeValueList);

	}

	/**
	 * Sets the {@code selectedDataType} property to the {@code String}
	 * argument.
	 * 
	 * @param dataType
	 */
	public void setSelectedDataType(String dataType) {
		this.selectedDataType = dataType;
		log.debug("Set  selectedDataType: " + selectedDataType);
	}

	/**
	 * Sets the {@code dataTypeList} property to the {@code List} argument.
	 * 
	 * @param dataTypeList
	 */
	public void setDataTypeList(List<String> dataTypeList) {
		this.dataTypeList = dataTypeList;
		log.debug("Set  dataTypeList: " + dataTypeList);
	}

	/**
	 * Sets the {@code value} property to the {@code ActAttrValues} argument.
	 * 
	 * @param value
	 */
	public void setValue(ActAttrValues value) {
		this.value = value;
		log.debug("Set  value: " + value);

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
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
	 * Returns the value of {@code attributeValueDefault} property.
	 * 
	 * @return attributeValueDefault
	 */
	public String getAttributeValueDefault() {
		log.debug("Get  attributeValueDefault: " + attributeValueDefault);
		return attributeValueDefault;
	}

	/**
	 * Returns the value of {@code daoAction} property.
	 * 
	 * @return daoAction
	 */
	public ActionDAO getDaoAction() {
		log.debug("Get  daoAction: " + daoAction);
		return daoAction;
	}

	/**
	 * Returns the value of {@code action} property.
	 * 
	 * @return action
	 */
	public Action getAction() {
		log.debug("Get  action: " + action);
		return action;
	}

	/**
	 * Returns the value of {@code selectedAttributeValueList} property.
	 * 
	 * @return selectedAttributeValueList
	 */
	public ArrayList<ActAttrValues> getSelectedAttributeValueList() {
		log.debug("Get  selectedAttributeValueList: "
				+ selectedAttributeValueList);
		return selectedAttributeValueList;
	}

	/**
	 * Returns the value of {@code attributeValue} property.
	 * 
	 * @return attributeValue
	 */
	public String getAttributeValue() {
		log.debug("Get  attributeValue: " + attributeValue);
		return attributeValue;
	}

	/**
	 * Returns the value of {@code attributeName} property.
	 * 
	 * @return attributeName
	 */
	public String getAttributeName() {
		log.debug("Get  attributeName: " + attributeName);
		return attributeName;
	}

	/**
	 * Returns the value of {@code name} property.
	 * 
	 * @return name
	 */
	public String getName() {
		log.debug("Get  name: " + name);
		return name;
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

	/**
	 * Returns the value of {@code actionAttributeList} property.
	 * 
	 * @return actionAttributeList
	 */
	public ArrayList<ActionAttribute> getActionAttributeList() {
		log.debug("Get  actionAttributeList: " + actionAttributeList);
		return actionAttributeList;
	}

	/**
	 * Returns the value of {@code selectedActionAttribute} property.
	 * 
	 * @return selectedActionAttribute
	 */
	public ActionAttribute getSelectedActionAttribute() {
		log.debug("Get  selectedActionAttribute: " + selectedActionAttribute);
		return selectedActionAttribute;
	}

	/**
	 * Returns the value of {@code attribute} property.
	 * 
	 * @return attribute
	 */
	public ActionAttribute getAttribute() {
		log.debug("Get  attribute: " + attribute);
		return attribute;
	}

	/**
	 * Returns the value of {@code value} property.
	 * 
	 * @return value
	 */
	public ActAttrValues getValue() {
		log.debug("Get  value: " + value);
		return value;
	}

	/**
	 * Returns the value of {@code actionAttributeValueList} property.
	 * 
	 * @return actionAttributeValueList
	 */
	public ArrayList<ActAttrValues> getActionAttributeValueList() {
		if (this.selectedActionAttribute != null) {
			this.actionAttributeValueList = new ArrayList<>(
					this.selectedActionAttribute.getActAttrValues());

		}
		log.debug("Get  actionAttributeValueList: " + actionAttributeValueList);
		return this.actionAttributeValueList;
	}

	/**
	 * Returns the value of {@code selectedDataType} property.
	 * 
	 * @return selectedDataType
	 */
	public String getSelectedDataType() {
		log.debug("Get  selectedDataType: " + selectedDataType);
		return this.selectedDataType;

	}

	/**
	 * Returns the value of {@code dataTypeList} property.
	 * 
	 * @return dataTypeList
	 */
	public List<String> getDataTypeList() {
		log.debug("Get  dataTypeList: " + dataTypeList);
		return this.dataTypeList;
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code ActionAttribute} instance.
	 */

	public void addActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		this.attributeName = null;
		this.attributeValueDefault = null;
		this.value = null;
		this.selectedAttributeValueList = null;
		this.attribute = null;
		this.selectedDataType = null;

		context.execute("PF('ex').show()");

	}

	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code ActAttrValues} instance.
	 */
	public void addActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedActionAttribute == null) {
			log.info("No Attribute Selected. Please Select  Attribute  First.");

			context.showMessageInDialog(new FacesMessage("Warning",
					"No Attribute Selected. Please Select  Attribute  First."));

		} else {

			this.attributeName = null;
			this.attributeValue = null;
			this.value = null;
			this.selectedAttributeValueList = null;

			context.execute("PF('ex1').show()");

		}

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * 
	 * Saves the newly created instance of {@code Action} in the database.
	 * 
	 * @return
	 */
	public String saveAction() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.name == null) {
			log.info("Name cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Name cannot be empty."));

			return null;
		}

		if (this.description == null) {
			log.info("Description cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Description cannot be empty."));

			return null;
		}

		if (this.actionAttributeList.isEmpty()) {
			log.info("Action must have a Attribute(s).");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Action must have a Attribute(s)."));

			return null;
		} else {
			if ((!this.actionAttributeList.isEmpty())) {
				// System.out.println("checking");
			}

			this.daoAction.createAction(this.description, this.name,
					this.actionAttributeList);

			this.attribute = null;
			this.name = null;
			this.description = null;
			this.actionAttributeList.clear();
			this.selectedAttributeValueList = null;
			this.actionAttributeValueList = null;
			this.selectedActionAttribute = null;
			this.selectedDataType = null;
			log.info("Action Added Successfully");

			context.showMessageInDialog(new FacesMessage(
					" Successful Execution", "Action Added Successfully"));
			log.info("Closing dialog.");

			context.closeDialog(this);

			this.operationFail = false;

			return null;
		}

	}

	/**
	 * Saves the newly created instance of {@code ActionAttribute} corresponding
	 * to the {@code Action} instance that is to be created.
	 */
	public void saveAddActionAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.attributeName == null) {
			context.execute("noNameDialog.show()");
			return;

		}

		if (this.attributeValueDefault == null) {
			context.execute("noValueDialog.show()");
			return;

		}
		if (this.attributeName != null && this.attributeValueDefault != null) {
			this.attribute = new ActionAttribute();
			this.value = new ActAttrValues();
			this.selectedAttributeValueList = new ArrayList<ActAttrValues>();
			this.attribute.setActAttrId(this.attributeName);

			this.attribute
					.setDataType(this.selectedDataType != null ? this.selectedDataType
							: "String");

			this.value.setActAttrValue(this.attributeValueDefault);
			this.selectedAttributeValueList.add(this.value);
			this.attribute.setActAttrValues(new HashSet<ActAttrValues>(
					this.selectedAttributeValueList));
			this.actionAttributeList.add(attribute);

			this.attributeName = null;
			this.attributeValueDefault = null;
			this.value = null;
			this.attribute = null;
		}

		this.attributeName = null;
		this.attributeValueDefault = null;
		this.attributeName = null;
		this.value = null;
		this.attribute = null;
		this.selectedAttributeValueList = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/**
	 * Saves the newly created instance of {@code ActAttrValues} corresponding
	 * to an instance of {@code ActionAttribute}.
	 */
	public void saveAddActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.value = new ActAttrValues();
		this.value.setActAttrValue(this.attributeValue);
		this.selectedActionAttribute.getActAttrValues().add(this.value);

		this.attributeValue = null;
		this.value = null;

		context.execute("PF('ex1').hide()");

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of adding a new {@code Action} instance in the
	 * database.
	 * 
	 * @return
	 */
	public String cancelAction() {

		this.attribute = null;
		this.name = null;
		this.description = null;
		this.actionAttributeList.clear();
		this.selectedAttributeValueList = null;
		this.actionAttributeValueList = null;
		this.selectedActionAttribute = null;

		this.operationFail = true;

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

		return null;

	}

	/**
	 * Cancels the operation of adding a new {@code ActionAttribute} instance.
	 */
	public void cancelAddActionAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/**
	 * Cancels the operation of adding a new {@code ActAttrValues} instance.
	 */
	public void cancelAddActionAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeValue = null;

		context.execute("PF('ex1').hide()");

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Successfully");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Successfully"));

			this.setOperationFail(true);
		}

	}

}
