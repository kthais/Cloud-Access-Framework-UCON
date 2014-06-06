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

import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.ui.dao.EnvironmentDAO;

@ManagedBean
@SessionScoped
/**
 * A session scoped, managed bean for user interfaces related to adding a new {@code Environment} instance
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 * 
 * 
 */
public class AddEnvironmentController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddEnvironmentController.class
			.getName());

	/**
	 * A String variable to store the value of {@code environmentName} attribute
	 * of {@code Environment} instance to be added.
	 */
	String name;
	/**
	 * A String variable to store the value of {@code description} attribute of
	 * {@code Environment} instance to be added.
	 */

	String description;

	/**
	 * A String variable to store the value of {@code envAttrId} attribute of
	 * {@code EnvironmentAttribute} instance corresponding to the
	 * {@code Environment} instance to be added.
	 */
	String attributeName;
	/**
	 * A String variable to store the value of {@code envAttrValue} attribute of
	 * {@code EnvAttrValues} instance corresponding to a newly created instance
	 * of {@code EnvironmentAttribute}.
	 */
	String attributeValueDefault;
	/**
	 * A String variable to store the value of {@code envAttrValue} attribute of
	 * any additional {@code EnvAttrValues} instances corresponding to a newly
	 * created instance of {@code EnvironmentAttribute}.
	 */
	String attributeValue = null;
	/**
	 * An instance of {@code EnvironmentDAO} for using methods to access data
	 * related to {@code Environment}
	 */
	EnvironmentDAO daoEnvironment = new EnvironmentDAO();
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Environment},
	 * {@code EnvironmentAttribute} or {@code EnvAttrValues} instance. By
	 * default it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;
	/**
	 * An ArrayList of {@code EnvironmentAttribute} used to display all the
	 * {@code EnvironmentAttribute}(s) newly created related to the new
	 * {@code Environment} instance that is to be created.
	 */
	public ArrayList<EnvironmentAttribute> environmentAttributeList = new ArrayList<EnvironmentAttribute>();
	/**
	 * An instance of {@code EnvironmentAttribute} used to store the
	 * {@code EnvironmentAttribute} selected by the user from the user
	 * interface.
	 */
	public EnvironmentAttribute selectedEnvironmentAttribute;
	/**
	 * A newly created instance of {@code Environment} that is to be added in
	 * the database
	 */
	public Environment environment = new Environment();
	/**
	 * A instance of {@code EnvironmentAttribute} used to store the relevant
	 * data when the user chooses to add a new {@code EnvironmentAttribute}
	 * instance.
	 */
	public EnvironmentAttribute attribute = new EnvironmentAttribute();

	/**
	 * A instance of {@code EnvAttrValues} used to store the relevant data when
	 * the user chooses to add a new {@code EnvAttrValues} instance.
	 */
	public EnvAttrValues value = new EnvAttrValues();
	/**
	 * An {@code ArrayList} of {@code EnvAttrValues} instances used to display
	 * the already added instances of {@code EnvAttrValues} corresponding to the
	 * {@code EnvironmentAttribute} selected by the user.
	 */
	public ArrayList<EnvAttrValues> environmentAttributeValueList = new ArrayList<EnvAttrValues>();
	/**
	 * An {@code ArrayList} of {@code EnvAttrValues} instances used to add
	 * additional {@code EnvAttrValues} instances to an instance of
	 * {@code EnvironmentAttribute}.
	 */
	public ArrayList<EnvAttrValues> selectedAttributeValueList = new ArrayList<EnvAttrValues>();

	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code EnvironmentAttribute} while adding a new
	 * {@code EnvironmentAttribute} corresponding to the {@code Environment}
	 * instance that is to be created.
	 */
	String selectedDataType = null;

	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code EnvironmentAttribute} corresponding to the
	 * {@code Environment} instance that is to be created.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI","time");

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/

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
	 * Sets the {@code daoEnvironment} property to {@code EnvironmentDAO}
	 * argument.
	 * 
	 * @param daoEnvironment
	 */
	public void setDaoEnvironment(EnvironmentDAO daoEnvironment) {
		this.daoEnvironment = daoEnvironment;
		log.debug("Set  daoEnvironment: " + daoEnvironment);

	}

	/**
	 * Sets the {@code environment} property to the {@code Environment}
	 * argument.
	 * 
	 * @param environment
	 */
	public void setEnvironment(Environment environment) {
		this.environment = environment;
		log.debug("Set  environment: " + environment);

	}

	/**
	 * Sets the {@code selectedAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param selectedAttributeValueList
	 */
	public void setSelectedAttributeValueList(
			ArrayList<EnvAttrValues> selectedAttributeValueList) {
		this.selectedAttributeValueList = selectedAttributeValueList;
		log.debug("Set  selectedAttributeValueList: "
				+ selectedAttributeValueList);

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
	 * Sets the {@code name} property to the {@code String} argument.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
		log.debug("Set  name: " + name);

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
	 * Sets the {@code environmentAttributeList} property to the
	 * {@code  ArrayList} argument.
	 * 
	 * @param environmentAttributeList
	 */
	public void setEnvironmentAttributeList(
			ArrayList<EnvironmentAttribute> environmentAttributeList) {
		this.environmentAttributeList = environmentAttributeList;
		log.debug("Set  environmentAttributeList: " + environmentAttributeList);

	}

	/**
	 * Sets the {@code selectedEnvironmentAttribute} property to the
	 * {@code EnvironmentAttribute} argument.
	 * 
	 * @param selectedEnvironmentAttribute
	 */

	public void setSelectedEnvironmentAttribute(
			EnvironmentAttribute selectedEnvironmentAttribute) {
		this.selectedEnvironmentAttribute = selectedEnvironmentAttribute;
		log.debug("Set  selectedEnvironmentAttribute: "
				+ selectedEnvironmentAttribute);

	}

	/**
	 * Sets the {@code attribute} property to the {@code EnvironmentAttribute}
	 * argument.
	 * 
	 * @param attribute
	 */
	public void setAttribute(EnvironmentAttribute attribute) {
		this.attribute = attribute;
		log.debug("Set  attribute: " + attribute);

	}

	/**
	 * Sets the {@code value} property to the {@code EnvAttrValues} argument.
	 * 
	 * @param value
	 */
	public void setValue(EnvAttrValues value) {
		this.value = value;
		log.debug("Set  value: " + value);

	}

	/**
	 * Sets the {@code environmentAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param environmentAttributeValueList
	 */
	public void setEnvironmentAttributeValueList(
			ArrayList<EnvAttrValues> environmentAttributeValueList) {
		this.environmentAttributeValueList = environmentAttributeValueList;
		log.debug("Set  environmentAttributeValueList: "
				+ environmentAttributeValueList);

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

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/

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
	 * Returns the value of {@code environmentAttributeList} property.
	 * 
	 * @return environmentAttributeList
	 */
	public ArrayList<EnvironmentAttribute> getEnvironmentAttributeList() {
		log.debug("Get  environmentAttributeList: " + environmentAttributeList);
		return environmentAttributeList;
	}

	/**
	 * Returns the value of {@code selectedEnvironmentAttribute} property.
	 * 
	 * @return selectedEnvironmentAttribute
	 */
	public EnvironmentAttribute getSelectedEnvironmentAttribute() {
		log.debug("Get  selectedEnvironmentAttribute: "
				+ selectedEnvironmentAttribute);
		return selectedEnvironmentAttribute;
	}

	/**
	 * Returns the value of {@code attribute} property.
	 * 
	 * @return attribute
	 */
	public EnvironmentAttribute getAttribute() {
		log.debug("Get  attribute: " + attribute);
		return attribute;
	}

	/**
	 * Returns the value of {@code value} property.
	 * 
	 * @return value
	 */
	public EnvAttrValues getValue() {
		log.debug("Get  value: " + value);
		return value;
	}

	/**
	 * Returns the value of {@code environmentAttributeValueList} property.
	 * 
	 * @return environmentAttributeValueList
	 */
	public ArrayList<EnvAttrValues> getEnvironmentAttributeValueList() {
		if (this.selectedEnvironmentAttribute != null) {
			this.environmentAttributeValueList = new ArrayList<>(
					this.selectedEnvironmentAttribute.getEnvAttrValues());

		}
		log.debug("Get  environmentAttributeValueList: "
				+ environmentAttributeValueList);
		return this.environmentAttributeValueList;
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
	 * Returns the value of {@code daoEnvironment} property.
	 * 
	 * @return daoEnvironment
	 */
	public EnvironmentDAO getDaoEnvironment() {
		log.debug("Get  daoEnvironment: " + daoEnvironment);
		return daoEnvironment;
	}

	/**
	 * Returns the value of {@code environment} property.
	 * 
	 * @return environment
	 */
	public Environment getEnvironment() {
		log.debug("Get  environment: " + environment);
		return environment;
	}

	/**
	 * Returns the value of {@code selectedAttributeValueList} property.
	 * 
	 * @return selectedAttributeValueList
	 */
	public ArrayList<EnvAttrValues> getSelectedAttributeValueList() {
		log.debug("Get  selectedAttributeValueList: "
				+ selectedAttributeValueList);
		return selectedAttributeValueList;
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

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/
	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code EnvironmentAttribute} instance.
	 */
	public void addEnvironmentAttribute() {
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.value = null;
		this.selectedAttributeValueList = null;
		this.attribute = null;
		this.selectedDataType = null;

		RequestContext context = RequestContext.getCurrentInstance();

		context.execute("PF('ex').show()");

	}

	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code EnvAttrValues} instance.
	 */
	public void addEnvironmentAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedEnvironmentAttribute == null) {
			log.info("No Attribute Selected. Please Select  Attribute  First.");

			context.showMessageInDialog(new FacesMessage("Warning",
					"No Attribute Selected. Please Select  Attribute  First."));

		} else {

			this.attributeName = null;
			this.attributeValue = null;
			this.value = null;
			this.selectedAttributeValueList = null;
			this.selectedDataType = null;

			context.execute("PF('ex1').show()");

		}

	}

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/

	/**
	 * 
	 * Saves the newly created instance of {@code Environment} in the database.
	 * 
	 * @return
	 */
	public String saveEnvironment() {

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

		if (this.environmentAttributeList.isEmpty()) {
			log.info("Environment must have a Attribute(s).");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Environment must have a Attribute(s)."));

			return null;
		} else {
			if ((!this.environmentAttributeList.isEmpty())) {
				// System.out.println("checking");
			}

			this.daoEnvironment.createEnvironment(this.description, this.name,
					this.environmentAttributeList);

			this.attribute = null;
			this.name = null;
			this.description = null;
			this.environmentAttributeList.clear();
			this.selectedAttributeValueList = null;
			this.environmentAttributeValueList = null;
			this.selectedEnvironmentAttribute = null;
			log.info("Environment Added Successfully.");

			context.showMessageInDialog(new FacesMessage(
					" Successful Execution", "Environment Added Successfully"));
			log.info("Closing dialog.");

			context.closeDialog(this);

			this.operationFail = false;

			return null;
		}

	}

	/**
	 * Saves the newly created instance of {@code EnvironmentAttribute}
	 * corresponding to the {@code Environment} instance that is to be created.
	 */
	public void saveAddEnvironmentAttribute() {
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
			this.attribute = new EnvironmentAttribute();
			this.value = new EnvAttrValues();
			this.selectedAttributeValueList = new ArrayList<EnvAttrValues>();
			this.attribute.setEnvAttrId(this.attributeName);

			this.attribute
					.setDataType(this.selectedDataType != null ? this.selectedDataType
							: "String");

			this.value.setEnvAttrValue(this.attributeValueDefault);
			this.selectedAttributeValueList.add(this.value);
			this.attribute.setEnvAttrValues(new HashSet<EnvAttrValues>(
					this.selectedAttributeValueList));
			this.environmentAttributeList.add(attribute);

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
	 * Saves the newly created instance of {@code EnvAttrValues} corresponding
	 * to an instance of {@code EnvironmentAttribute}.
	 */
	public void saveAddEnvironmentAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.value = new EnvAttrValues();
		this.value.setEnvAttrValue(this.attributeValue);
		this.selectedEnvironmentAttribute.getEnvAttrValues().add(this.value);

		this.attributeValue = null;
		this.value = null;
		context.execute("PF('ex1').hide()");

	}

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/
	/**
	 * Cancels the operation of adding a new {@code EnvironmentAttribute}
	 * instance.
	 */
	public void cancelAddEnvironmentAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/**
	 * Cancels the operation of adding a new {@code Environment} instance in the
	 * database.
	 * 
	 * @return
	 */
	public String cancelEnvironment() {

		this.attribute = null;
		this.name = null;
		this.description = null;
		this.environmentAttributeList.clear();
		this.selectedAttributeValueList = null;
		this.environmentAttributeValueList = null;
		this.selectedEnvironmentAttribute = null;

		this.operationFail = true;

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

		return null;

	}

	/**
	 * Cancels the operation of adding a new {@code EnvAttrValues} instance.
	 */
	public void cancelAddEnvironmentAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeValue = null;
		context.execute("PF('ex1').hide()");

	}

	/*--------------------------------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Environment Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Environment Successfully"));

			this.setOperationFail(true);
		}

	}

}
