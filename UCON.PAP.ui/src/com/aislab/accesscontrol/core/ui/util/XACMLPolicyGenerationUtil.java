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

package com.aislab.accesscontrol.core.ui.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBElement;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.jboss.security.xacml.core.model.policy.ActionMatchType;
import org.jboss.security.xacml.core.model.policy.ActionType;
import org.jboss.security.xacml.core.model.policy.ActionsType;
import org.jboss.security.xacml.core.model.policy.ApplyType;
import org.jboss.security.xacml.core.model.policy.AttributeAssignmentType;
import org.jboss.security.xacml.core.model.policy.AttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.AttributeValueType;
import org.jboss.security.xacml.core.model.policy.ConditionType;
import org.jboss.security.xacml.core.model.policy.EffectType;
import org.jboss.security.xacml.core.model.policy.EnvironmentMatchType;
import org.jboss.security.xacml.core.model.policy.EnvironmentType;
import org.jboss.security.xacml.core.model.policy.EnvironmentsType;
import org.jboss.security.xacml.core.model.policy.ExpressionType;
import org.jboss.security.xacml.core.model.policy.FunctionType;
import org.jboss.security.xacml.core.model.policy.ObjectFactory;
import org.jboss.security.xacml.core.model.policy.ObligationType;
import org.jboss.security.xacml.core.model.policy.ObligationsType;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.core.model.policy.ResourceMatchType;
import org.jboss.security.xacml.core.model.policy.ResourceType;
import org.jboss.security.xacml.core.model.policy.ResourcesType;
import org.jboss.security.xacml.core.model.policy.RuleType;
import org.jboss.security.xacml.core.model.policy.SubjectAttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.SubjectMatchType;
import org.jboss.security.xacml.core.model.policy.SubjectType;
import org.jboss.security.xacml.core.model.policy.SubjectsType;
import org.jboss.security.xacml.core.model.policy.TargetType;
import org.jboss.security.xacml.factories.PolicyAttributeFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionMatch;
import com.aislab.accesscontrol.core.entities.Actions;
import com.aislab.accesscontrol.core.entities.Apply;
import com.aislab.accesscontrol.core.entities.AttributeAssignment;
import com.aislab.accesscontrol.core.entities.AttributeDesignator;
import com.aislab.accesscontrol.core.entities.AttributeValue;
import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentMatch;
import com.aislab.accesscontrol.core.entities.Environments;
import com.aislab.accesscontrol.core.entities.Expression;
import com.aislab.accesscontrol.core.entities.Obligations;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceMatch;
import com.aislab.accesscontrol.core.entities.Resources;
import com.aislab.accesscontrol.core.entities.Rule;
import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectMatch;
import com.aislab.accesscontrol.core.entities.Subjects;
import com.aislab.accesscontrol.core.entities.Target;

/**
 * Provides utility methods related to {@code XacmlPolicyGeneration}
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
public class XACMLPolicyGenerationUtil {
	/**
	 * A static {@code SessionFactory} instance.
	 */
	public static SessionFactory sessionFactory;
	/**
	 * A static {@code Session} instance.
	 */
	public static Session session;
	/**
	 * A static {@code Transaction} instance.
	 */
	public static Transaction tx;
	/**
	 * A {@code String} variable to store the url for data type.
	 */
	public String attrDataType = "http://www.w3.org/2001/XMLSchema#";

	/**
	 * A {@code String} variable for the Policy Repository Path
	 */
	public String POLICY_REPOSITORY_PATH = null;

	/**
	 * Constructor for {@link XACMLPolicyGenerationUtil} that sets repository
	 * path
	 * 
	 * @throws IOException
	 */
	public XACMLPolicyGenerationUtil() {
		// Code for path properties config
		Properties propertiesPolicyPath = new Properties();

		try {
			propertiesPolicyPath.load(Thread.currentThread()
					.getContextClassLoader()
					.getResourceAsStream("/path.properties"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.POLICY_REPOSITORY_PATH = propertiesPolicyPath
				.getProperty("PolicyPath");

	}

	/**
	 * Generates an XACML Policy based on a {@code Policy} instance specified by
	 * its primary key given as {@code Long} argument.
	 * 
	 * @param pkPolicy
	 * @return boolean
	 * @throws IOException
	 */
	public boolean generateXACMLPolicy(Long pkPolicy) throws IOException {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		if (session.get(Policy.class, pkPolicy) != null) {

			// Load the Policy into current Hibernate session
			Policy genPolicy = (Policy) session.load(Policy.class, pkPolicy);

			// JBoss PolicyType Object
			PolicyType policyType = new PolicyType();
			policyType.setDescription(genPolicy.getDescription());

			// Removing whitespaces and special characters from PolicyId
			String policyId = genPolicy.getPolicyId().replaceAll(
					"[\\W\\-\\+\\.\\^:!-)_+{}<>]", "");
			policyType.setPolicyId(policyId);
			policyType.setVersion("2.0");

			// Rule combining algo
			String appendURI = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:";
			String ruleCombAlgo = genPolicy.getRuleCombAlgo().toLowerCase()
					.replaceAll("[\\W\\s]", "-");
			policyType.setRuleCombiningAlgId(appendURI + ruleCombAlgo);

			// Create a target
			TargetType targetType = new TargetType();

			if (genPolicy.getTarget() != null) {
				targetType = setTarget(genPolicy.getTarget());
			}

			policyType.setTarget(targetType);

			// Get rules from Policy
			if (!genPolicy.getRules().isEmpty()) {
				Set<RuleType> ruleTypeSet = this.setRuleTypes(genPolicy
						.getRules());
				for (RuleType ruleType : ruleTypeSet)
					policyType
							.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition()
							.add(ruleType);
			}

			if (genPolicy.getObligations().size() != 0) {
				ObligationsType oblsType = this.setObligations(genPolicy
						.getObligations());
				policyType.setObligations(oblsType);
			}

			// Set File Name
			String FileName = genPolicy.getPolicyId() + "_P" + ".xml";
			System.out.println(POLICY_REPOSITORY_PATH);
			String[] parseString = FileName.split(" ");
			String semiFinalFileName = "";
			for(int i = 0; i < parseString.length; i++){
				semiFinalFileName += parseString[i];
			}
			String finalFileName = "";
			String[] secondParse = semiFinalFileName.split(":");
			for(int i = 0; i < secondParse.length; i++)
				finalFileName += secondParse[i];
			JAXBElement<PolicyType> jaxbPolicy = new ObjectFactory()
					.createPolicy(policyType);
			JAXB.marshal(jaxbPolicy, System.out);
			try {
				JAXB.marshal(jaxbPolicy, new FileOutputStream(new File(
						POLICY_REPOSITORY_PATH + finalFileName)));
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
			return true;
		}

		return false;
	}

	/**
	 * Transforms a Set {@code Rule} instances to a Set of {@code RuleType}
	 * instances.
	 * 
	 * @param rules
	 * @return ruleSet
	 */
	public Set<RuleType> setRuleTypes(Set<Rule> rules) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		// tx = session.beginTransaction();

		RuleType ruleType;
		Set<RuleType> ruleSet = new HashSet<RuleType>(0);
		for (Rule rul : rules) {
			ruleType = new RuleType();
			ruleType.setRuleId(rul.getRuleId());
			ruleType.setDescription(rul.getDescription());
			if (rul.getEffect().equalsIgnoreCase("permit"))
				ruleType.setEffect(EffectType.PERMIT);
			else
				ruleType.setEffect(EffectType.DENY);
			// ruleType.setEffect(EffectType.valueOf(rul.getEffect()));

			// Append <Condition> tag in Rule
			if (rul.getCondition() != null) {
				ConditionType conType = new ConditionType();
				conType = setConditionType(rul);
				ruleType.setCondition(conType);
			}

			if (rul.getTarget() != null) {
				TargetType targetType = new TargetType();
				targetType = setTarget(rul.getTarget());
				ruleType.setTarget(targetType);
			}

			ruleSet.add(ruleType);
		}

		// tx.commit();
		return ruleSet;

	}

	/**
	 * Transforms a Set {@code Obligations} instances to an
	 * {@code ObligationsType} instance.
	 * 
	 * @param obligations
	 * @return
	 */
	public ObligationsType setObligations(Set<Obligations> obligations) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();

		ObligationsType obls = new ObligationsType();
		ObligationType obl;
		AttributeAssignmentType attrType;
		for (Obligations ob : obligations) {
			obl = new ObligationType();
			obl.setObligationId(ob.getObligationId());
			if (ob.getFulfillOn().equalsIgnoreCase("permit"))
				obl.setFulfillOn(EffectType.PERMIT);
			else
				obl.setFulfillOn(EffectType.DENY);
			Set<AttributeAssignment> attrAssignment = ob
					.getAttributeAssignments();
			for (AttributeAssignment attr : attrAssignment) {
				attrType = new AttributeAssignmentType();
				attrType.setAttributeId(attr.getAttributeId());
				// ////////////////////////////////
				// ////NEEDS TO BE CHANGED
				// attrType.setDataType(attr.get);
				// ////////////////////////////////
				attrType.setDataType(attr.getDataType());
				attrType.getContent().add(attr.getAttributeValue());
				obl.getAttributeAssignment().add(attrType);
			}

			obls.getObligation().add(obl);

		}

		tx.commit();
		return obls;

	}

	/**
	 * Transforms a {@code Target} instance to a {@code TargetType} instance.
	 * 
	 * @param targ
	 * @return targetType
	 */
	public TargetType setTarget(Target targ) {

		TargetType targetType = new TargetType();

		if (!targ.getActions().isEmpty()) {
			ActionsType actsType = setTargetActionsType(targ);
			targetType.setActions(actsType);
		}

		if (!targ.getSubjects().isEmpty()) {
			SubjectsType subsType = setTargetSubjectsType(targ);
			targetType.setSubjects(subsType);
		}

		if (!targ.getEnvironments().isEmpty()) {
			EnvironmentsType envsType = setTargetEnvironmentsType(targ);
			targetType.setEnvironments(envsType);
		}

		if (!targ.getResources().isEmpty()) {
			ResourcesType ressType = setTargetResourcesType(targ);
			targetType.setResources(ressType);
		}

		return targetType;
	}

	/**
	 * Transforms a {@code Target} instance to a {@code ResourcesType} instance.
	 * 
	 * @param targ
	 * @return ressType
	 */
	@SuppressWarnings("unchecked")
	public ResourcesType setTargetResourcesType(Target targ) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Resource> resList = session.createQuery(
				"select distinct r.resource from Resources r join r.targets t "
						+ "where t.pkTarget = " + targ.getPkTarget()).list();
		List<Resources> ress;
		// New XACML <Resources> tag
		ResourcesType ressType = new ResourcesType();
		ResourceType resType;
		ResourceMatchType rmt;
		for (Resource res : resList) {
			// Check for Resources i.e. <ResourceMatch> tags belonging to this
			// particular <Resource>
			ress = session.createQuery(
					"select res from Target t inner join t.resources res where t.pkTarget = "
							+ targ.getPkTarget() + " and res.resource = "
							+ res.getPkResource()).list();

			// New XACML <Resource> tag
			resType = new ResourceType();
			for (Resources r : ress) {

				// Get ResourceMatch and ResAttrValues from Resources
				Object[] list = (Object[]) session
						.createQuery(
								"select resMatch, val from Resources r join r.resourceMatch resMatch join resMatch.resAttrValues val where r.pkResources = "
										+ r.getPkResources()).uniqueResult();

				ResourceMatch resMatch = (ResourceMatch) list[0];
				ResAttrValues resAttrVal = (ResAttrValues) list[1];

				if (resAttrVal != null) {
					// New XACML <ResourceMatch> tag
					rmt = new ResourceMatchType();
					rmt.setMatchId(resMatch.getMatchId());

					String appendId = resAttrVal.getResourceAttribute()
							.getResAttrId()
							.replaceAll("[\\-\\+\\.\\^:!-)_+{}<>]", "");

					String attributeId = ""
							.concat(appendId.replaceAll("[\\W\\s]", "-")
									.toLowerCase());

					// DataType to lowercase to prep for the switch statements
					String dataType = (resAttrVal.getResourceAttribute()
							.getDataType() != null ? resAttrVal
							.getResourceAttribute().getDataType().toLowerCase()
							: "string");

					String finalDataType = null;

					switch (dataType) {

					case "anyuri":

						try {
							rmt.setAttributeValue(PolicyAttributeFactory
									.createAnyURIAttributeType(new URI(r
											.getResourceMatch()
											.getResAttrValues()
											.getResAttrValue())));
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						finalDataType = attrDataType.concat("anyURI");
						break;

					case "integer":
						// ******************************************************************
						// ///// NEED TO CORRECT THIS
						// ******************************************************************
						String intgr = resAttrVal.getResAttrValue().replaceAll(
								"[\\W\\.\\-\\^a-zA-Z,'+*]", "");
						rmt.setAttributeValue(PolicyAttributeFactory
								.createIntegerAttributeType(Integer
										.parseInt(intgr/*
														 * resAttrVal.
														 * getResAttrValue()
														 */)));
						finalDataType = attrDataType.concat("integer");
						break;

					case "boolean":
						rmt.setAttributeValue(PolicyAttributeFactory
								.createBooleanAttributeType(Boolean
										.parseBoolean(resAttrVal
												.getResAttrValue())));
						finalDataType = attrDataType.concat("boolean");
						break;

					default:
						rmt.setAttributeValue(PolicyAttributeFactory
								.createStringAttributeType(resAttrVal
										.getResAttrValue()));
						finalDataType = attrDataType.concat("string");
						break;

					}

					rmt.setResourceAttributeDesignator(PolicyAttributeFactory
							.createAttributeDesignatorType(attributeId,
									finalDataType, null, (resMatch
											.getMustBePresent() == null ? false
											: resMatch.getMustBePresent())));

					resType.getResourceMatch().add(rmt);
				}

			}
			ressType.getResource().add(resType);
		}
		tx.commit();
		return ressType;
	}

	/**
	 * Transforms a {@code Target} instance to a {@code SubjectsType} instance.
	 * 
	 * @param targ
	 * @return subsType
	 */
	@SuppressWarnings("unchecked")
	public SubjectsType setTargetSubjectsType(Target targ) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		System.out.println("session.beginTransaction()");
		tx = session.beginTransaction();
		System.out.println("session.beginTransaction()");
		List<Subject> subList = session.createQuery(
				"select distinct s.subject from Subjects s join s.targets t "
						+ "where t.pkTarget = " + targ.getPkTarget()).list();
		List<Subjects> subsList;
		// New XACML <Subjects> tag
		SubjectsType subsType = new SubjectsType();
		SubjectType subType;
		SubjectMatchType smt;
		for (Subject sub : subList) {
			// Check for Subject i.e. <SubjectMatch> tags belonging to this
			// particular <Subject>
			subsList = session.createQuery(
					"select sub from Target t inner join t.subjects sub where t.pkTarget = "
							+ targ.getPkTarget() + " and sub.subject = "
							+ sub.getPkSubject()).list();
			subType = new SubjectType();
			for (Subjects s : subsList) {

				Object[] list = (Object[]) session
						.createQuery(
								"select subMatch, val from Subjects s join s.subjectMatch subMatch join subMatch.subAttrValues val where s.pkSubjects = "
										+ s.getPkSubjects()).uniqueResult();

				SubjectMatch subMatch = (SubjectMatch) list[0];
				SubAttrValues subAttrVal = (SubAttrValues) list[1];

				// Check to make sure AttrValue
				if (subAttrVal != null) {

					// New XACML <ResourceMatch> tag
					smt = new SubjectMatchType();
					smt.setMatchId(subMatch.getMatchId());

					String appendId = subAttrVal.getSubjectAttribute()
							.getSubjAttrId()
							.replaceAll("[\\+\\.\\^:!-)_+{}<>]", "");

					String attributeId = ""
							.concat(appendId.replaceAll("[\\W\\s]", "-")
									.toLowerCase());

					// DataType to lowercase to prep for the switch statements
					String dataType = (subAttrVal.getSubjectAttribute()
							.getDataType() != null ? subAttrVal
							.getSubjectAttribute().getDataType().toLowerCase()
							: "string");

					String finalDataType = null;

					switch (dataType) {

					case "anyuri":
						try {
							smt.setAttributeValue(PolicyAttributeFactory
									.createAnyURIAttributeType(new URI(
											subAttrVal.getSubAttrValue())));
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						finalDataType = attrDataType.concat("anyURI");
						break;

					case "integer":
						smt.setAttributeValue(PolicyAttributeFactory.createIntegerAttributeType(Integer
								.parseInt(subAttrVal.getSubAttrValue())));
						finalDataType = attrDataType.concat("integer");
						break;

					case "boolean":
						smt.setAttributeValue(PolicyAttributeFactory
								.createBooleanAttributeType(Boolean
										.parseBoolean(subAttrVal
												.getSubAttrValue())));
						finalDataType = attrDataType.concat("boolean");
						break;

					default:
						smt.setAttributeValue(PolicyAttributeFactory
								.createStringAttributeType(s.getSubjectMatch()
										.getSubAttrValues().getSubAttrValue()));
						finalDataType = attrDataType.concat("string");
						break;
					}

					String subCategory = s.getSubject().getSubjectCategory()
							.replaceAll("[\\W\\s]", "").toLowerCase();

					String finalSubCategory = null;

					switch (subCategory) {

					case "codebase":
						finalSubCategory = XACMLConstants.ATTRIBUTEID_CODEBASE;
						break;

					case "intermediarysubject":
						finalSubCategory = XACMLConstants.ATTRIBUTEID_INTERMEDIARY_SUBJECT;
						break;

					case "recipientsubject":
						finalSubCategory = XACMLConstants.ATTRIBUTEID_RECIPIENT_SUBJECT;
						break;

					case "requestingmachine":
						finalSubCategory = XACMLConstants.ATTRIBUTEID_REQUESTING_MACHINE;
						break;

					default:
						finalSubCategory = XACMLConstants.ATTRIBUTEID_ACCESS_SUBJECT;
						break;

					}

					smt.setSubjectAttributeDesignator((PolicyAttributeFactory
							.createSubjectAttributeDesignatorType(attributeId,
									finalDataType, null, (subMatch
											.getMustBePresent() == null ? false
											: subMatch.getMustBePresent()),
									finalSubCategory)));

					subType.getSubjectMatch().add(smt);
				}

			}
			subsType.getSubject().add(subType);
		}

		tx.commit();
		return subsType;

	}

	/**
	 * Transforms a {@code Target} instance to an {@code EnvironmentsType}
	 * instance.
	 * 
	 * @param targ
	 * @return envsType
	 */
	@SuppressWarnings("unchecked")
	public EnvironmentsType setTargetEnvironmentsType(Target targ) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Environment> envList = session.createQuery(
				"select distinct e.environment from Environments e join e.targets t "
						+ "where t.pkTarget = " + targ.getPkTarget()).list();
		List<Environments> envsList;
		// New XACML <Environments> tag
		EnvironmentsType envsType = new EnvironmentsType();
		EnvironmentType envType;
		EnvironmentMatchType emt;
		for (Environment en : envList) {
			// Check for Environment i.e. <EnvironmentMatch> tags belonging to
			// this particular <Environment>
			envsList = session.createQuery(
					"select env from Target t inner join t.environments env where t.pkTarget = "
							+ targ.getPkTarget() + " and env.environment = "
							+ en.getPkEnvironment()).list();
			envType = new EnvironmentType();
			for (Environments e : envsList) {

				Object[] list = (Object[]) session
						.createQuery(
								"select envMatch, val from Environments e join e.environmentMatch envMatch join envMatch.envAttrValues val where e.pkEnvironments = "
										+ e.getPkEnvironments()).uniqueResult();

				EnvironmentMatch envMatch = (EnvironmentMatch) list[0];
				EnvAttrValues envAttrVal = (EnvAttrValues) list[1];

				if (envAttrVal != null) {

					// New XACML <ResourceMatch> tag
					emt = new EnvironmentMatchType();
					emt.setMatchId(envMatch.getMatchId());

					String appendId = envAttrVal.getEnvironmentAttribute()
							.getEnvAttrId()
							.replaceAll("[\\-\\+\\.\\^:!-)_+{}<>]", "");
				
					String attributeId = ""
						.concat(appendId.replaceAll("[\\W\\s]", "-")
								.toLowerCase());
				
					// DataType to lowercase to prep for the switch statements
					String dataType = (envAttrVal.getEnvironmentAttribute()
							.getDataType() != null ? envAttrVal
							.getEnvironmentAttribute().getDataType()
							.toLowerCase() : "string");

					String finalDataType = null;

					switch (dataType) {

					case "anyuri":
						try {
							emt.setAttributeValue(PolicyAttributeFactory
									.createAnyURIAttributeType(new URI(
											envAttrVal.getEnvAttrValue())));
						} catch (URISyntaxException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}

						finalDataType = attrDataType.concat("anyURI");
						break;

					case "integer":
						emt.setAttributeValue(PolicyAttributeFactory.createIntegerAttributeType(Integer
								.parseInt(envAttrVal.getEnvAttrValue())));
						finalDataType = attrDataType.concat("integer");
						break;

					case "boolean":
						emt.setAttributeValue(PolicyAttributeFactory
								.createBooleanAttributeType(Boolean
										.parseBoolean(envAttrVal
												.getEnvAttrValue())));
						finalDataType = attrDataType.concat("boolean");
						break;

					default:
						emt.setAttributeValue(PolicyAttributeFactory
								.createStringAttributeType(envAttrVal
										.getEnvAttrValue()));

						finalDataType = attrDataType.concat("string");
						break;

					}

					emt.setEnvironmentAttributeDesignator((PolicyAttributeFactory
							.createAttributeDesignatorType(attributeId,
									finalDataType, null, (envMatch
											.getMustBePresent() == null ? false
											: envMatch.getMustBePresent()))));

					envType.getEnvironmentMatch().add(emt);
				}

			}
			envsType.getEnvironment().add(envType);
		}

		tx.commit();
		return envsType;

	}

	/**
	 * Transforms a {@code Target} instance to an {@code ActionsType} instance.
	 * 
	 * @param targ
	 * @return actsType
	 */
	@SuppressWarnings("unchecked")
	public ActionsType setTargetActionsType(Target targ) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.getCurrentSession().isOpen() ? sessionFactory
				.getCurrentSession() : sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Action> actList = session.createQuery(
				"select distinct a.action from Actions a join a.targets t "
						+ "where t.pkTarget = " + targ.getPkTarget()).list();
		List<Actions> actsList;
		// New XACML <Actions> tag
		ActionsType actsType = new ActionsType();
		ActionType actType;
		ActionMatchType amt;
		for (Action act : actList) {
			// Check for Action i.e. <ActionMatch> tags belonging to this
			// particular <Action>
			actsList = session.createQuery(
					"select act from Target t inner join t.actions act where t.pkTarget = "
							+ targ.getPkTarget() + " and act.action = "
							+ act.getPkAction()).list();
			actType = new ActionType();
			for (Actions a : actsList) {

				Object[] list = (Object[]) session
						.createQuery(
								"select actMatch, val from Actions a join a.actionMatch actMatch join actMatch.actAttrValues val where a.pkActions = "
										+ a.getPkActions()).uniqueResult();

				ActionMatch actMatch = (ActionMatch) list[0];
				ActAttrValues actAttrVal = (ActAttrValues) list[1];

				// Check to make sure AttrValue
				if (actAttrVal != null) {

					// New XACML <ActionMatch> tag
					amt = new ActionMatchType();
					amt.setMatchId(actMatch.getMatchId());

					String appendId = actAttrVal.getActionAttribute()
							.getActAttrId()
							.replaceAll("[\\-\\+\\.\\^:!-)_+{}<>]", "");

					String attributeId = ""
							.concat(appendId.replaceAll("[\\W\\s]", "-")
									.toLowerCase());

					// DataType to lowercase to prep for the switch statements
					String dataType = (actAttrVal.getActionAttribute()
							.getDataType() != null ? actAttrVal
							.getActionAttribute().getDataType().toLowerCase()
							: "string");

					String finalDataType = null;
					// AttributeType according to DataType
					switch (dataType) {

					case "anyuri":
						try {
							amt.setAttributeValue(PolicyAttributeFactory
									.createAnyURIAttributeType(new URI(
											actAttrVal.getActAttrValue())));
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						finalDataType = attrDataType.concat("anyURI");
						break;

					default:

						// Create the <AttributeValue> tag
						amt.setAttributeValue(PolicyAttributeFactory
								.createStringAttributeType(actAttrVal
										.getActAttrValue()));

						finalDataType = attrDataType.concat("string");
						break;

					}

					// AttributeDesignator
					amt.setActionAttributeDesignator((PolicyAttributeFactory
							.createAttributeDesignatorType(attributeId,
									finalDataType, null, (actMatch
											.getMustBePresent() == null ? false
											: actMatch.getMustBePresent()))));

					actType.getActionMatch().add(amt);
				}
			}
			actsType.getAction().add(actType);

		}
		tx.commit();
		return actsType;
	}

	/**
	 * Transforms a {@code Apply} instance to an {@code ApplyType} instance.
	 * 
	 * @param app
	 * @return
	 */
	public ApplyType setApply(Apply app) {
		// Apply in Condition
		ApplyType apply = new ApplyType();

		ObjectFactory jbossXacmlObjectFactory = new ObjectFactory();
		// Get Condition Apply

		apply.setFunctionId(app.getFunctionId().toLowerCase());
		Set<Expression> appExp = app.getExpressions();

		// Traverse Expressions in Apply
		for (Expression e : appExp) {
			String expType = e.getExpType();

			switch (expType) {

			case "AttributeDesignator": {
				AttributeDesignator attrDes = (AttributeDesignator) e;
				String attrType = attrDes.getAttributeType();

				AttributeDesignatorType attrDesignator = new AttributeDesignatorType();
				if (!attrType.equalsIgnoreCase("subject")) {
					if(attrType.equalsIgnoreCase("environment") && attrDes.getAttributeId().equals("current-time"))
						attrDesignator.setAttributeId("urn:oasis:names:tc:xacml:1.0:environment:"+attrDes.getAttributeId());
					else
						attrDesignator.setAttributeId(attrDes.getAttributeId());
					attrDesignator.setDataType(attrDataType
							+ attrDes.getDataType().toLowerCase());
					if (attrDes.getIssuer() != null)
						attrDesignator.setIssuer(attrDes.getIssuer());
					attrDesignator
							.setMustBePresent(attrDes.getMustBePresent() != null ? attrDes
									.getMustBePresent() : false);
				}

				switch (attrType) {
				case "Subject":
					SubjectAttributeDesignatorType subAttrDes = new SubjectAttributeDesignatorType();
					subAttrDes.setAttributeId(attrDes.getAttributeId());
					subAttrDes.setDataType(attrDataType
							+ attrDes.getDataType().toLowerCase());
					if (attrDes.getIssuer() != null)
						subAttrDes.setIssuer(attrDes.getIssuer());
					subAttrDes
							.setMustBePresent(attrDes.getMustBePresent() != null ? attrDes
									.getMustBePresent() : false);
					apply.getExpression()
							.add(jbossXacmlObjectFactory
									.createSubjectAttributeDesignator(subAttrDes));

					break;
				case "Resource":
					apply.getExpression()
							.add(jbossXacmlObjectFactory
									.createResourceAttributeDesignator(attrDesignator));
					break;
				case "Environment":
					apply.getExpression()
							.add(jbossXacmlObjectFactory
									.createEnvironmentAttributeDesignator(attrDesignator));
					break;
				case "Action":

					apply.getExpression()
							.add(jbossXacmlObjectFactory
									.createActionAttributeDesignator(attrDesignator));
					break;
				}
				break;
			}

			case "AttributeValue":
				AttributeValue attrValue = (AttributeValue) e;
				AttributeValueType attrValType = new AttributeValueType();
				attrValType.setDataType(attrDataType
						+ attrValue.getDataType().toLowerCase());
				attrValType.getContent().add(
						(String) attrValue.getAttributeValue());
				apply.getExpression().add(
						jbossXacmlObjectFactory
								.createAttributeValue(attrValType));

				break;

			case "Apply":
				Apply innerApply = (Apply) e;
				apply.getExpression().add(
						jbossXacmlObjectFactory
								.createApply(setApply(innerApply)));
				break;

			}

		}

		return apply;
	}

	/**
	 * Transforms a {@code Condition} instance to an {@code ConditionType}
	 * instance.
	 * 
	 * @param Rule
	 *            r
	 * @return {@code ConditionType}
	 */
	public ConditionType setConditionType(Rule r) {

		// Check if Rule has Condition
		if (r.getCondition() != null) {

			ObjectFactory jbossXacmlObjectFactory = new ObjectFactory();

			Condition temp = r.getCondition();
			ConditionType conType = new ConditionType();

			Apply app = (Apply) temp.getExpression();
			ApplyType apply = setApply(app);
			conType.setExpression(jbossXacmlObjectFactory.createApply(apply));

			return conType;
		}

		else
			return null;

	}

	/**
	 * Deletes all existing Policies and generates all XACML Policies based in
	 * the {@code policyList}
	 * 
	 * @param policyList
	 * @return
	 * @throws IOException
	 */
	public boolean generateAllXACMLPolicies(ArrayList<Policy> policyList)
			throws IOException {

		// The Policy Repository
		File repository = new File(POLICY_REPOSITORY_PATH);
		// List of all files in the folder (All files may or may not be .xml)
		File fList[] = repository.listFiles();
		// Searches policies
		for (int i = 0; i < fList.length; i++) {
			File pol = fList[i];
			String polName = pol.getName();
			if (polName.contains("_P") && polName.endsWith(".xml")) {
				// and deletes
				pol.delete();
			}

		}

		for (Policy p : policyList) {
			this.generateXACMLPolicy(p.getPkPolicy());
		}
		return true;
	}

}
