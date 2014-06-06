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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBElement;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.jboss.security.xacml.core.model.policy.ObjectFactory;
import org.jboss.security.xacml.core.model.policy.ObligationsType;
import org.jboss.security.xacml.core.model.policy.PolicySetType;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.core.model.policy.RuleType;
import org.jboss.security.xacml.core.model.policy.TargetType;

import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.PolicySet;

/**
 * Provides utility methods related to {@code XacmlPolicySetGeneration}
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
public class XACMLPolicySetGenerationUtil {
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
	 * An instance of {@code XACMLPolicyGenerationUtil} for accessing methods
	 * related to {@code XacmlPolicyGeneration}.
	 */

	XACMLPolicyGenerationUtil obj = new XACMLPolicyGenerationUtil();

	/**
	 * A {@code String} variable for the Policy Repository Path
	 */
	public String POLICYSET_REPOSITORY_PATH = null;

	/**
	 * Constructor for {@link XACMLPolicySetGenerationUtil} that sets repository
	 * path
	 * 
	 * @throws IOException
	 */
	public XACMLPolicySetGenerationUtil() {
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
		this.POLICYSET_REPOSITORY_PATH = propertiesPolicyPath
				.getProperty("PolicySetPath");

	}

	/**
	 * Generates an XACML Policy Set based on a {@code PolicySet} instance
	 * specified by its primary key given as {@code Long} argument.
	 * 
	 * @param pkPolicySet
	 * @return boolean
	 * @throws IOException
	 */
	public boolean generateXACMLPolicySet(Long pkPolicySet) throws IOException {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		if (session.get(PolicySet.class, pkPolicySet) != null) {
			// Properties propertiesPolicyPath = new Properties();
			//
			// propertiesPolicyPath.load(Thread.currentThread()
			// .getContextClassLoader()
			// .getResourceAsStream("/path.properties"));
			// String POLICY_SET_REPOSITORY_PATH = propertiesPolicyPath
			// .getProperty("PolicySetPath");

			// String POLICY_REPOSITORY_PATH = "D:\\";
			// System.out.println(POLICY_SET_REPOSITORY_PATH);
			// Load the Policy into current Hibernate session
			PolicySet genPolicySet = (PolicySet) session.load(PolicySet.class,
					pkPolicySet);

			String policySetId = genPolicySet.getPolicySetId().replaceAll(
					"[\\W\\-\\+\\.\\^:!-)_+{}<>]", "");

			// JBoss Policy Object
			PolicySetType policySetType = new PolicySetType();
			policySetType.setPolicySetId(policySetId);
			policySetType.setVersion("2.0");

			String appendURI = "urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:";
			String policyCombAlgo = genPolicySet.getPolicyCombiningAlgo()
					.toLowerCase().replaceAll("[\\W\\s]", "-");
			// policyType.setRuleCombiningAlgId(appendURI + ruleCombAlgo);

			/*
			 * policySetType.setPolicyCombiningAlgId(genPolicySet
			 * .getPolicyCombiningAlgo());
			 */policySetType
					.setPolicyCombiningAlgId(appendURI + policyCombAlgo);

			System.out.println(genPolicySet.getPolicies().size());

			if (!genPolicySet.getPolicies().isEmpty()) {
				Set<PolicyType> polTypeSet = this.setPolicyTypes(genPolicySet
						.getPolicies());
				for (PolicyType pType : polTypeSet) {
					JAXBElement<PolicyType> jaxbPolicy = new ObjectFactory()
							.createPolicy(pType);
					policySetType.getPolicySetOrPolicyOrPolicySetIdReference()
							.add(jaxbPolicy);
				}
			}

			// Create a target
			TargetType targetType = new TargetType();

			if (genPolicySet.getTarget() != null) {
				targetType = obj.setTarget(genPolicySet.getTarget());
			}

			policySetType.setTarget(targetType);

			if (!genPolicySet.getSubPolicySets().isEmpty()) {
				Set<PolicySetType> set = this.setPolicySetType(genPolicySet
						.getSubPolicySets());
				for (PolicySetType pSetType : set) {
					JAXBElement<PolicySetType> jaxbPolicySet = new ObjectFactory()
							.createPolicySet(pSetType);
					policySetType.getPolicySetOrPolicyOrPolicySetIdReference()
							.add(jaxbPolicySet);
				}
			}

			if (!genPolicySet.getObligations().isEmpty()) {
				ObligationsType oblsType = obj.setObligations(genPolicySet
						.getObligations());
				policySetType.setObligations(oblsType);
			}

			// Set File Name
			String FileName = genPolicySet.getPolicySetId() + "_PS" + ".xml";
			System.out.println(FileName);
			System.out.println(POLICYSET_REPOSITORY_PATH);
			String[] parseString = FileName.split(" ");
			String semiFinalFileName = "";
			for(int i = 0; i < parseString.length; i++){
				semiFinalFileName += parseString[i];
			}
			String finalFileName = "";
			String[] secondParse = semiFinalFileName.split(":");
			for(int i = 0; i < secondParse.length; i++)
				finalFileName += secondParse[i];
			JAXBElement<PolicySetType> jaxbPolicySet = new ObjectFactory()
					.createPolicySet(policySetType);
			JAXB.marshal(jaxbPolicySet, System.out);
			try {
				JAXB.marshal(jaxbPolicySet, new FileOutputStream(new File(
						POLICYSET_REPOSITORY_PATH + finalFileName)));
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
	 * Transforms a Set {@code PolicySet} instances to a Set of
	 * {@code PolicySetType} instances.
	 * 
	 * @param policySets
	 * @return polTypeSet
	 */
	public Set<PolicySetType> setPolicySetType(Set<PolicySet> policySets) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		PolicySetType policySetType;
		TargetType targetType = new TargetType();
		Set<PolicySetType> polTypeSet = new HashSet<PolicySetType>(0);
		for (PolicySet polSet : policySets) {
			policySetType = new PolicySetType();
			if (!polSet.getDescription().isEmpty())
				policySetType.setDescription(polSet.getDescription());
			policySetType.setPolicySetId(polSet.getPolicySetId());
			policySetType.setVersion("2.0");
			policySetType.setPolicyCombiningAlgId(polSet
					.getPolicyCombiningAlgo());

			if (polSet.getTarget() != null) {
				targetType = obj.setTarget(polSet.getTarget());
			}

			policySetType.setTarget(targetType);

			if (!polSet.getPolicies().isEmpty()) {
				Set<PolicyType> policyTypeSet = this.setPolicyTypes(polSet
						.getPolicies());
				for (PolicyType pType : policyTypeSet) {
					JAXBElement<PolicyType> jaxbPolicy = new ObjectFactory()
							.createPolicy(pType);
					policySetType.getPolicySetOrPolicyOrPolicySetIdReference()
							.add(jaxbPolicy);
				}
			}

			if (!polSet.getObligations().isEmpty()) {
				ObligationsType oblsType = obj.setObligations(polSet
						.getObligations());
				policySetType.setObligations(oblsType);
			}

		}

		return polTypeSet;
	}

	/**
	 * Transforms a Set {@code Policy} instances to a Set of {@code PolicyType}
	 * instances.
	 * 
	 * @param polSet
	 * @return polTypeSet
	 */
	public Set<PolicyType> setPolicyTypes(Set<Policy> polSet) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		PolicyType policyType;
		TargetType targetType = new TargetType();
		Set<PolicyType> polTypeSet = new HashSet<PolicyType>(0);
		for (Policy pol : polSet) {
			policyType = new PolicyType();
			if (!pol.getDescription().isEmpty())
				policyType.setDescription(pol.getDescription());
			policyType.setPolicyId(pol.getPolicyId());
			policyType.setVersion("2.0");
			policyType.setRuleCombiningAlgId(pol.getRuleCombAlgo());

			if (pol.getTarget() != null) {
				targetType = obj.setTarget(pol.getTarget());
			}

			policyType.setTarget(targetType);

			// Get rules from Policy
			if (!pol.getRules().isEmpty()) {
				Set<RuleType> ruleTypeSet = obj.setRuleTypes(pol.getRules());
				for (RuleType ruleType : ruleTypeSet)
					policyType
							.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition()
							.add(ruleType);
			}

			if (!pol.getObligations().isEmpty()) {
				ObligationsType oblsType = obj.setObligations(pol
						.getObligations());
				policyType.setObligations(oblsType);
			}

			polTypeSet.add(policyType);
		}

		tx.commit();
		return polTypeSet;

	}

	/**
	 * Deletes all existing Policies and generates all XACML Policy Sets based
	 * in the {@code policySetList}
	 * 
	 * @param policySetList
	 * @return
	 * @throws IOException
	 */
	public boolean generateAllXACMLPolicySets(ArrayList<PolicySet> policySetList)
			throws IOException {
		// The Policy Repository
		File repository = new File(POLICYSET_REPOSITORY_PATH);
		// List of all files in the folder (All files may or may not be .xml)
		File fList[] = repository.listFiles();
		// Searches policies
		for (int i = 0; i < fList.length; i++) {
			File polSet = fList[i];
			String polName = polSet.getName();
			if (polName.contains("_PS") && polName.endsWith(".xml")) {
				// and deletes
				polSet.delete();
			}
		}

		for (PolicySet p : policySetList) {
			this.generateXACMLPolicySet(p.getPkPolicySet());
		}
		return true;
	}
}
