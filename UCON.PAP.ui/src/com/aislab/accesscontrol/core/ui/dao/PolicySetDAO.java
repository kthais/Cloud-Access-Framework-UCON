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

package com.aislab.accesscontrol.core.ui.dao;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;


import com.aislab.accesscontrol.core.entities.Obligations;
import com.aislab.accesscontrol.core.entities.Policy;
import com.aislab.accesscontrol.core.entities.PolicySet;
import com.aislab.accesscontrol.core.entities.Target;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Policy Sets
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @author Muhammad Sadiq Alvi <10besemalvi@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class PolicySetDAO {
	/**
	 * A SessionFactory variable to configure the database session
	 */
	public static SessionFactory sessionFactory;

	/**
	 * A Session variable to store the session opened
	 */
	public static Session session;

	/**
	 * A Transaction variable used to start a database transaction in a session
	 */
	public static Transaction tx;

	/**
	 * A Query variable used to retrieve information from database
	 */
	Query query;

	/**
	 * Function to get Sub Policy Sets for a given Policy Set primary key
	 * 
	 * @param pkPolicySet
	 *            Primary Key of the given Policy Set
	 * @return Returns list of Sub PolicySets added to the given Policy Sets
	 */
	@SuppressWarnings("unchecked")
	public List<PolicySet> selectSubPolicySets(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet where pkPolicySet !="
				+ pkPolicySet);
		List<PolicySet> polSet = query.list();

		tx.commit();
		session.close();

		return polSet;
	}

	/**
	 * Deletes Target of a given PolicySet
	 * 
	 * @param pkPolicySet
	 *            -> Primary Key for the PolicySet of which Target is to be
	 *            deleted
	 */

	public void deleteTarget(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet where pkPolicySet ="
				+ pkPolicySet);
		PolicySet pSet = (PolicySet) query.uniqueResult();
		pSet.setTarget(null);

		session.update(pSet);
		tx.commit();
		session.close();

	}

	/**
	 * Returns List of All Policy Sets
	 * 
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<PolicySet> selectPolicySet() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet");
		List<PolicySet> polSet = query.list();

		tx.commit();
		session.close();
		return polSet;
	}

	/**
	 * Function for Creating a PolicySet, and adding it to the database with the
	 * following Parameters
	 * 
	 * @param policySetId
	 * @param policyCombAlgo
	 * @param targ
	 * @param description
	 * @param subPolicySet
	 * @param policies
	 * @param obligations
	 */
	public void createPolicySet(String policySetId, String policyCombAlgo,
			Target targ, String description, Set<PolicySet> subPolicySet,
			Set<Policy> policies, Set<Obligations> obligations) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		PolicySet polSet = new PolicySet(targ, policySetId, policyCombAlgo,
				description, subPolicySet, policies);
		polSet.setObligations(obligations);
		session.persist(polSet);
		tx.commit();
		session.close();
	}

	/**
	 * Function for Creating a PolicySet, and adding it to the database with the
	 * following Parameters
	 * 
	 * @param policySetId
	 * @param policyCombAlgo
	 * @param targ
	 * @param description
	 * @param subPolicySet
	 * @param policies
	 */

	public void createPolicySet(String policySetId, String policyCombAlgo,
			Target targ, String description, Set<PolicySet> subPolicySet,
			Set<Policy> policies) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		PolicySet polSet = new PolicySet(targ, policySetId, policyCombAlgo,
				description, subPolicySet, policies);
		session.persist(polSet);
		tx.commit();
		session.close();
	}

	/**
	 * Function for Updating Policy Set with the following parameters, for the
	 * given PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param description
	 * @param polCombAlgo
	 * @param targ
	 * @param policies
	 * @param subPolicySets
	 */

	public void updatePolicySet(Long pkPolicySet, String description,
			String polCombAlgo, Target targ, Set<Policy> policies,
			Set<PolicySet> subPolicySets) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setDescription(description);
		pol.setPolicyCombiningAlgo(polCombAlgo);
		pol.setTarget(targ);
		pol.setPolicies(policies);
		pol.setSubPolicySets(subPolicySets);

		session.update(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Function for Updating Policy Set with the following parameters, for the
	 * given PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param description
	 * @param polCombAlgo
	 */
	public void updatePolicySet(Long pkPolicySet, String description,
			String polCombAlgo) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setDescription(description);
		pol.setPolicyCombiningAlgo(polCombAlgo);
		session.update(pol);
		tx.commit();

		session.close();
	}

	/**
	 * Function for Updating Policy Set with the following parameters, for the
	 * given PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param description
	 * @param polCombAlgo
	 * @param target
	 */
	public void updatePolicySet(Long pkPolicySet, String description,
			String polCombAlgo, Target target) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setDescription(description);
		pol.setPolicyCombiningAlgo(polCombAlgo);
		pol.setTarget(target);
		session.update(pol);
		tx.commit();

		session.close();
	}

	/**
	 * Function for Updating Policy Set with the following parameters, for the
	 * given PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param targ
	 */
	public void updatePolicySetTarget(Long pkPolicySet, Target targ) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setTarget(targ);
		session.update(pol);
		tx.commit();
		session.close();

	}

	/**
	 * Function for Updating Policy Set with the Sub PolicySets, for the given
	 * PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param subPolicySets
	 */
	public void updatePolicySetSubPolicySets(Long pkPolicySet,
			Set<PolicySet> subPolicySets) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setSubPolicySets(subPolicySets);
		session.update(pol);
		tx.commit();
		session.close();
	}

	/**
	 * Function for Updating Policy Set with the Sub Policies, for the given
	 * PolicySet with the following Primary Key
	 * 
	 * @param pkPolicySet
	 * @param policies
	 */
	public void updatePolicySetSubPolicies(Long pkPolicySet,
			Set<Policy> policies) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setPolicies(policies);
		session.update(pol);
		tx.commit();
		session.close();

	}

	/**
	 * Function for deleting PolicySet with given Primary Key
	 * 
	 * @param pkPolicySet
	 */


	public void deletePolicySet(Long pkPolicySet) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet = "
				+ pkPolicySet);
		PolicySet polSet = (PolicySet) query.uniqueResult();

		session.delete(polSet);
		tx.commit();
		session.close();
	}

	/**
	 * Returns Target of the given PolicySet with the pkPolicySet Primary Key
	 * 
	 * @param pkPolicySet
	 * @return
	 */
	public Target getTarget(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		Target targ = (Target) session.createQuery(
				"select p.target from PolicySet p where p.pkPolicySet = "
						+ pkPolicySet).uniqueResult();
		tx.commit();
		return targ;
	}

	/**
	 * Returns Obligations of the given PolicySet with the pkPolicySet Primary
	 * Key
	 * 
	 * @param pkPolicySet
	 * @return
	 */
	@SuppressWarnings("unused")
	public List<Obligations> getObligations(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		PolicySet pSet = (PolicySet) session.createQuery(
				"from PolicySet p where p.pkPolicySet = " + pkPolicySet)
				.uniqueResult();
		tx.commit();
		List<Obligations> obList = new ArrayList<Obligations>(0);
		for (Obligations ob : obList) {
			obList.add(ob);
		}
		return obList;
	}

	/**
	 * Returns Sub PolicySets of the given PolicySet with the pkPolicySet
	 * Primary Key
	 * 
	 * @param pkPolicySet
	 * @return
	 */
	public List<PolicySet> getSubPolicySets(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		PolicySet tempPolSet = (PolicySet) session.load(PolicySet.class,
				pkPolicySet);
		List<PolicySet> subPolSet = new ArrayList<PolicySet>(0);
		for (PolicySet ps : tempPolSet.getSubPolicySets()) {
			subPolSet.add(ps);
		}

		tx.commit();
		session.close();
		return subPolSet;
	}

	/**
	 * Returns Sub Policies of the given PolicySet with the pkPolicySet Primary
	 * Key
	 * 
	 * @param pkPolicySet
	 * @return
	 */
	public List<Policy> getPolicy(Long pkPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		PolicySet tempPolSet = (PolicySet) session.load(PolicySet.class,
				pkPolicySet);
		List<Policy> pol = new ArrayList<Policy>(0);
		for (Policy p : tempPolSet.getPolicies()) {
			pol.add(p);
		}
		tx.commit();
		session.close();
		return pol;
	}

	/**
	 * Deletes Sub PolicySet of the given PolicySet with the pkPolicySet Primary
	 * Key
	 * 
	 * @param pkPolicySet
	 * @param pkSubPolicySet
	 */
	public void deleteSubPolicySet(Long pkPolicySet, Long pkSubPolicySet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet = "
				+ pkPolicySet);
		PolicySet polSet = (PolicySet) query.uniqueResult();
		Set<PolicySet> tempSubSet = polSet.getSubPolicySets();
		ArrayList<PolicySet> listPSet = new ArrayList<PolicySet>();
		for (PolicySet pSet : tempSubSet) {
			listPSet.add(pSet);
		}
		for (int i = 0; i < listPSet.size(); i++) {
			if (listPSet.get(i).getPkPolicySet() == pkSubPolicySet) {
				listPSet.remove(i);
				break;
			}

		}
		tempSubSet.clear();
		for (int i = 0; i < listPSet.size(); i++) {
			tempSubSet.add(listPSet.get(i));
		}
		polSet.setSubPolicySets(tempSubSet);
		session.update(polSet);
		tx.commit();
		session.close();

	}

	/**
	 * Deletes Sub Policies of the given PolicySet with the pkPolicySet Primary
	 * Key
	 * 
	 * @param pkPolicySet
	 * @param pkSubPolicy
	 */

	public void deleteSubPolicies(Long pkPolicySet, Long pkSubPolicy) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet = "
				+ pkPolicySet);
		PolicySet polSet = (PolicySet) query.uniqueResult();
		Set<Policy> tempSubSet = polSet.getPolicies();
		ArrayList<Policy> listPSet = new ArrayList<Policy>();
		for (Policy pSet : tempSubSet) {
			listPSet.add(pSet);
		}
		for (int i = 0; i < listPSet.size(); i++) {
			if (listPSet.get(i).getPkPolicy() == pkSubPolicy) {
				listPSet.remove(i);
				break;
			}

		}
		tempSubSet.clear();
		for (int i = 0; i < listPSet.size(); i++) {
			tempSubSet.add(listPSet.get(i));
		}
		polSet.setPolicies(tempSubSet);
		session.update(polSet);
		tx.commit();
		session.close();
	}

	/**
	 * Get all policy sets using policy set primary key
	 * 
	 * @param pkPolicySet
	 * 
	 */

	@SuppressWarnings("unchecked")
	public ArrayList<PolicySet> getAllPolicySets(Long pkPolicySet) {
		ArrayList<PolicySet> allPSets;
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from PolicySet p where p.pkPolicySet != "
				+ pkPolicySet);
		allPSets = (ArrayList<PolicySet>) query.list();
		return allPSets;
	}

	/**
	 * Select policies to add to the selected policy set
	 * 
	 * @param pSet
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<Policy> selectPoliciesToAdd(PolicySet pSet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		List<Policy> polList = (List<Policy>) session
				.createQuery(
						"from Policy p where p.pkPolicy not in (select pol.pkPolicy from PolicySet pSet join pSet.policies pol where pSet.pkPolicySet = "
								+ pSet.getPkPolicySet() + ")").list();

		tx.commit();
		session.close();
		return polList;

	}

	/**
	 * Select policy sets that are to be added in the slected policy set
	 * 
	 * @param pSet
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<PolicySet> selectPolicySetsToAdd(PolicySet pSet) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		List<PolicySet> polSetList = (List<PolicySet>) session
				.createQuery(
						"from PolicySet pSet where pSet.pkPolicySet not in (select subPSet.pkPolicySet from PolicySet superPSet join superPSet.subPolicySets subPSet where superPSet.pkPolicySet = "
								+ pSet.getPkPolicySet()
								+ ") and pSet.pkPolicySet != "
								+ pSet.getPkPolicySet()).list();

		tx.commit();
		session.close();
		return polSetList;

	}

	/**
	 * Add policies to the selected policy set
	 * 
	 * @param pSet
	 * 
	 * @param addedPolicyList
	 * 
	 */

	@SuppressWarnings("unchecked")
	public void addPolicy(PolicySet pSet, List<Policy> addedPolicyList) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<Policy> polList = (List<Policy>) session.createQuery(
				"select pSet.policies from PolicySet pSet where pSet.pkPolicySet = "
						+ pSet.getPkPolicySet()).list();
		// Add Policies to existing Policy List
		polList.addAll(addedPolicyList);
		pSet.setPolicies(new HashSet<Policy>(polList));
		session.saveOrUpdate(pSet);

		tx.commit();
		session.close();
	}

	/**
	 * Add sub policies to the selected policy set
	 * 
	 * @param pSet
	 * 
	 * @param addedPolicySetList
	 * 
	 */

	@SuppressWarnings("unchecked")
	public void addSubPolicySet(PolicySet pSet,
			List<PolicySet> addedPolicySetList) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		List<PolicySet> polSetList = (List<PolicySet>) session.createQuery(
				"select pSet.subPolicySets from PolicySet pSet where pSet.pkPolicySet = "
						+ pSet.getPkPolicySet()).list();
		// Add SubPolicySets to existing SubPolicySets List
		polSetList.addAll(addedPolicySetList);
		pSet.setSubPolicySets(new HashSet<PolicySet>(polSetList));
		session.saveOrUpdate(pSet);

		tx.commit();
		session.close();
	}

	/**
	 * Update existing policy set using the parameters below
	 * 
	 * @param pkPolicySet
	 * 
	 * @param policySetId
	 * 
	 * @param description
	 * 
	 * @param polCombAlgo
	 * 
	 * @param target
	 * 
	 */

	public void updatePolicySet(Long pkPolicySet, String policySetId,
			String description, String polCombAlgo, Target target) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from PolicySet p where p.pkPolicySet ="
				+ pkPolicySet);
		PolicySet pol = (PolicySet) query.uniqueResult();
		pol.setDescription(description);
		pol.setPolicyCombiningAlgo(polCombAlgo);
		pol.setTarget(target);
		pol.setPolicySetId(policySetId);
		session.update(pol);
		tx.commit();

		session.close();
	}
}
