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

import java.util.List;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Environment Attributes
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class EnvironmentAttributeDAO {
	/**
	 * A SessionFactory variable to configure the database session
	 */
	public static SessionFactory sessionFactory;

	/**
	 * A Session variable to store the session opened
	 */
	public static Session session;

	/**
	 * A Transaction variable used to start a transaction in a session
	 */
	public static Transaction tx;

	/**
	 * A Query variable used to retrieve information from database
	 */
	Query query;

	/**
	 * Fetching list of environment attributes based on environment selection
	 * 
	 * @param envPk
	 *            primary key of environment
	 * 
	 * @return List<EnvironmentAttribute> List of environment attributes
	 * 
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<EnvironmentAttribute> selectEnvironmentAttributes(Long envPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select env.environmentAttributes from Environment env where env.pkEnvironment ="
						+ envPk);
		List<EnvironmentAttribute> envAttr = query.list();

		tx.commit();
		session.close();
		return envAttr;

	}

	/**
	 * Selecting environment attribute
	 * 
	 * @param envAttrPk
	 *            primary key of environment attribute
	 * 
	 * 
	 * @return EnvironmentAttribute Value of Environment attribute
	 * 
	 */

	public EnvironmentAttribute selectEnvironmentAttribute(Long envAttrPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from EnvironmentAttribute envAttr where envAttr.pkEnvAttr = "
						+ envAttrPk);
		EnvironmentAttribute envAttr = (EnvironmentAttribute) query
				.uniqueResult();

		tx.commit();
		return envAttr;

	}

	/**
	 * Populating list of environment attributes based on environment selection
	 * 
	 * @param envPk
	 *            primary key of environment
	 * 
	 * @return List<String> List of environment attributes
	 * 
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<String> populateEnvAttrList(Long envPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select envAttrId from EnvironmentAttribute envAttr"
						+ " where envAttr.environment = " + envPk);
		List<String> envAttr = query.list();

		tx.commit();
		session.close();
		return envAttr;

	}

	/**
	 * Creating a new environment attribute
	 * 
	 * @param environment
	 *            value of environment
	 * 
	 * 
	 * @param envAttrId
	 *            Environment attribute id
	 * 
	 */

	public void createEnvironmentAttr(Environment environment, String envAttrId) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvironmentAttribute envAttr = new EnvironmentAttribute(environment,
				envAttrId);

		session.persist(envAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new environment attribute value
	 * 
	 * @param environment
	 *            value of environment
	 * 
	 * 
	 * @param envAttrId
	 *            Environment attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of action attribute
	 * 
	 * 
	 * @param attrValue
	 *            value of environment attribute
	 * 
	 */

	public void createEnvironmentAttrValue(Environment environment,
			String envAttrId, String dataType, String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvironmentAttribute envAttr = new EnvironmentAttribute(environment,
				envAttrId, dataType);
		EnvAttrValues attrVal = new EnvAttrValues(envAttr, attrValue);

		session.persist(envAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new environment attribute
	 * 
	 * @param environment
	 *            value of environment
	 * 
	 * 
	 * @param envAttrId
	 *            Environment attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of environment
	 * 
	 */

	public void createEnvironmentAttr(Environment environment,
			String envAttrId, String dataType) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvironmentAttribute envAttr = new EnvironmentAttribute(environment,
				envAttrId, dataType);

		session.persist(envAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Updating an environment attribute
	 * 
	 * @param envAttrPk
	 *            primary key of environment
	 * 
	 * 
	 * @param envAttrId
	 *            Environment attribute id
	 * 
	 * 
	 */

	public void updateEnvironmentAttr(Long envAttrPk, String envAttrId) {
		selectEnvironmentAttributes(envAttrPk);
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvironmentAttribute envAttr = (EnvironmentAttribute) session.load(
				EnvironmentAttribute.class, envAttrPk);
		envAttr.setEnvAttrId(envAttrId);

		session.persist(envAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting an environment attribute
	 * 
	 * @param pkEnvAttr
	 *            primary key of environment
	 * 
	 * 
	 */

	public void deleteEnvironmentAttribute(Long pkEnvAttr) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from EnvironmentAttribute e where e.pkEnvAttr = "
						+ pkEnvAttr);
		EnvironmentAttribute envAttr = (EnvironmentAttribute) query
				.uniqueResult();

		session.delete(envAttr);
		tx.commit();
		session.close();
	}

}
