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

import java.util.HashSet;
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
 * Class for querying Database for queries related to Environment Elements
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class EnvironmentDAO {
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
	 * Fetching list of environment elements from database
	 * 
	 * @return list of environment elements
	 */

	@SuppressWarnings("unchecked")
	public List<Environment> selectEnvironment() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Environment");
		List<Environment> env = query.list();

		tx.commit();
		session.close();
		return env;
	}

	/**
	 * Creating a new environment
	 * 
	 * @param env
	 *            value of the environment
	 * 
	 * 
	 */
	public void createEnvironment(Environment env) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(env);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new environment
	 * 
	 * @param description
	 *            description of the environment
	 * 
	 * @param environment
	 *            value of the environment
	 * 
	 */

	public void createEnvironment(String description, String environment) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Environment env = new Environment(environment, description);
		session.persist(env);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new environment
	 * 
	 * @param description
	 *            description of the environment
	 * 
	 * @param environment
	 *            value of the environment
	 * 
	 * @param envAttr
	 *            list of environment attributes
	 * 
	 */

	public void createEnvironment(String description, String environment,
			List<EnvironmentAttribute> envAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Environment env = new Environment(environment, description);

		env.setEnvironmentAttributes(new HashSet<EnvironmentAttribute>(envAttr));
		session.persist(env);

		for (EnvironmentAttribute attr : envAttr) {
			attr.setEnvironment(env);
			session.persist(attr);

			for (EnvAttrValues val : attr.getEnvAttrValues()) {
				val.setEnvironmentAttribute(attr);
				session.persist(val);
			}

		}
		tx.commit();
		session.close();
	}

	/**
	 * Updating an environment
	 * 
	 * 
	 * @param pkEnvironment
	 *            primary key of the environment
	 * 
	 * @param description
	 *            description of the environment
	 * 
	 * @param environment
	 *            value of the environment
	 * 
	 * @param envtAttr
	 *            list of environment attributes
	 * 
	 */

	public void updateEnvironment(Long pkEnvironment, String description,
			String environment, List<EnvironmentAttribute> envAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from Environment e where e.pkEnvironment ="
						+ pkEnvironment);
		Environment env = (Environment) query.uniqueResult();
		env.setDescription(description);
		env.setEnvironmentName(environment);
		env.setEnvironmentAttributes(new HashSet<EnvironmentAttribute>(envAttr));
		session.persist(env);
		tx.commit();
		session.close();
	}

	/**
	 * Updating an environment
	 * 
	 * 
	 * @param pkEenvironment
	 *            primary key of the environment
	 * 
	 * @param description
	 *            description of the environment
	 * 
	 * @param environment
	 *            value of the environment
	 */

	public void updateEnvironment(Long pkEnvironment, String description,
			String environment) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from Environment e where e.pkEnvironment ="
						+ pkEnvironment);
		Environment env = (Environment) query.uniqueResult();
		env.setDescription(description);
		env.setEnvironmentName(environment);

		session.persist(env);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting an environment
	 * 
	 * 
	 * @param pkEnvironment
	 *            primary key of the environment
	 * 
	 * 
	 */


	public void deleteEnvironment(Long pkEnvironment) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from Environment e where e.pkEnvironment = "
						+ pkEnvironment);
		Environment env = (Environment) query.uniqueResult();

		session.delete(env);
		tx.commit();
		session.close();
	}
}
