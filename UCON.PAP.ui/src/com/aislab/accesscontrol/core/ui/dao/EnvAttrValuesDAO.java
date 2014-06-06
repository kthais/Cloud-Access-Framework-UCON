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
import java.util.List;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.EnvAttrValues;
import com.aislab.accesscontrol.core.entities.EnvironmentAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Environment Attribute
 * Values
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class EnvAttrValuesDAO {
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
	 * Populating a list of environment attribute value based on selection
	 * 
	 * @param pkEnvAttr
	 *            primary key of environment attribute
	 * @return list of environment attribute values
	 */

	@SuppressWarnings("unchecked")
	public List<EnvAttrValues> populateEnvValueList(Long pkEnvAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session
				.createQuery("from EnvAttrValues val where val.environmentAttribute = "
						+ pkEnvAttr);
		List<EnvAttrValues> vals = query.list();

		tx.commit();
		session.close();
		return vals;
	}

	/**
	 * Deleting the selected environment attribute value
	 * 
	 * @param pkEnvAttrVal
	 *            primary key of environment attribute value
	 * 
	 */

	public void deleteEnvironmentAttributeValue(Long pkEnvAttrVal) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from EnvAttrValues e where e.pkEnvAttrVal = "
						+ pkEnvAttrVal);

		EnvAttrValues val = (EnvAttrValues) query.uniqueResult();
		session.delete(val);
		tx.commit();
		session.close();
	}

	/**
	 * Updating the selected environment attribute value
	 * 
	 * @param pkEnvAttrVal
	 *            primary key of environment attribute value
	 * 
	 * @param envAttrValue
	 *            string to be updated
	 * 
	 */

	public void updateEnvAttrValue(Long pkEnvAttrVal, String envAttrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvAttrValues val = (EnvAttrValues) session.load(EnvAttrValues.class,
				pkEnvAttrVal);
		val.setEnvAttrValue(envAttrValue);

		session.persist(val);
		tx.commit();
		session.close();
	}

	/**
	 * Creating the selected environment attribute value
	 * 
	 * @param envAttr
	 *            value of the environment attribute
	 * 
	 * @param attrValue
	 *            string to be added for the selected environment attribute
	 * 
	 */

	public void createEnvAttrValue(EnvironmentAttribute envAttr,
			String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		EnvAttrValues val = new EnvAttrValues(envAttr, attrValue);

		session.persist(val);
		tx.commit();
		session.close();
	}

	/**
	 * Populating a list of environment attribute value based on selection
	 * 
	 * @param pkEnvAttr
	 *            primary key of environment attribute
	 * @return list of environment attribute values
	 */

	@SuppressWarnings("unchecked")
	public ArrayList<EnvAttrValues> selectEnvAttrValue(Long pkEnvAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session
				.createQuery("from EnvAttrValues val where val.environmentAttribute = "
						+ pkEnvAttr);
		ArrayList<EnvAttrValues> vals = (ArrayList<EnvAttrValues>) query.list();

		tx.commit();
		session.close();
		return vals;

	}
}