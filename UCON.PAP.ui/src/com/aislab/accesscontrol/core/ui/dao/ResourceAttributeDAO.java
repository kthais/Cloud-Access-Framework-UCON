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

import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Resource Attributes
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class ResourceAttributeDAO {
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
	 * Fetching list of resource attributes based on resource selection
	 * 
	 * @param resPk
	 *            primary key of resource
	 * 
	 * 
	 * @return List<ResourceAttribute> List of resource attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<ResourceAttribute> selectResourceAttributes(Long resPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select res.resourceAttributes from Resource res where res.pkResource ="
						+ resPk);
		List<ResourceAttribute> resAttr = query.list();

		tx.commit();
		session.close();
		return resAttr;

	}

	/**
	 * Selecting resource attribute
	 * 
	 * @param resAttrPk
	 *            primary key of resource attribute
	 * 
	 * 
	 * @return ResourceAttribute Value of resource attribute
	 * 
	 */

	public ResourceAttribute selectResourceAttribute(Long resAttrPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from ResourceAttribute resAttr where resAttr.pkResAttr = "
						+ resAttrPk);
		ResourceAttribute resAttr = (ResourceAttribute) query.uniqueResult();

		tx.commit();
		return resAttr;

	}

	/**
	 * Populating list of resource attributes based on resource selection
	 * 
	 * @param resPk
	 *            primary key of resource
	 * 
	 * 
	 * @return List<String> List of resource attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<String> populateResAttrList(Long resPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select resAttrId from ResourceAttribute resAttr"
						+ " where resAttr.resource = " + resPk);
		List<String> resAttr = query.list();

		tx.commit();
		session.close();
		return resAttr;

	}

	/**
	 * Creating a new resource attribute
	 * 
	 * @param resource
	 *            value of resource
	 * 
	 * 
	 * @param resAttrId
	 *            Resource attribute id
	 * 
	 * 
	 */

	public void createResourceAttr(Resource resource, String resAttrId) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ResourceAttribute resAttr = new ResourceAttribute(resource, resAttrId);

		session.persist(resAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new resource attribute value
	 * 
	 * @param resource
	 *            value of resource
	 * 
	 * 
	 * @param resAttrId
	 *            Resource attribute id
	 * 
	 * 
	 * @param attrValue
	 *            value of resource attribute
	 * 
	 */

	public void createResourceAttrValue(Resource resource, String resAttrId,
			String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ResourceAttribute resAttr = new ResourceAttribute(resource, resAttrId);
		ResAttrValues attrVal = new ResAttrValues(resAttr, attrValue);

		session.persist(resAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new resource attribute value
	 * 
	 * @param resource
	 *            value of resource
	 * 
	 * 
	 * @param resAttrId
	 *            Resource attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of resource
	 * 
	 * 
	 * @param attrValue
	 *            value of resource attribute
	 * 
	 */

	public void createResourceAttrValue(Resource resource, String resAttrId,
			String dataType, String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ResourceAttribute resAttr = new ResourceAttribute(resource, resAttrId,
				dataType);
		ResAttrValues attrVal = new ResAttrValues(resAttr, attrValue);

		session.persist(resAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new resource attribute
	 * 
	 * @param resource
	 *            value of resource
	 * 
	 * 
	 * @param resAttrId
	 *            Resource attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of resource
	 * 
	 */

	public void createResourceAttr(Resource resource, String resAttrId,
			String dataType) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ResourceAttribute resAttr = new ResourceAttribute(resource, resAttrId,
				dataType);

		session.persist(resAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Updating a resource attribute
	 * 
	 * @param resAttrPk
	 *            primary key of resource
	 * 
	 * 
	 * @param resAttrId
	 *            Resource attribute id
	 * 
	 * 
	 */

	public void updateResourceAttr(Long resAttrPk, String resAttrId) {
		selectResourceAttributes(resAttrPk);
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ResourceAttribute resAttr = (ResourceAttribute) session.load(
				ResourceAttribute.class, resAttrPk);
		resAttr.setResAttrId(resAttrId);

		session.persist(resAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting a resource attribute
	 * 
	 * @param pkResAttr
	 *            primary key of resource
	 * 
	 * 
	 */

	public void deleteResourceAttribute(Long pkResAttr) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from ResourceAttribute r where r.pkResAttr = "
						+ pkResAttr);
		ResourceAttribute resAttr = (ResourceAttribute) query.uniqueResult();

		session.delete(resAttr);
		tx.commit();
		session.close();
	}

}
