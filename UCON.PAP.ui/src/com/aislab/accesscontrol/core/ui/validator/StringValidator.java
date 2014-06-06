package com.aislab.accesscontrol.core.ui.validator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

public class StringValidator implements Validator {

	private final static String STRING_PATTERN = "(([a-zA-Z0-9_-])+([a-zA-Z0-9'_ -])*)+";

	private final static Pattern STRING_COMPILED_PATTERN = Pattern
			.compile(STRING_PATTERN);

	public void validate(FacesContext context, UIComponent component,
			Object value) throws ValidatorException {

		Matcher matcher = STRING_COMPILED_PATTERN.matcher((String) value);

		if (!matcher.matches()) {

			// System.out.println("============>  :" + dataType);
			FacesMessage message = new FacesMessage();
			message.setSeverity(FacesMessage.SEVERITY_ERROR);
			message.setSummary("String is not valid.");
			message.setDetail("String is not valid.");
			throw new ValidatorException(message);
		}
	}
}
