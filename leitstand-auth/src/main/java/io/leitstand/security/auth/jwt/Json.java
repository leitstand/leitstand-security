/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.auth.jwt;

import static io.leitstand.commons.model.StringUtil.fromUtf8Bytes;
import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static javax.json.bind.JsonbBuilder.create;
import static javax.json.bind.config.PropertyNamingStrategy.LOWER_CASE_WITH_UNDERSCORES;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbConfig;
import javax.json.bind.config.PropertyVisibilityStrategy;

/**
 * A thread-safe utility to convert Java object graphs to JSON object graphs and vice versa via JSON-B.
 */
class Json {
	
	//Jsonb is thread-safe
	private static final Jsonb JSONB;

	static {
		// Create a default JSON config:
		// - UTF-8 character encoding
		// - snake case property names (lower case and underscore as delimiter)
		// - enable field access (via PropertyVisibilityStrategy)
		JsonbConfig JWT_CONFIG = new JsonbConfig()
									 .withEncoding("UTF-8")
									 .withPropertyNamingStrategy(LOWER_CASE_WITH_UNDERSCORES)
									 .withPropertyVisibilityStrategy(new PropertyVisibilityStrategy() {
												
									 @Override
									public boolean isVisible(Method method) {
										 return method.getName().startsWith("get") 
												&& (method.getModifiers() & Modifier.PUBLIC) == Modifier.PUBLIC;
									}
												
									@Override
									public boolean isVisible(Field field) {
										return true;
									}
								});
		JSONB = create(JWT_CONFIG);
	}
	
	/**
	 * Converts the given object tree to a JSON string.
	 * @param o - the root object of the object tree.
	 * @return the JSON representation
	 */
	public static String toJson(Object o) {
		return JSONB.toJson(o);
	}
	
	/**
	 * Converts the given object to a JSON string and 
	 * converts the JSON string into a byte array using 
	 * UTF-8 as character encoding.
	 * @param o - the root object of the object tree
	 * @return the JSON representation as byte array.
	 */
	public static byte[] marshal(Object o) {
		return toUtf8Bytes(toJson(o));
	}
	
	/**
	 * Converts the byte array to a string using UTF-8 character encoding and 
	 * creates the object tree from the JSON structure.
	 * @param type - the Java type of the object tree root object
	 * @param data - the JSON data as byte array
	 * @return the object tree root object
	 */
	public static <T> T unmarshal(Class<T> type, byte[] data) {
		return fromJson(type,fromUtf8Bytes(data));
	}
	
	/**
	 * Converts a JOSN string to a Java object tree.
	 * @param type - the Java type of the object tree root object
	 * @param json - the JSON string
	 * @return the object tree root object
	 */
	public static <T> T fromJson(Class<T> type, String json) {
		return JSONB.fromJson(json, type);
	}
	
	private Json() {
		// No instances allowed
	}
}
