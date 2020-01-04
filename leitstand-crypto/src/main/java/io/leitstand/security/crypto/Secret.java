/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.crypto;

import static java.util.Arrays.fill;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * A secret for symmetric cryptography such as AES encryption for example.
 * <p>
 * The {@link #clear()} method removes the secret from memory 
 * by replacing the secret with <code>null</code> values. 
 */
public class Secret implements Serializable{

	private static final long serialVersionUID = 1L;

	private byte[] value;
	
	/**
	 * Creates a <code>Secret</code>.
	 * @param value the binary value of the secret
	 */
	public Secret(byte[] value){
		this.value = Arrays.copyOf(value, value.length);
	}
	
	/**
	 * Returns the binary value of this secret.
	 * @return the binary value of this secret.
	 */
	public byte[] toByteArray(){
		return Arrays.copyOf(value, value.length);
	}
	
	/**
	 * Calculates a non-secure hashcode from this secret's binary value.
	 * The intention of this method is to be compliant to the <code>equals</code> and
	 * <code>hashCode</code> contract specified by <code>java.lang.Object</code>.
	 * <p>
	 * {@inheritDoc}
	 * </p>
	 * @return a non-secure hashcode from this secret's binary value.
	 */
	@Override
	public int hashCode(){
		return Objects.hash(value);
	}
	
	/**
	 * Two secrets are considered equal, if the have the same binary value.
	 * <p>
	 * {@inheritDoc}
	 * </p>
	 */
	@Override
	public boolean equals(Object o){
		if(o == null){
			return false;
		}
		if(o == this){
			return true;
		}
		if(getClass() != o.getClass()){
			return false;
		}
		return Arrays.equals(value, ((Secret)o).value);
	}
	
	/**
	 * Returns the base 64 encoded value of this secret.
	 * @return the base 64 encoded value of this secret.
	 */
	@Override
	public String toString(){
		return Base64.getEncoder().encodeToString(value);
	}
	
	/**
	 * Overwrites the secret with null values to remove it from memory.
	 */
	public void clear() {
		fill(value, (byte) 0);
	}
	
}
