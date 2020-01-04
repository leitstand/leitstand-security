/*
 * (c) RtBrick, Inc - All rights reserved, 2015 - 2019
 */
package io.leitstand.security.users.model;

import static io.leitstand.security.crypto.SecureRandomFactory.newSHA1PRNG;
import static java.lang.String.format;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.enterprise.context.Dependent;
import javax.security.enterprise.credential.Password;

/**
 * A service to computes the password hash value.
 * <p>
 * In addition, this service provides methods to generate salt values and to verify whether a 
 * given password matches a given tuple of password hash, salt and iterations.
 * </p>
 * All password hashes are computed with <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a> 
 * and <a href="https://en.wikipedia.org/wiki/HMAC">HMAC-SHA256</a> as pseudo random function.
 * The salt values are computed with a cryptographically secure pseudorandom number generator.
 * The number of iterations is {@value #ITERATIONS}.
 * The hash value length in bytes is {@value #HASHBYTES}.
 * <p>
 * The number of iterations enables to adjust the cost of the hash computation. 
 * Thus the number of iterations shall be stored along with the computed password hash and salt values 
 * in order to be able to adjust the number of iterations in the future. 
 * During credentials verification the password hash is computed with the same number of iterations as
 * the stored password hash. If the password is valid, i.e. the password hashes match, then
 * a new password hash with a new salt value and the new number of iterations is computed and the password record gets updated.
 * By that all password hashes can be renewed incrementally.
 * </p>
 */
@Dependent
public class PasswordService {
	private static final Logger LOG = Logger.getLogger(PasswordService.class.getName());
	
	/** The number of iterations to compute the password hash value ({@value #ITERATIONS}). */
	public static final int ITERATIONS = 10000;
	
	/** The length of the computed hash value in bytes.*/
	public static final int HASHBYTES  = 64;
	
	/** The cryptographically secure pseudorandom number generator*/
	private static final SecureRandom PRNG = newSHA1PRNG();

	private SecretKeyFactory factory;
	
	/**
	 * Create a <code>PasswordService</code> instance.
	 */
	public PasswordService(){
		try{
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		} catch (NoSuchAlgorithmException e){
			LOG.severe(format("Algorithm PBKDIF2 is not available: %s",e.getMessage()));
		}
	}

	/**
	 * Computes the hash value for the given password.
	 * The password is cleared after the computation is done 
	 * to remove it as soon as possible from memory.
	 * @param password - the password to be hashed
	 * @param salt - the computed salt value
	 * @param iterations - the number of iterations 
	 * @return the computed hash value
	 */
	public byte[] hash(Password password, byte[] salt, int iterations) {
		try {
			return hash(password.getValue(),salt, iterations);
		} finally {
			password.clear();
		}
	}
	
	/**
	 * Computes the hash value for the given password.
	 * The password is overwritten with <code>0</code> values after the computation is done 
	 * to remove it as soon as possible from the heap.
	 * @param password - the password to be hashed
	 * @param salt - the computed salt value
	 * @param iterations - the number of iterations 
	 * @return the computed hash value
	 */
	public byte[] hash(char[] password, byte[] salt, int iterations){
		PBEKeySpec spec = new PBEKeySpec(password,salt,iterations,8*HASHBYTES);
		Arrays.fill(password, Character.MIN_VALUE);
		try{
			return factory.generateSecret(spec).getEncoded();
		} catch(InvalidKeySpecException e){
			LOG.severe(format("Cannot calculate a password hash: %s",e.getMessage()));
			throw new IllegalStateException(e);
		} finally {
			spec.clearPassword();
			Arrays.fill(password,(char)0);
		}
	}
	
	/**
	 * Computes a random salt value with a cryptographically secure pseudorandom number generator.
	 * @return the computed random salt value.
	 */
	public byte[] salt(){
		byte[] salt = new byte[HASHBYTES];
		PRNG.nextBytes(salt);
		return salt;
	}
	
	/**
	 * Compares the given password against the given tuple of password salt, hash and number of iterations. 
	 * The password is cleared after the validation is done to remove it as soon as possible from memory.	 
	 * @param password - the password to be verified
	 * @param salt - the stored salt value
	 * @param hash - the stored hash value
	 * @param iterations - the stored number of iterations
	 * @return <code>true</code> if the computed password hash matches the stored hash value, <code>false</code> otherwise.
	 */
	public boolean isExpectedPassword(Password password, 
									  byte[] salt, 
									  byte[] hash, 
									  int iterations){
		return Arrays.equals(hash, hash(password,salt,iterations));
	}

	/**
	 * Compares the given password against the given tuple of password salt, hash and number of iterations. 
	 * The password is overwritten with <code>0</code> values after the validation is done to remove it as soon as possible from memory.	 
	 * @param password - the password to be verified
	 * @param salt - the stored salt value
	 * @param hash - the stored hash value
	 * @param iterations - the stored number of iterations
	 * @return <code>true</code> if the computed password hash matches the stored hash value, <code>false</code> otherwise.
	 */
	public boolean isExpectedPassword(char[] password, 
									  byte[] salt, 
									  byte[] hash, 
									  int iterations){
		return Arrays.equals(hash, hash(password,salt,iterations));
	}
	
}
