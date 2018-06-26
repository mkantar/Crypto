package tr.edu.iyte.ceng.ceng471.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.Random;

public class DiffieHellman {

	private BigInteger prime = BigInteger.ZERO;
	private BigInteger generator = BigInteger.ZERO;
	private BigInteger secret = BigInteger.ZERO;
	private BigInteger publicKey = BigInteger.ZERO;
	private BigInteger sharedKey = BigInteger.ZERO;
	private SecureRandom rand = new SecureRandom();
	
	public DiffieHellman(BigInteger p, BigInteger g) {
		this.prime = p;
		this.generator = g;
		this.secret = new BigInteger(26, rand);
		this.publicKey = generator.modPow(secret, prime);
	}
	
	public BigInteger getPublicKey() {
		return publicKey;
	}
	
	public BigInteger getSharedKey() {
		if(sharedKey.equals(BigInteger.ZERO))
			throw new NoSuchElementException("Shared key is not generated.");
		
		return sharedKey;
	}
	
	public void setSharedKey(BigInteger o) {
		sharedKey = o.modPow(secret, prime);
	}
	
	public static void main(String[] args) {
		DiffieHellman dhAlice = new DiffieHellman(BigInteger.valueOf(23), BigInteger.valueOf(5));
		DiffieHellman dhBob = new DiffieHellman(BigInteger.valueOf(23), BigInteger.valueOf(5));
		dhAlice.setSharedKey(dhBob.getPublicKey());
		dhBob.setSharedKey(dhAlice.getPublicKey());
		System.out.println(dhBob.getSharedKey());
		System.out.println(dhAlice.getSharedKey());
	}
}
