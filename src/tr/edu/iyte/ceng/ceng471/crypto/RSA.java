package tr.edu.iyte.ceng.ceng471.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import tr.edu.iyte.ceng.ceng471.crypto.CryptoUtil.BezoutPolynomial;;

public class RSA {
	
	private BigInteger p;
	private BigInteger q;
	private BigInteger e;
	private BigInteger d;
	
	public RSA() {
		SecureRandom rand = new SecureRandom();
		BigInteger lo = BigInteger.valueOf(1009);
		BigInteger hi = BigInteger.valueOf(105943);
		do {
			p = new BigInteger(16, rand);
			if(p.compareTo(lo) < 0 && p.compareTo(hi) > 0)
				continue;
		} while(!CryptoUtil.checkPrimality(p));
		
		do {
			q = new BigInteger(12, rand);
			if(q.compareTo(lo) < 0 && q.compareTo(hi) > 0)
				continue;
		} while(!CryptoUtil.checkPrimality(q));
	}
	
	public BigInteger getP() {
		return this.p;
	}
	
	public BigInteger getQ() {
		return this.q;
	}
	
	public BigInteger getN() {
		return p.multiply(q);
	}

	public BigInteger getPublicKey() {
		return this.e;
	}
	

	public BigInteger getPrivateKey() {
		return this.d;
	}
	
	public void generateKeyPair() {
		BigInteger totient = this.computeLeastCommonMultiple();			
		SecureRandom rand = new SecureRandom();
		BezoutPolynomial poly = null;
	
		do {
			e = new BigInteger(totient.bitLength(), rand);
			if(e.compareTo(BigInteger.ONE) < 0 && e.compareTo(totient) > 0)
				continue;
			
			poly = CryptoUtil.computePolynomial(e, totient);
			
		}while(!poly.isCoPrime());
		
		d = poly.computeMultiplicativeInverse();
	}
	
	public BigInteger encrypt(BigInteger msg) {
		BigInteger n = p.multiply(q);
		
		return msg.pow(e.intValue()).mod(n);
	}
	
	public BigInteger encrypt(BigInteger msg, BigInteger e, BigInteger n) {
		return msg.pow(e.intValue()).mod(n);
	}
	
	public BigInteger decrypt(BigInteger msg) {
		BigInteger n = p.multiply(q);
		
		return msg.pow(d.intValue()).mod(n);
	}

	private BigInteger computeLeastCommonMultiple() {
		BigInteger a = p.subtract(BigInteger.ONE);
		BigInteger b = q.subtract(BigInteger.ONE);
		BezoutPolynomial poly = CryptoUtil.computePolynomial(a, b);
		
		BigInteger mul = a.multiply(b);
		
		return mul.divide(poly.computeGCD());		
	}
	
	public static void main(String[] args) {
		RSA rsa = new RSA();
		rsa.generateKeyPair();
		BigInteger msg = BigInteger.valueOf(23);
		System.out.println("Message is " + msg);
		BigInteger cipher = rsa.encrypt(msg);
		System.out.println("Encrypted: " + cipher);
		System.out.println("Alice decrypted as " + rsa.decrypt(cipher));

	}

}
