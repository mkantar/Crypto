package tr.edu.iyte.ceng.ceng471.crypto;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import tr.edu.iyte.ceng.ceng471.crypto.CryptoUtil.BezoutPolynomial;

public class ElGamal {
	private BigInteger p;
	private BigInteger g;
	
	private BigInteger x;
	private BigInteger y;
	
	public ElGamal()  {
		Random rand = new Random();
		BigInteger lo = BigInteger.valueOf(1009);
		BigInteger hi = BigInteger.valueOf(105943);
		do {
			p = new BigInteger(16, rand);
			if(p.compareTo(lo) < 0 && p.compareTo(hi) > 0)
				continue;
		} while(!CryptoUtil.checkPrimality(p));
		
		BigInteger totient = p.subtract(BigInteger.ONE);
		ArrayList<BigInteger> factors = new ArrayList<BigInteger>();
		BigInteger n = p.subtract(BigInteger.ONE);
		for(BigInteger i = BigInteger.valueOf(2); i.compareTo(n) <= 0; i = i.add(BigInteger.ONE)) {
			while(n.mod(i).equals(BigInteger.ZERO)) {
				factors.add(i);
				n = n.divide(i);
			}
		}
		
		for(BigInteger a = BigInteger.valueOf(2);; a = a.add(BigInteger.ONE)) {
			boolean found = true;
			for(int i = 0; i < factors.size(); i++) {
				BigInteger exponient = totient.divide(factors.get(i));
				if(a.mod(exponient).equals(BigInteger.ONE))
					found = found && false;
				else
					found = found && true;
			}
			if(found) {
				this.g = a;
				break;
			}
		}
	
	}

	public BigInteger getP() {
		return this.p;
	}
	
	public BigInteger getG() {
		return this.g;
	}
	
	public BigInteger getPrivateKey() {
		return this.x;
	}
	
	public BigInteger getPublicKey() {
		return this.y;
	}
	
	public void generateKeyPair() {
		Random rand = new Random();
		BigInteger totient = p.subtract(BigInteger.ONE);
		do {
			x = new BigInteger(16, rand);
		} while((p.compareTo(BigInteger.ONE) <= 0) && (p.compareTo(totient) > 0));
		
		y = g.pow(x.intValue()).mod(p);	
	}
	
	public BigInteger[] encrypt(BigInteger msg) {
		Random rand = new Random();
		BigInteger totient = p.subtract(BigInteger.ONE);
		BigInteger k = BigInteger.ONE;
		do {
			k = new BigInteger(16, rand);
		} while((p.compareTo(BigInteger.ONE) <= 0) && (p.compareTo(totient) > 0));
		
		BigInteger c1 = g.pow(k.intValue()).mod(p);
		BigInteger c2 = msg.multiply(y.pow(k.intValue())).mod(p);
		
		return new BigInteger[] {c1, c2};
	}
	
	public BigInteger[] encrypt(BigInteger msg, BigInteger y, BigInteger p, BigInteger g) {
		Random rand = new Random();
		BigInteger totient = p.subtract(BigInteger.ONE);
		BigInteger k = BigInteger.ONE;
		do {
			k = new BigInteger(16, rand);
		} while((p.compareTo(BigInteger.ONE) <= 0) && (p.compareTo(totient) > 0));
		
		BigInteger c1 = g.pow(k.intValue()).mod(p);
		BigInteger c2 = msg.multiply(y.pow(k.intValue())).mod(p);
		
		return new BigInteger[] {c1, c2};
	}
	
	public BigInteger decrypt(BigInteger[] cipher) {
		BigInteger s = cipher[0].pow(x.intValue()).mod(p);
		BezoutPolynomial poly = CryptoUtil.computePolynomial(s, p);
		s = poly.computeMultiplicativeInverse();
		
		return cipher[1].multiply(s).mod(p);
	}
	
	public static void main(String[] args) {
		ElGamal elgamal = new ElGamal();
		elgamal.generateKeyPair();
		BigInteger msg = BigInteger.valueOf(26);
		System.out.println("Message is " + msg);
		BigInteger[] cipher = elgamal.encrypt(msg);
		System.out.println("Encrypted: " + cipher[0] + ", " + cipher[1]);
		System.out.println("Alice decrypted as " + elgamal.decrypt(cipher));
	}
}
