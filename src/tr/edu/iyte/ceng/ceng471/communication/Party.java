package tr.edu.iyte.ceng.ceng471.communication;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;  

import tr.edu.iyte.ceng.ceng471.crypto.AES;
import tr.edu.iyte.ceng.ceng471.crypto.DES;
import tr.edu.iyte.ceng.ceng471.crypto.ElGamal;
import tr.edu.iyte.ceng.ceng471.crypto.RSA;
import tr.edu.iyte.ceng.ceng471.crypto.SymmetricKey;

public class Party {
	private long id;
	private static long genId = 1;
	private String name;
	private ModeOfOperation mode;
	private SymmetricKey symt;
	private RSA rsa;
	private ElGamal elgamal;
	
	public Party(String name) {
		this.name = name;
		this.id = genId;
		genId++;
	}
	
	public long getId() {
		return this.id;
	}
	
	public String getName() {
		return name;
	}
	
	public void setMode(ModeOfOperation mode) {
		this.mode = mode;
	}
	
	public void init(BigInteger key) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		if(!(mode.equals(ModeOfOperation.DES) || mode.equals(ModeOfOperation.AES)))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		if(mode.equals(ModeOfOperation.DES))
			symt = new DES(key);
		else if(mode.equals(ModeOfOperation.AES))
			symt = new AES(key);
		else 
			throw new InvalidAlgorithmParameterException("Mode of opeation is invalid!");
	}
	
	public void init() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		if(!(mode.equals(ModeOfOperation.RSA) || mode.equals(ModeOfOperation.ELGAMAL)))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		
		if(mode.equals(ModeOfOperation.RSA)) {
			rsa = new RSA();
			rsa.generateKeyPair();
		} else if(mode.equals(ModeOfOperation.ELGAMAL)) {
			elgamal =  new ElGamal();
			elgamal.generateKeyPair();
		}
		else 
			throw new InvalidAlgorithmParameterException("Mode of opeation is invalid!");
	}
	
	public BigInteger getPublicKey() throws NoSuchAlgorithmException {
		if(!(mode.equals(ModeOfOperation.RSA) || mode.equals(ModeOfOperation.ELGAMAL)))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		
		if(mode.equals(ModeOfOperation.RSA))
			return rsa.getPublicKey();
		else if(mode.equals(ModeOfOperation.ELGAMAL))
			return elgamal.getPublicKey();
		else 
			return null;		
	}
	
	public BigInteger encryptRSA(BigInteger msg, BigInteger publicKey, BigInteger n) throws NoSuchAlgorithmException {
		if(!mode.equals(ModeOfOperation.RSA))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		
		if(mode.equals(ModeOfOperation.RSA))
			return rsa.encrypt(msg, publicKey, n);
		else 
			return null;
	}
	
	public BigInteger[] encryptElGamal(BigInteger msg, BigInteger publicKey, BigInteger p, BigInteger g) throws NoSuchAlgorithmException {
		if(!mode.equals(ModeOfOperation.ELGAMAL))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		 if(mode.equals(ModeOfOperation.ELGAMAL))
			return elgamal.encrypt(msg, publicKey, p, g);
		else 
			return null;
	}
	
	public String encryptSymmetric(String msg) throws NoSuchAlgorithmException {
		if(!(mode.equals(ModeOfOperation.DES) || mode.equals(ModeOfOperation.AES)))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		return symt.encrypt(msg);
	}
	
	public BigInteger decryptRSA(BigInteger msg) throws NoSuchAlgorithmException {
		if(!mode.equals(ModeOfOperation.RSA))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		
		if(mode.equals(ModeOfOperation.RSA))
			return rsa.decrypt(msg);
		else 
			return null;
	}
	
	public BigInteger decryptElGamal(BigInteger[] msg) throws NoSuchAlgorithmException {
		if(!mode.equals(ModeOfOperation.ELGAMAL))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		 if(mode.equals(ModeOfOperation.ELGAMAL))
			return elgamal.decrypt(msg);
		else 
			return null;
	}
	
	public String decryptSymmetric(String msg) throws NoSuchAlgorithmException {
		if(!(mode.equals(ModeOfOperation.DES) || mode.equals(ModeOfOperation.AES)))
			throw new NoSuchAlgorithmException("Invalid initialization!");
		return symt.decrypt(msg);
	}
	
	public BigInteger getN() {
		return rsa.getN();
	}
	
	public BigInteger getP() {
		return elgamal.getP();
	}
	
	public BigInteger getG() {
		return elgamal.getG();
	}


}
