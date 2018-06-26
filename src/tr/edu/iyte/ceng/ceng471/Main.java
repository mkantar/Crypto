package tr.edu.iyte.ceng.ceng471;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import tr.edu.iyte.ceng.ceng471.communication.ModeOfOperation;
import tr.edu.iyte.ceng.ceng471.communication.Party;
import tr.edu.iyte.ceng.ceng471.crypto.DiffieHellman;

public class Main {

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in).useDelimiter("\\s");
		
		System.out.print("Choose mode of operation:\n"
				+ "1) DES \n"
				+ "2) AES \n"
				+ "3) RSA \n"
				+ "4) ElGamal \n");
		
		Party bob = new Party("Bob");
		Party alice = new Party("Alice");
		
		ModeOfOperation mode = ModeOfOperation.values()[scanner.nextInt() - 1];
		
		bob.setMode(mode);
		alice.setMode(mode);
		
		if(mode.equals(ModeOfOperation.AES) || mode.equals(ModeOfOperation.DES)) {
			DiffieHellman dhBob = new DiffieHellman(BigInteger.valueOf(23), BigInteger.valueOf(5));
			DiffieHellman dhAlice = new DiffieHellman(BigInteger.valueOf(23), BigInteger.valueOf(5));
			
			dhBob.setSharedKey(dhAlice.getPublicKey());
			dhAlice.setSharedKey(dhBob.getPublicKey());			
			try {
				Scanner scl = new Scanner(System.in);
				alice.init(dhAlice.getSharedKey());
				bob.init(dhBob.getSharedKey());
				
				System.out.println("Enter a message to send to the Alice");
				
				String msg = scl.nextLine();
				
				System.out.println("Message is " + msg);
				
				String encrypted = bob.encryptSymmetric(msg);
				
				System.out.println("Encrypted message is " + encrypted);
				
				System.out.print("Alice decrypted as " + alice.decryptSymmetric(encrypted));
				
				scl.close();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if(mode.equals(ModeOfOperation.RSA)) {
			try {
				alice.init();
				bob.init();
				Scanner scr = new Scanner(System.in);
				System.out.println("Enter a message to send to the Alice (only number)");
				int msg = scr.nextInt();
				
				System.out.println("Message is " + msg);
				System.out.println("Alice public: " + alice.getPublicKey());
				BigInteger encrypted = bob.encryptRSA(BigInteger.valueOf(msg), alice.getPublicKey(), alice.getN());
				
				System.out.println("Encrypted message is " + encrypted);
				
				System.out.print("Alice decrypted as " + alice.decryptRSA(encrypted));
				
				scr.close();
				
			} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if(mode.equals(ModeOfOperation.ELGAMAL)) {
			try {
				alice.init();
				bob.init();
				Scanner sce = new Scanner(System.in);
				System.out.println("Enter a message to send to the Alice (only number)");
				int msg = sce.nextInt();
				
				System.out.println("Message is " + msg);
				System.out.println("Alice public: " + alice.getPublicKey());
				BigInteger[] encrypted = bob.encryptElGamal(BigInteger.valueOf(msg), alice.getPublicKey(), alice.getP(), alice.getG());
				
				System.out.println("Encrypted message is " + encrypted[0] + ", " + encrypted[1]);
				
				System.out.print("Alice decrypted as " + alice.decryptElGamal(encrypted));
				
				sce.close();
				
			} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		scanner.close();
	}

}
