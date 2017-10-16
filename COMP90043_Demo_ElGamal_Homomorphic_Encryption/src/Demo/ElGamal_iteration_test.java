package Demo;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public final class ElGamal_iteration_test {

	private static BigInteger r;
	private static List<BigInteger> encrypt;
	private static List<BigInteger> encrypt2;

	public static BigInteger TWO = new BigInteger("2");

	// Generate key for ElGamal
	public static List<List<BigInteger>> KeyGen(int n) {
		BigInteger p = getPrime(n, 40, new Random());
		BigInteger g = randNum(p, new Random());
		BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal_iteration_test.TWO);

		while (!g.modPow(pPrime, p).equals(BigInteger.ONE)) {
			if (g.modPow(pPrime.multiply(ElGamal_iteration_test.TWO), p).equals(BigInteger.ONE))
				g = g.modPow(TWO, p);
			else
				g = randNum(p, new Random());
		}

		BigInteger x = randNum(pPrime.subtract(BigInteger.ONE), new Random());
		BigInteger h = g.modPow(x, p);
		List<BigInteger> sk = new ArrayList<>(Arrays.asList(p, x));
		List<BigInteger> pk = new ArrayList<>(Arrays.asList(p, g, h));
		return new ArrayList<>(Arrays.asList(pk, sk));
	}

	// ElGamal encryption function
	public static List<BigInteger> Encrypt(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
		BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal_iteration_test.TWO);
		r = randNum(pPrime, new Random());
		return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
	}

	// ElGamal decryption function for second input
	public static List<BigInteger> Encrypt_Second(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
		BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal_iteration_test.TWO);
		return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
	}

	// ElGamal decryption function
	public static BigInteger Decrypt(BigInteger p, BigInteger x, BigInteger gr, BigInteger mhr) {
		BigInteger hr = gr.modPow(x, p);
		return mhr.multiply(hr.modInverse(p)).mod(p);
	}

	// Generate a prime BigInt
	public static BigInteger getPrime(int nb_bits, int certainty, Random prg) {
		BigInteger pPrime = new BigInteger(nb_bits, certainty, prg);
		BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

		while (!p.isProbablePrime(certainty)) {
			pPrime = new BigInteger(nb_bits, certainty, prg);
			p = pPrime.multiply(TWO).add(BigInteger.ONE);
		}
		return p;
	}

	// Generate a random BigInt
	public static BigInteger randNum(BigInteger N, Random prg) {
		return new BigInteger(N.bitLength() + 100, prg).mod(N);
	}

	// Super powerful loop, when decryption result is not equal to estimate result, break the loop
	public static void startEncryptionLoop(BigInteger input1, BigInteger input2, BigInteger p, BigInteger x) {
		System.out.println("Additive Homomorphic Encrypting now, please wait...");
		System.out.println("**************************" + "Infinite Additive Homomorphic Encryption Start"
				+ "***********************");

		int count = 1;
		String successfulState = "success";
		boolean a;
		BigInteger decryptionResult;
		BigInteger estimatedResult;
		List<BigInteger> resultList = new ArrayList<BigInteger>();

		int resultIsTrue = 0;
		estimatedResult = input1.add(input2);

		//do the first loop and initialise all elements
		resultList = startAdditiveHomomorphicEncryption(encrypt.get(1), encrypt2.get(1), p, x);
		decryptionResult = startAdditiveHomomorphicDecryption(resultList.get(1), p, x);
		resultIsTrue = estimatedResult.compareTo(decryptionResult);

		while (resultIsTrue == 0) {

			if (resultIsTrue == 0) {
				for (int i = 1; i < count; i++) {
					resultList = startAdditiveHomomorphicEncryption(resultList.get(1), resultList.get(1), p, x);
				}
				for (int i = 1; i < count; i++) {
					decryptionResult = startAdditiveHomomorphicDecryption(resultList.get(1), p, x);
					// System.out.println("decryptionResult:" + decryptionResult);
				}

				resultIsTrue = (estimatedResult).compareTo(decryptionResult);
				System.out.println("Estimated Result:\t" + estimatedResult);
				System.out.println("Decryption Result:\t" + decryptionResult);
				//update the estimated result
				estimatedResult = estimatedResult.multiply(TWO.pow(count));
			}

			if (resultIsTrue != 0) {
				successfulState = "fail";
			}
			System.out.println("Enpcryt for loop: " + count + "\t" + successfulState);
			System.out.println();

			count++;
		}

		System.out.println("-------------------------------END------------------------------");
	}

	// Additive Homomorphic Encryption function
	public static List<BigInteger> startAdditiveHomomorphicEncryption(BigInteger s21, BigInteger s22, BigInteger p,
			BigInteger x) {

		int resultIsTrue;
		BigInteger additiveResult;
		BigInteger additiveResultBigInt;
		BigInteger decryptResult;

		BigInteger addResult;
		addResult = (s21.add(s22).mod(p));
		List<BigInteger> encryptAggregation = new ArrayList<>(Arrays.asList(encrypt.get(0), addResult));

		return new ArrayList<>(Arrays.asList(encryptAggregation.get(0), encryptAggregation.get(1)));

	}

	public static BigInteger startAdditiveHomomorphicDecryption(BigInteger s2, BigInteger p, BigInteger x) {

		BigInteger decryptResult;
		decryptResult = ElGamal_iteration_test.Decrypt(p, x, encrypt.get(0), s2);

		// resultIsTrue = decryptResult.compareTo(additiveResultBigInt);
		return decryptResult;

	}

	//main
	public static void main(String[] args) {
		List<List<BigInteger>> pksk = ElGamal_iteration_test.KeyGen(200);
		// public key
		BigInteger p = pksk.get(0).get(0);
		BigInteger g = pksk.get(0).get(1);
		BigInteger h = pksk.get(0).get(2);
		// secret key
		BigInteger p_sk = pksk.get(1).get(0);
		BigInteger x = pksk.get(1).get(1);

		// get input
		System.out.println("Please input first plaintext(INT):");
		Scanner sc = new Scanner(System.in);
		String strInput = sc.nextLine();
		encrypt = ElGamal_iteration_test.Encrypt(p, g, h, new BigInteger(strInput));

		System.out.println("Please input second plaintext(INT):");
		Scanner sc2 = new Scanner(System.in);
		String strInput2 = sc.nextLine();
		encrypt2 = ElGamal_iteration_test.Encrypt_Second(p, g, h, new BigInteger(strInput2));

		// start HomomorphicEncryption
		startEncryptionLoop(new BigInteger(strInput), new BigInteger(strInput2), p, x);
		// startMultiplicativeHomomorphicEncryption(strInput,strInput2,p,x);

	}
}
