package Demo;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public final class ElGamal {
	
	private static BigInteger r;
	private static List<BigInteger> encrypt;
	private static List<BigInteger> encrypt2;

    public static BigInteger TWO = new BigInteger("2");

    //Generate key for ElGamal
    public static List<List<BigInteger>> KeyGen(int n) {
        BigInteger p = getPrime(n, 40, new Random());
        BigInteger g = randNum(p, new Random());
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);

        while (!g.modPow(pPrime, p).equals(BigInteger.ONE)) {
            if (g.modPow(pPrime.multiply(ElGamal.TWO), p).equals(BigInteger.ONE))
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

    //ElGamal encryption function
    public static List<BigInteger> Encrypt(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);
        r = randNum(pPrime, new Random());
        return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
    }
    
    //ElGamal decryption function for second input
    public static List<BigInteger> Encrypt_Second(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(ElGamal.TWO);
        return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
    } 

    
    //ElGamal decryption function
    public static BigInteger Decrypt(BigInteger p, BigInteger x, BigInteger gr, BigInteger mhr) {
        BigInteger hr = gr.modPow(x, p);
        return mhr.multiply(hr.modInverse(p)).mod(p);
    }

    //Generate a prime BigInt
    public static BigInteger getPrime(int nb_bits, int certainty, Random prg) {
        BigInteger pPrime = new BigInteger(nb_bits, certainty, prg);
        BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

        while (!p.isProbablePrime(certainty)) {
            pPrime = new BigInteger(nb_bits, certainty, prg);
            p = pPrime.multiply(TWO).add(BigInteger.ONE);
        }
        return p;
    }

    //Generate a random BigInt
    public static BigInteger randNum(BigInteger N, Random prg) {
        return new BigInteger(N.bitLength() + 100, prg).mod(N);
    }
    
    
    //Additive Homomorphic Encryption function
    public static void startAdditiveHomomorphicEncryption(String input1, String input2,BigInteger p, BigInteger x) {
	  
        System.out.println("Additive Homomorphic Encrypting now, please wait...");
        System.out.println("**********************" + "Additive Homomorphic Encryption Start" + "********************");
        System.out.println("Ciphertext for first input: \t\t\t\t\t" + encrypt.toString());
        //System.out.println("Decrypted : " + ElGamal.Decrypt(p, x, encrypt.get(0), encrypt.get(1)));
        
        System.out.println("Ciphertext for second input: \t\t\t\t\t" + encrypt2.toString());
        //System.out.println("Decrypted : " + ElGamal.Decrypt(p, x, encrypt2.get(0), encrypt2.get(1)));
        
        BigInteger addResult;
        addResult =  (encrypt2.get(1).add(encrypt.get(1)).mod(p));
        List<BigInteger> encryptAggregation = new ArrayList<>(Arrays.asList(encrypt.get(0), addResult));
        
        System.out.println("Additive Aggregation of two ciphertext: \t\t\t" + encryptAggregation.toString());        
        System.out.println("Additive Aggregation of two ciphertext decryption: \t\t" + ElGamal.Decrypt(p, x, encryptAggregation.get(0), encryptAggregation.get(1)));
        System.out.println("Additive Aggregation of two plaintext: \t\t\t\t" + (Integer.parseInt(input1) + Integer.parseInt(input2)));
        System.out.println("**********************" + "Additive Homomorphic Encryption End" + "**********************");
        System.out.println();
        System.out.println();
                
    }
    
    //Multiplicative Homomorphic Encryption function
    public static void startMultiplicativeHomomorphicEncryption(String input1, String input2,BigInteger p, BigInteger x) {
  	  
        System.out.println("**********************" + "Multiplicative Homomorphic Encryption Start" + "********************");
        System.out.println("Multiplicative  Homomorphic Encrypting now, please wait...");
        //System.out.println("Ciphertext for first input: \t\t\t\t" + encrypt.toString());
        //System.out.println("Decrypted : " + ElGamal.Decrypt(p, x, encrypt.get(0), encrypt.get(1)));
        
        //System.out.println("Ciphertext for second input: \t\t\t\t" + encrypt2.toString());
        //System.out.println("Decrypted : " + ElGamal.Decrypt(p, x, encrypt2.get(0), encrypt2.get(1)));
        
        BigInteger MultiplyResult;
        MultiplyResult =  (encrypt2.get(1).multiply(encrypt.get(1))).mod(p);
        List<BigInteger> encryptAggregationMultiply = new ArrayList<>(Arrays.asList((encrypt.get(0).multiply(encrypt2.get(0)).mod(p)), MultiplyResult));
        
        System.out.println("Multiplicative Aggregation of two ciphertext: \t\t\t" + encryptAggregationMultiply.toString());        
        System.out.println("Multiplicative Aggregation of two ciphertext decryption: \t" + ElGamal.Decrypt(p, x, encryptAggregationMultiply.get(0), encryptAggregationMultiply.get(1)));
        System.out.println("Multiplicative Aggregation of two plaintext: \t\t\t" + (Integer.parseInt(input1) * Integer.parseInt(input2)));
        System.out.println("**********************" + "Multiplicative Homomorphic Encryption End" + "**********************");
                
    }
    

    public static void main(String[] args) {
        List<List<BigInteger>> pksk = ElGamal.KeyGen(200);
        // public key
        BigInteger p = pksk.get(0).get(0);
        BigInteger g = pksk.get(0).get(1);
        BigInteger h = pksk.get(0).get(2);
        // secret key
        BigInteger p_sk = pksk.get(1).get(0);
        BigInteger x = pksk.get(1).get(1);
        
        //get input
        System.out.println("Please input first plaintext(INT):");
        Scanner sc=new Scanner(System.in);
        String strInput = sc.nextLine();        
        encrypt = ElGamal.Encrypt(p, g, h, new BigInteger(strInput));
        
        System.out.println("Please input second plaintext(INT):");
        Scanner sc2=new Scanner(System.in);
        String strInput2 = sc.nextLine();        
        encrypt2 = ElGamal.Encrypt_Second(p, g, h, new BigInteger(strInput2));
        
        //start HomomorphicEncryption
        startAdditiveHomomorphicEncryption(strInput,strInput2,p,x);      
        startMultiplicativeHomomorphicEncryption(strInput,strInput2,p,x);

    }
}
