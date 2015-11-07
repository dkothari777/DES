import java.math.BigInteger;

import gnu.getopt.Getopt;
import java.security.SecureRandom;

public class RSA_skeleton {
	private static boolean kflag = false;
	public static void main(String[] args){
		
		StringBuilder bitSizeStr = new StringBuilder(); //this is the -k -b bit-size default should be 1024
		StringBuilder nStr = new StringBuilder();
		StringBuilder dStr = new StringBuilder();
		StringBuilder eStr = new StringBuilder();
		StringBuilder m = new StringBuilder();
		
		
		pcl(args, bitSizeStr, nStr, dStr, eStr,m);
		
		if(!bitSizeStr.toString().equalsIgnoreCase("")){
			//This means you want to create a new key
			genRSAkey(bitSizeStr.toString());
			kflag = false;
		}
		
		if(kflag== true){
			genRSAkey("1024");
			kflag = false;
		}
		
		if(!eStr.toString().equalsIgnoreCase("")){
			RSAencrypt(m, nStr, eStr);
		}
		
		if(!dStr.toString().equalsIgnoreCase("")){
			RSAdecrypt(m, nStr, dStr);
		}
		
		
	}



	private static void RSAencrypt(StringBuilder m, StringBuilder nStr, StringBuilder eStr) {
		// TODO Auto-generated method stub
	}

	private static void RSAdecrypt(StringBuilder cStr, StringBuilder nStr,
			StringBuilder dStr){
		// TODO Auto-generated method stub
	}
	
	private static void genRSAkey(String bitSizeStr) {
		// TODO Auto-generated method stub
		SecureRandom rnd = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(Integer.parseInt(bitSizeStr), rnd);
		BigInteger q = BigInteger.probablePrime(Integer.parseInt(bitSizeStr), rnd);
		BigInteger n = p.multiply(q);
		BigInteger fi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		Integer e_int= rnd.nextInt()%10000;
		BigInteger e = new BigInteger(e_int.toString());
		while (e_int%2 == 0 || fi_n.mod(e) == BigInteger.ZERO || e.mod(fi_n) == BigInteger.ZERO){
			e_int= rnd.nextInt()%10000;
			e = new BigInteger(e_int.toString());
		}
		BigInteger d = e.modInverse(fi_n);
		System.out.println("Public: " + e.toString(16) + n.toString(16));
		System.out.println("Private: " + d.toString(16)+ n.toString(16));
	}


	/**
	 * This function Processes the Command Line Arguments.
	 */
	private static void pcl(String[] args, StringBuilder bitSizeStr,
							StringBuilder nStr, StringBuilder dStr, StringBuilder eStr,
							StringBuilder m) {
		/*
		 * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
		*/	
		Getopt g = new Getopt("Chat Program", args, "hke:d:b:n:i:");
		int c;
		String arg;
		while ((c = g.getopt()) != -1){
		     switch(c){
		     	  case 'i':
		        	  arg = g.getOptarg();
		        	  m.append(arg);
		        	  break;
		          case 'e':
		        	  arg = g.getOptarg();
		        	  eStr.append(arg);
		        	  break;
		     	  case 'n':
		        	  arg = g.getOptarg();
		        	  nStr.append(arg);
		        	  break;
		     	  case 'd':
		        	  arg = g.getOptarg();
		        	  dStr.append(arg);
		        	  break;
		          case 'k':
		        	  kflag = true;
		        	  break;
		     	  case 'b':
		        	  arg = g.getOptarg();
		        	  bitSizeStr.append(arg);
		        	  break;
		          case 'h':
		        	  callUsage(0);
		          case '?':
		            break; // getopt() already printed an error
		          default:
		              break;
		       }
		   }
	}
	
	private static void callUsage(int exitStatus) {

		String useage = "-h\n\tPrints out all the command line options supported by your program.\n\n"
				+ "-k -b <bit_size>\n\tgenerates a public/private key pair, encoded in hex, printed on the command line. The size of the key is given by the <bit_size>.\n\n"
				+ "-e <public key> -i <plaintext_value>\n"
				+ "\tencrypts the text <plaintext_value> using the <public key> and prints the output.\n\n"
				+ "-d <private_key> -i <ciphertext_value>\n"
				+ "\tdecrypts the file <ciphertext_value> using the <private_key> and prints the output.\n";
		
		System.err.println(useage);
		System.exit(exitStatus);
		
	}


}
