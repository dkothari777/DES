import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.BitSet;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64.Encoder;

import gnu.getopt.Getopt;


public class DES_Skeleton {

	public static void main(String[] args) {
		
		StringBuilder inputFile = new StringBuilder();
		StringBuilder outputFile = new StringBuilder();
		StringBuilder keyStr = new StringBuilder();
		StringBuilder encrypt = new StringBuilder();
		
		pcl(args, inputFile, outputFile, keyStr, encrypt);
		
		if(keyStr.toString() != "" && encrypt.toString().equals("e")){
			encrypt(keyStr, inputFile, outputFile);
		} else if(keyStr.toString() != "" && encrypt.toString().equals("d")){
			decrypt(keyStr, inputFile, outputFile);
		}
		
		
	}
	

	private static void decrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
		try {
			PrintWriter writer = new PrintWriter(outputFile.toString(), "UTF-8");
			List<String> lines = Files.readAllLines(Paths.get(inputFile.toString()), Charset.defaultCharset());
			String IVStr = lines.get(0);
			lines.remove(0);
			String encryptedText;
			
			for (String line : lines) {
				encryptedText = DES_decrypt(IVStr, line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * TODO: You need to write the DES encryption here.
	 * @param line
	 */
	private static String DES_decrypt(String iVStr, String line) {
	
		
		return null;
	}


	private static void encrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
		
		try {
			PrintWriter writer = new PrintWriter(outputFile.toString(), "UTF-8");
			
			String encryptedText;
			for (String line : Files.readAllLines(Paths.get(inputFile.toString()), Charset.defaultCharset())) {
				encryptedText = DES_encrypt(keyStr.toString(),line);
				writer.print(encryptedText);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		
	}
	/**
	 * TODO: You need to write the DES encryption here.
	 * @param line
	 */
	private static String DES_encrypt(String key, String line) {
		processKey(key);
		byte[] l = line.getBytes();
		
		return null;
	}
	
	private static void processKey(String key){
		SBoxes sbox = new SBoxes();
		BigInteger k = permutateKey(new BigInteger(key, 16), sbox.PC1);
		String k_str = k.toString(2);
		String c_0 = k_str.substring(0, k_str.length()/2);
		String d_0 = k_str.substring(k_str.length()/2, k_str.length());
		
	}
	//Taken From StackOverflow 
	//http://stackoverflow.com/questions/4299111/convert-long-to-byte-array-and-add-it-to-another-array
	private static byte[] longToByteArray(long hex) {
		return new byte[] {
				(byte) (hex >> 56),
				(byte) (hex >> 48),
				(byte) (hex >> 40),
				(byte) (hex >> 32),
				(byte) (hex >> 24),
				(byte) (hex >> 16),
				(byte) (hex >> 8),
				(byte) hex
		};
	}
	private static BigInteger permutateKey(BigInteger k, int[] pc){
		String bin_k = k.toString(2);
		String new_key = "";
		
		for(int i=0; i< pc.length; i++) {
			new_key += bin_k.charAt(pc[i]-1);
		}
		return new BigInteger(new_key, 2);
	}
	
	static void genDESkey(){
		System.out.println("3F52D4829C358A95");
		
		return;
	}


	/**
	 * This function Processes the Command Line Arguments.
	 * -p for the port number you are using
	 * -h for the host name of system
	 */
	private static void pcl(String[] args, StringBuilder inputFile,
							StringBuilder outputFile, StringBuilder keyString,
							StringBuilder encrypt) {
		/*
		 * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
		*/	
		Getopt g = new Getopt("Chat Program", args, "hke:d:i:o:");
		int c;
		String arg;
		while ((c = g.getopt()) != -1){
		     switch(c){
		     	  case 'o':
		        	  arg = g.getOptarg();
		        	  outputFile.append(arg);
		        	  break;
		     	  case 'i':
		        	  arg = g.getOptarg();
		        	  inputFile.append(arg);
		        	  break;
	     	  	  case 'e':
		        	  arg = g.getOptarg();
		        	  keyString.append(arg);
		        	  encrypt.append("e");
		        	  break;
	     	  	  case 'd':
		        	  arg = g.getOptarg();
		        	  keyString.append(arg);
		        	  encrypt.append("d");
		        	  break;
		          case 'k':
		        	  genDESkey();
		        	  break;
		          case 'h':
		        	  callUseage(0);
		          case '?':
		            break; // getopt() already printed an error
		            //
		          default:
		              break;
		       }
		   }
		
	}
	
	private static void callUseage(int exitStatus) {
		
		String useage = "-h\n\tPrints out all the command line options supported by your program.\n\n"
				+ "-k\n\tgenerates a DES key, encoded in hex, printed on the command line.\n\n"
				+ "-e <64 bit key in hex> -i <input file> -o <output file>\n"
				+ "\tencrypts the file <input file> using <64 bit key in hex> and stores the encrypted file in the <output file>\n\n"
				+ "-d <64 bit key in hex> -i <input file> -o <output file>\n"
				+ "\t decrypts the file <input file> using <64 bit key in hex> and stores the plain text file in the <output file>\n";
		
		System.err.println(useage);
		System.exit(exitStatus);
		
	}
	
}
