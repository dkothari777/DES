import gnu.getopt.Getopt;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;


public class DES_Skeleton {
	private static SBoxes sbox = new SBoxes();

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
		BigInteger[] sub_keys = processKey(key);
		BigInteger l = new BigInteger(line.getBytes());
		BigInteger[] blocks = splitBlock(l);
		return null;
	}
	
	private static BigInteger[] processKey(String key){
		BigInteger k = permutateKey(new BigInteger(key, 16), sbox.PC1, 64);
		String k_str = addPadding(k.toString(2), 56);
		String c_0 = k_str.substring(0, k_str.length()/2);
		String d_0 = k_str.substring(k_str.length()/2, k_str.length());
		BigInteger[] c_arr = new BigInteger[17];
		BigInteger[] d_arr = new BigInteger[17];
		c_arr[0] = new BigInteger(c_0, 2);
		d_arr[0] = new BigInteger(d_0, 2);
		for(int i=1; i<17; i++) {
			c_arr[i] = rotateKey(c_arr[i-1], sbox.rotations[i-1]);
			d_arr[i] = rotateKey(d_arr[i-1], i-1);
		}
		for(int i=1; i< 17; i++){
			c_arr[i] = permutateKey(c_arr[i], sbox.PC2, 28);
			d_arr[i] = permutateKey(d_arr[i], sbox.PC2, 28);
		}
		BigInteger[] sub_keys = new BigInteger[16];
		for(int i =1; i<17; i++){
			sub_keys[i-1] = mergeKeys(c_arr[i], d_arr[i], 28);
		}
		return sub_keys;
	}

	private static BigInteger permutateKey(BigInteger k, int[] pc, int length){
		String bin_k = addPadding(k.toString(2), length);
		String new_key = "";
		
		for(int i=0; i< pc.length; i++) {
			new_key += bin_k.charAt(pc[i]-1);
		}
		return new BigInteger(new_key, 2);
	}
	
	private static String addPadding(String str, int length) {
		if(str.length() > length){
			throw new IllegalArgumentException();
		}
		if(str.length() == length)
			return str;
		while(str.length() !=  length)
			str = '0' + str;
		return str;
	}
	
	private static BigInteger splitPadding(String str, int length){
		if(str.length()>length){
			throw new IllegalArgumentException();
		}
		while(str.length()<57){
			str+='0';
		}
		BigInteger l = new BigInteger(Integer.toString(length));
		str+=addPadding(l.toString(2), l.bitLength());
		
		return new BigInteger(str);
	}
	
	private static BigInteger rotateKey(BigInteger k, int r) {
		String key = addPadding(k.toString(2), 28);
		while(r > 0){
			key = key.substring(1, key.length()) + key.charAt(0);
			r--;
		}
		return new BigInteger(key,2);
	}
	
	private static BigInteger mergeKeys(BigInteger c, BigInteger d, int length){
		String c_str = addPadding(c.toString(2), length);
		String d_str = addPadding(d.toString(2), length);
		return new BigInteger(c_str+d_str, 2);
	}
	
	private static BigInteger[] splitBlock(BigInteger line) {
		ArrayList<BigInteger> block_list = new ArrayList<BigInteger>();
		String x = addPadding(line.toString(2), line.bitLength()+1);
		if(x.length() < 64){
			block_list.add(splitPadding(x, x.length()));
		}else if(x.length() == 64){
			//add block of 0's
			block_list.add(splitPadding("",0));
		}else{
			int k = 0;
			while(x.length() - k > 64){
				block_list.add(new BigInteger(x.substring(k, k+64), 2));
				k = k+64;
			}
			block_list.add(splitPadding(x.substring(k,  x.length()), x.length()-k));
		}
		return (BigInteger[]) block_list.toArray();
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
