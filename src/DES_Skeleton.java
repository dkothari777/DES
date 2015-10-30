import gnu.getopt.Getopt;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Base64.Encoder;


public class DES_Skeleton {
	private static SBoxes sbox = new SBoxes();
	private static BigInteger iv;
	
	public static void main(String[] args) {
		
		StringBuilder inputFile = new StringBuilder();
		StringBuilder outputFile = new StringBuilder();
		StringBuilder keyStr = new StringBuilder();
		StringBuilder encrypt = new StringBuilder();
		
		pcl(args, inputFile, outputFile, keyStr, encrypt);
		
		if(keyStr.toString() != "" && encrypt.toString().equals("e")){
			iv = generateIV();
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
			iv = new BigInteger(IVStr,16);
			int count = 0;
			for (String line : lines) {
				if(count != 0)
					IVStr = line;
				encryptedText = DES_decrypt(IVStr, line, keyStr.toString());
				writer.print(encryptedText);
				count ++;
			}
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * TODO: You need to write the DES encryption here.
	 * @param line
	 */
	private static String DES_decrypt(String iVStr, String line, String key) {
		BigInteger[] sub_keys = processKey(key);
		BigInteger l = new BigInteger(line,16);
		String results = "";			
			
		BigInteger ip_blck = permutate(l, sbox.IP, 64);
		String ip_str = addPadding(ip_blck.toString(2), 64);
		String ip_l = ip_str.substring(0, ip_str.length()/2);
		String ip_r = ip_str.substring(ip_str.length()/2, ip_str.length());
		
		BigInteger[] l_arr = new BigInteger[17];
		BigInteger[] r_arr = new BigInteger[17];
		l_arr[0] = new BigInteger(ip_l, 2);
		r_arr[0] = new BigInteger(ip_r, 2);
		for(int i=1, j=15; i<17; i++, j--) {
			l_arr[i] = r_arr[i-1];
			r_arr[i] = l_arr[i-1].xor(functionE(r_arr[i-1], sub_keys[j]));
		}
		BigInteger decrypted = new BigInteger(addPadding(r_arr[16].toString(2),32)+addPadding(l_arr[16].toString(2),32),2);
		decrypted = permutate(decrypted, sbox.FP, 64);
		decrypted = decrypted.xor(iv);
		iv = l;
		results += removeTrailingZeros(addPadding(decrypted.toString(16),16));
		if(decrypted.toString(16).equals("0")){
			results += '\n';
		}
	
		return results;
	}

	//code taken from http://wiki.scn.sap.com/wiki/display/Java/Remove+Leading+and+Trailing+Zeros+from+a+String
	private static String removeTrailingZeros( java.lang.String str ){
		if (str == null){
			return null;
		}
		char[] chars = str.toCharArray();int length,index ;length = str.length();
		index = length -1;
		for (; index >=0;index--){
			if (chars[index] != '0'){
				break;
			}
		}
		return (index == length-1) ? str :str.substring(0,index+1);
	}

	private static void encrypt(StringBuilder keyStr, StringBuilder inputFile,
			StringBuilder outputFile) {
		
		try {
			PrintWriter writer = new PrintWriter(outputFile.toString(), "UTF-8");
			
			String encryptedText;
			writer.println(iv.toString(16));
			for (String line : Files.readAllLines(Paths.get(inputFile.toString()), Charset.defaultCharset())) {
				encryptedText = DES_encrypt(keyStr.toString(),line);
				writer.print(encryptedText);
			}
			writer.close();
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
		//line = asciiToHex(line);
		byte[] k = line.getBytes();
		if(line.isEmpty()){
			return "";
		}
		BigInteger l = new BigInteger(line, 16);
		BigInteger[] blocks = splitBlock(l, k.length*4);
		String results = "";
		
		for(BigInteger blck: blocks){
			
			blck = blck.xor(iv);
			
			BigInteger ip_blck = permutate(blck, sbox.IP, 64);
			String ip_str = addPadding(ip_blck.toString(2), 64);
			String ip_l = ip_str.substring(0, ip_str.length()/2);
			String ip_r = ip_str.substring(ip_str.length()/2, ip_str.length());
			
			BigInteger[] l_arr = new BigInteger[17];
			BigInteger[] r_arr = new BigInteger[17];
			l_arr[0] = new BigInteger(ip_l, 2);
			r_arr[0] = new BigInteger(ip_r, 2);
			for(int i=1; i<17; i++) {
				l_arr[i] = r_arr[i-1];
				r_arr[i] = l_arr[i-1].xor(functionE(r_arr[i-1], sub_keys[i-1]));
			}
			BigInteger encrypted = new BigInteger(addPadding(r_arr[16].toString(2),32)+addPadding(l_arr[16].toString(2),32),2);
			encrypted = permutate(encrypted, sbox.FP, 64);
			iv = encrypted;
			results += encrypted.toString(16) + '\n';
		}
		return results;
	}
	
	private static BigInteger generateIV() {
		byte[] b = new byte[8];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		return new BigInteger(b).abs();
	}


	private static BigInteger functionE(BigInteger r, BigInteger k){		
		BigInteger x_er = k.xor(permutate(r, sbox.E, 32));
		String s_er = addPadding(x_er.toString(2),48);
		String new_er="";
		for(int i=0; i<48; i+=6){
			new_er += substitute(s_er.substring(i, i+6), i/6);
		}
		
		return permutate(new BigInteger(new_er,2), sbox.P ,32);
	}
	
	private static String substitute(String s, int n){
		byte[] sb = sbox.S[n];
		String i="", j="";
		i += s.charAt(0);		// 00 01 11
		i += s.charAt(5);		// 0000 0001 0010
		j = s.substring(1,5);
		
		int row = Integer.parseInt(i, 2);
		int col = Integer.parseInt(j, 2);
		
		byte b[] = {sb[row*16 + col]};
		BigInteger newS = new BigInteger(b);
		
		
		
		return addPadding(newS.toString(2), 4);
	}
	
	
	private static BigInteger[] processKey(String key){
		BigInteger k = permutate(new BigInteger(key, 16), sbox.PC1, 64);
		String k_str = addPadding(k.toString(2), 56);
		String c_0 = k_str.substring(0, k_str.length()/2);
		String d_0 = k_str.substring(k_str.length()/2, k_str.length());
		BigInteger[] c_arr = new BigInteger[17];
		BigInteger[] d_arr = new BigInteger[17];
		c_arr[0] = new BigInteger(c_0, 2);
		d_arr[0] = new BigInteger(d_0, 2);
		for(int i=1; i<17; i++) {
			c_arr[i] = rotateKey(c_arr[i-1], sbox.rotations[i-1]);
			d_arr[i] = rotateKey(d_arr[i-1], sbox.rotations[i-1]);
		}
		BigInteger[] sub_keys = new BigInteger[16];
		for(int i =1; i<17; i++){
			sub_keys[i-1] = mergeKeys(c_arr[i], d_arr[i], 28);
		}
		for(int i=0; i< 16; i++){
			sub_keys[i] = permutate(sub_keys[i], sbox.PC2, 56);
		}
		return sub_keys;
	}

	private static BigInteger permutate(BigInteger k, int[] pc, int length){
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
		while(str.length()<64){
			str+='0';
		}
		return new BigInteger(str,2);
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
	
	private static BigInteger[] splitBlock(BigInteger line, int length) {
		ArrayList<BigInteger> block_list = new ArrayList<BigInteger>();
		String x = addPadding(line.toString(2), length);
		if(x.length() < 64){
			block_list.add(splitPadding(x, x.length()));
		}
		else{
			int k = 0;
			while(x.length() - k >= 64){
				block_list.add(new BigInteger(x.substring(k, k+64),2));
				k = k+64;
			}
			if(x.length()-k > 0){
				block_list.add(splitPadding(x.substring(k,  x.length()), x.length()-k));
			}	
		}
		
		block_list.add(splitPadding("",0));
		
		return block_list.toArray(new BigInteger[block_list.size()]);
	}
	
	static void genDESkey(){
		byte[] b = new byte[8];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		System.out.println((new BigInteger(b)).toString(16));
		return;
	}
	
	private static String asciiToHex(String asciiValue)
	{
	    char[] chars = asciiValue.toCharArray();
	    StringBuffer hex = new StringBuffer();
	    for (int i = 0; i < chars.length; i++)
	    {
	        hex.append(Integer.toHexString((int) chars[i]));
	    }
	    return hex.toString();
	}
	
	private static String hexToASCII(String hexValue)
	{
	    StringBuilder output = new StringBuilder("");
	    for (int i = 0; i < hexValue.length(); i += 2)
	    {
	        String str = hexValue.substring(i, i + 2);
	        output.append((char) Integer.parseInt(str, 16));
	    }
	    return output.toString();
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
