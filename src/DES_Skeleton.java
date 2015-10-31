import gnu.getopt.Getopt;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Name: Christopher Stepanski and Darshan Kothari
 * Assignment: DES
 * **/

public class DES_Skeleton {
	//We made Sboxes global variable, because I do not keep on instantiating them, but anyhow,
	//Sbox class holds all the permutations and substitutions needed by DES 
	private static SBoxes sbox = new SBoxes();
	//We did not want to change much of DES skeleton so we used a global variable to keep track of the ivStr
	private static BigInteger iv;
	
	/**
	 * Name: main
	 * Purpose: This will parse the arguments and see if whether the arguments 
	 * Parameters: String args. This will parse the arguments
	 * Return: Nothing
	 * Side Effect:Writes out either an encrypted file or decrypted 
	 * **/
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
	
	/**
	 * Name: encrypt
	 * Purpose: This function will read each line on the file and pass them on to DES_encrypt where
	 * 			the line will be encrypted then returned and written out to the specified file
	 * Parameters: Key, inputFile name, output File name
	 * Return: nothing
	 * Side Effect: Encrypted file is written. 
	 * **/
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
	 * Name: decrypt
	 * Purpose: Function will read each line and pass it onto DES_decrypt when each hex block will be decoded 
	 * Parameters: key, input filename, output filename
	 * Return: nothing
	 * Side Effect: a decrypted file is written
	 * **/
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
					IVStr = lines.get(count-1); // once the first cipher
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
	 * Name: DES_encrypt
	 * Purpose: This encrypts the line that is passed through
	 * Parameters: Key, line
	 * Return: encrypted string
	 * Side Effect: nothing
	 * **/
	private static String DES_encrypt(String key, String line) {
		BigInteger[] sub_keys = processKey(key); //creates 16 sub-keys
		line = asciiToHex(line); //converts line into hex so it fits how we coded it the first time
		byte[] k = line.getBytes(); //line may be longer than 64 bytes
		if(line.isEmpty()){ //if line is empty return empty string
			return "";
		}
		BigInteger l = new BigInteger(line, 16); //converts the Hex string to a big integers
		BigInteger[] blocks = splitBlock(l, k.length*4); //splits line into blocks of 64 bits
		String results = ""; // store the results of each block
		for(BigInteger blck: blocks){ //encrypt each block
			
			blck = blck.xor(iv); //xor for CBC
			
			BigInteger ip_blck = permutate(blck, sbox.IP, 64); //permutates the bits on sboxIP
			String ip_str = addPadding(ip_blck.toString(2), 64); //Big Integer normally removes the 0s in front add them back in
			String ip_l = ip_str.substring(0, ip_str.length()/2); //Split message into two left and right
			String ip_r = ip_str.substring(ip_str.length()/2, ip_str.length());
			
			BigInteger[] l_arr = new BigInteger[17]; // create arrays so we can run thru i-1 easily through a for loop
			BigInteger[] r_arr = new BigInteger[17];
			l_arr[0] = new BigInteger(ip_l, 2);
			r_arr[0] = new BigInteger(ip_r, 2);
			for(int i=1; i<17; i++) { //loops to get 16 
				l_arr[i] = r_arr[i-1]; //swap left and right sides
				r_arr[i] = l_arr[i-1].xor(functionE(r_arr[i-1], sub_keys[i-1])); //run through Function for each on the right then xor with the left
			}
			BigInteger encrypted = new BigInteger(addPadding(r_arr[16].toString(2),32)+addPadding(l_arr[16].toString(2),32),2); //merge the messages together
			encrypted = permutate(encrypted, sbox.FP, 64); //final permutation 
			iv = encrypted; //use this cipher block for the new IVStr
			results += encrypted.toString(16) + '\n'; //add it to the results
		}
		return results; //Once all the block are done it will return to results 
	}

	/**
	 * Name: DES_decrypt
	 * Purpose: decrypt each line to get the message back
	 * Parameters: iVstr, line, key
	 * Return: decrypted string
	 * Side Effect: nothing
	 * **/
	private static String DES_decrypt(String iVStr, String line, String key) {
		BigInteger[] sub_keys = processKey(key); //get the 16 sub-keys
		BigInteger l = new BigInteger(line,16); //convert Hex String to bigInt
		String results = ""; // place to return results
			
		BigInteger ip_blck = permutate(l, sbox.IP, 64); //permutate each block on IP 
		String ip_str = addPadding(ip_blck.toString(2), 64); //add Padding to 64 bit, because BigInteger removes the bits in front if they are all 0
		String ip_l = ip_str.substring(0, ip_str.length()/2); //split the encrypted string into a left and right 
		String ip_r = ip_str.substring(ip_str.length()/2, ip_str.length());
		
		BigInteger[] l_arr = new BigInteger[17]; //loop through each block in array in reverse order of the keys 
		BigInteger[] r_arr = new BigInteger[17];
		l_arr[0] = new BigInteger(ip_l, 2);
		r_arr[0] = new BigInteger(ip_r, 2);
		for(int i=1, j=15; i<17; i++, j--) {
			l_arr[i] = r_arr[i-1];
			r_arr[i] = l_arr[i-1].xor(functionE(r_arr[i-1], sub_keys[j]));
		}
		BigInteger decrypted = new BigInteger(addPadding(r_arr[16].toString(2),32)+addPadding(l_arr[16].toString(2),32),2); // merge the messages 
		decrypted = permutate(decrypted, sbox.FP, 64); //permutate on FP
		decrypted = decrypted.xor(iv); //xor the cipher block with the final decrypted block 
		iv = l; //update to the new line of iv may be dead code
		results += hexToASCII(removeTrailingZeros(addPadding(decrypted.toString(16),16))); //convert hex string to ascii chars and get rid of trailing zeroes in blocks
		if(decrypted.toString(16).equals("0")){ //If it is all zeros then it should be a new line
			results += '\n';
		}
	
		return results;
	}
	
	/**
	 * Name: removeTrailingZeroes 
	 * Purpose: get rid of trailing zeroes after the block is done 
	 * Parameters: String 
	 * Return: a String without trailing zeroes 
	 * Side Effect: Will throw Illegal Argument Exception if the string is null. This may never happen 
	 * Notes: Inspiration taken from http://wiki.scn.sap.com/wiki/display/Java/Remove+Leading+and+Trailing+Zeros+from+a+String
	 * **/
	private static String removeTrailingZeros(String str){
		if (str == null){ // check if the string is null or not 
			throw new IllegalArgumentException(); // throws Exception 
		}
		char[] chars = str.toCharArray(); //Convert String to char Array not really needed but it makes things easier 
		int index = str.length() -1; //Start at the end not at the beginning
		for (; index >=0;index--){
			if (chars[index] != '0'){ // if this is the index that there is not a zero then break
				break;
			}
		}
		if(index == str.length()-1) // if the index did not move then just return the normal string
			return str;
		else{
			String temp = str.substring(0, index+1); //return the substring from the beginning to index+1 (+1 bc substring is (inclusive, exclusive))
			if(temp.length()%2!=0) //If the length is not even add one more. When converting from hex to ascii, the string needs to be even
				temp = str.substring(0, index+2);
			return temp;
		}
	}

	/**
	 * Name: generateIV
	 * Purpose: generates an  random IVStr 
	 * Parameters: nothing
	 * Return: a BigInteger random
	 * Side Effect:
	 * **/
	private static BigInteger generateIV() {
		byte[] b = new byte[8];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		return new BigInteger(b).abs();
	}

	/**
	 * Name: Function E
	 * Purpose: This the function that the messages are run through 
	 * Parameters: The right half of the message and the key 
	 * Return: the new Big Integer of R 
	 * Side Effect: Nothing
	 * **/
	private static BigInteger functionE(BigInteger r, BigInteger k){		
		BigInteger x_er = k.xor(permutate(r, sbox.E, 32)); //key is xor with r where r is permutated on E. We know the size is going to be 32 bits
		String s_er = addPadding(x_er.toString(2),48); //add padding make sure it is the right length 
		String new_er="";
		for(int i=0; i<48; i+=6){
			new_er += substitute(s_er.substring(i, i+6), i/6); //substitute for each 6 bits (i/6 is to specify for each substitution array
		}
		
		return permutate(new BigInteger(new_er,2), sbox.P ,32); //Finally, permutate on P and return 
	}
	/**
	 * Name: substitute
	 * Purpose: Do the substitute part of 
	 * Parameters: string and which sbox to use
	 * Return: 4bits instead of 6 bits 
	 * Side Effect:
	 * **/
	private static String substitute(String s, int n){
		byte[] sb = sbox.S[n];//sbox that we are using 
		String i="", j="";
		i += s.charAt(0);	// get the first char in row
		i += s.charAt(5);		// get the second char in char
		j = s.substring(1,5); // get col in binary 
		int row = Integer.parseInt(i, 2); //parse binary to a readable it for row
		int col = Integer.parseInt(j, 2); //parse binary to readable col
		byte b[] = {sb[row*16 + col]}; //convert the 2D to 1D point and get the byte from there. Big Integer takes in a byte buffer not a single byte
										// that is why it is at 
		BigInteger newS = new BigInteger(b); //convert byte buffer to bigInteger
		return addPadding(newS.toString(2), 4); // convert bigInteger to news and return a 4 bit string 
	}
	
	/**
	 * Name: processKey
	 * Purpose: Get 16 sub-keys for DES
	 * Parameters: The key in hex
	 * Return: 16 DES_encrypt sub-keys
	 * Side Effect: nothing
	 * **/
	private static BigInteger[] processKey(String key){
		BigInteger k = permutate(new BigInteger(key, 16), sbox.PC1, 64); // permutate key on PC1
		String k_str = addPadding(k.toString(2), 56); //convert to a binary string and addpadding in from 
		String c_0 = k_str.substring(0, k_str.length()/2); //split into two parts. A left and right 
		String d_0 = k_str.substring(k_str.length()/2, k_str.length());
		BigInteger[] c_arr = new BigInteger[17]; // create and array so it is easier to do rotations on i-1 to generate 
		BigInteger[] d_arr = new BigInteger[17];
		c_arr[0] = new BigInteger(c_0, 2); //add the zero string to c_arr
		d_arr[0] = new BigInteger(d_0, 2);
		for(int i=1; i<17; i++) {
			c_arr[i] = rotateKey(c_arr[i-1], sbox.rotations[i-1]); //rotate base on the sbox rotations array 
			d_arr[i] = rotateKey(d_arr[i-1], sbox.rotations[i-1]); // same with d
		}
		BigInteger[] sub_keys = new BigInteger[16]; //create and array of 16 to where the keys are going to be merge 
		for(int i =1; i<17; i++){
			sub_keys[i-1] = mergeKeys(c_arr[i], d_arr[i], 28);// merge the left and right keys 
		}
		for(int i=0; i< 16; i++){
			sub_keys[i] = permutate(sub_keys[i], sbox.PC2, 56);// permutate each key on PC2
		}
		return sub_keys;
	}
	
	/**
	 * Name: permutate
	 * Purpose: permutate integer on a specific box 
	 * Parameters:the integer, the box you want to permutate on, the length that the bigInteger is in binary 
	 * Return: the new BigInteger that is permutate
	 * Side Effect: Nothing
	 * **/
	private static BigInteger permutate(BigInteger k, int[] pc, int length){
		String bin_k = addPadding(k.toString(2), length); //converts 
		String new_key = ""; //new permutated key
		
		for(int i=0; i< pc.length; i++) {
			new_key += bin_k.charAt(pc[i]-1); //gets the bit at the char Since the pc does not start at 0, we have to subtract 1
		}
		return new BigInteger(new_key, 2); //converts string to BigInteger and returns 
	}
	
	/**
	 * Name: addPadding
	 * Purpose: adds '0' to the front of the BigInteger String until it reaches the length specified
	 * Parameters: String and length 
	 * Return: new String with 0
	 * Side Effect: throws an Exception if the string length is larger than the length specified
	 * **/
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
	
	/**
	 * Name: splitPadding 
	 * Purpose: adds 0's at the end until it reaches the specified length 
	 * Parameters: the string and the length 
	 * Return: the new Big int with 0's in the back
	 * Side Effect: throws an Exception if the string length is larger than the length specified 
	 * **/
	private static BigInteger splitPadding(String str, int length){
		if(str.length()>length){
			throw new IllegalArgumentException(); //DEAD CODE
		}
		while(str.length()<64){
			str+='0';
		}
		return new BigInteger(str,2);
	}
	
	/**
	 * Name: rotateKey
	 * Purpose: It rotates the string with the number of rotations and returns the new BigInteger
	 * Parameters: BigInteger k and the number of rotations
	 * Return: the new rotated BigInteger 
	 * Side Effect:nothing
	 * **/
	private static BigInteger rotateKey(BigInteger k, int r) {
		String key = addPadding(k.toString(2), 28);
		while(r > 0){
			key = key.substring(1, key.length()) + key.charAt(0);
			r--;
		}
		return new BigInteger(key,2);
	}
	
	/**
	 * Name: mergeKeys
	 * Purpose: It merges two BigIntegers Strings together and returns the BigInteger String of it
	 * Parameters: Two Big Ints to merge and the specified length 
	 * Return: return the new BigInts
	 * Side Effect: nothing
	 * **/
	private static BigInteger mergeKeys(BigInteger c, BigInteger d, int length){
		String c_str = addPadding(c.toString(2), length);
		String d_str = addPadding(d.toString(2), length);
		return new BigInteger(c_str+d_str, 2);
	}
	
	/**
	 * Name: splitBlcok
	 * Purpose: splits the block read in into sizes of 64 bits
	 * Parameters: line, length
	 * Return: array of blocks of size 64 
	 * Side Effect: nothing
	 * **/
	private static BigInteger[] splitBlock(BigInteger line, int length) {
		ArrayList<BigInteger> block_list = new ArrayList<BigInteger>(); //do not knw the size of how many blocks there is going to be
		String x = addPadding(line.toString(2), length); // convert line to binary
		if(x.length() < 64){ //if the block is less than 64 than splitpadding 
			block_list.add(splitPadding(x, x.length()));
		}
		else{
			int k = 0; //start at 0
			while(x.length() - k >= 64){
				block_list.add(new BigInteger(x.substring(k, k+64),2)); //add each substring of 64 bits to the block 
				k = k+64; //increase the size of k 
			}
			if(x.length()-k > 0){
				block_list.add(splitPadding(x.substring(k,  x.length()), x.length()-k)); //add padding at the end of the block 
			}	
		}
		block_list.add(splitPadding("",0)); //add a zero block padding to represent a new line
		return block_list.toArray(new BigInteger[block_list.size()]); //return a size of bigIntegers
	}
	/**
	 * Name: genDESkey
	 * Purpose: This prints out a DESKey when the -k option is used
	 * Parameters: nothing
	 * Return: nothing
	 * Side Effect: prints out a key to standard out 
	 * **/
	static void genDESkey(){
		ArrayList<String> weakKeys = new ArrayList<String>();
		weakKeys.add("0101010101010101");
		weakKeys.add("1010101010101010");
		weakKeys.add("0000000000000000");
		weakKeys.add("FFFFFFFFFFFFFFFF");
		weakKeys.add("E0E0E0E0F1F1F1F1");
		weakKeys.add("FEFEFEFEFEFEFEFE");
		weakKeys.add("EFEFEFEFEFEFEFEF");
		weakKeys.add("1F1F1F1F0E0E0E0E");
		weakKeys.add("E1E1E1E1F0F0F0F0");
		weakKeys.add("1E1E1E1E0F0F0F0F");
		weakKeys.add("011F011F010E010E");
		weakKeys.add("1F011F010E010E01");
		weakKeys.add("01E001E001F101F1");
		weakKeys.add("E001E001F101F101");
		weakKeys.add("01FE01FE01FE01FE");
		weakKeys.add("FE01FE01FE01FE01");
		weakKeys.add("1FE01FE00EF10EF1");
		weakKeys.add("E01FE01FF10EF10E");
		weakKeys.add("1FFE1FFE0EFE0EFE");
		weakKeys.add("FE1FFE1FFE0EFE0E");
		weakKeys.add("E0FEE0FEF1FEF1FE");
		weakKeys.add("FEE0FEE0FEF1FEF1");
		byte[] b = new byte[8];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		BigInteger l = new BigInteger(b);
		boolean strong = false;
		while(weakKeys.contains(l.toString(16))){
			r.nextBytes(b);
			l = new BigInteger(b);
		}
		System.out.println(l);
		return;
	}
	
	/**
	 * Name: asciiToHex
	 * Purpose: convert ascii to Hex 
	 * Parameters:String ascii Value
	 * Return: hex string 
	 * Side Effect: nothing
	 * **/
	/*
	 * This function was take from http://howtodoinjava.com/2014/06/05/convert-hex-to-ascii-and-ascii-to-hex/
	 * Explanation:
	 * When we first wrote the encryption, we wrote it when the messages were being passed as hex messages only
	 * So we needed the messages to be in hex only. Since the input was going to be in ascii characters, we can
	 * then map the ascii characters to hex. We didn't know how to do it or if it was even possible  
	 * */
	private static String asciiToHex(String asciiValue)
	{
	    char[] chars = asciiValue.toCharArray();
	    String hex = "";
	    for (int i = 0; i < chars.length; i++)
	    {
	        hex+=Integer.toHexString((int) chars[i]);
	    }
	    return hex;
	}
	
	/**
	 * Name: hexToAscII
	 * Purpose: convert hex to Ascii 
	 * Parameters: String hex String 
	 * Return: ascii string 
	 * Side Effect: nothing
	 * **/
	/*
	 * This function was take from http://howtodoinjava.com/2014/06/05/convert-hex-to-ascii-and-ascii-to-hex/
	 * Explanation: 
	 * 	Same as above
	 * */
	private static String hexToASCII(String hexValue)
	{
	    String output = "";
	    for (int i = 0; i < hexValue.length(); i += 2)
	    {
	        String str = hexValue.substring(i, i + 2);
	        output+= (char) Integer.parseInt(str, 16);
	    }
	    return output;
	}

	/**
	 * This function Processes the Command Line Arguments.
	 * -p for the port number you are using
	 * -h for the host name of system
	 */
	/**
	 * Name: pcl
	 * Purpose: Processes the arguments 
	 * Parameters: args, inputfile, outputfile, keystring, encrypt
	 * Return: nothing
	 * Side Effect:
	 * **/
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
	/**
	 * Name: callUseage
	 * Purpose: Prints the Usage of the Program  
	 * Parameters: exitStatus
	 * Return: Nothing
	 * Side Effect: nothing
	 * **/
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
