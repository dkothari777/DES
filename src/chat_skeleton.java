import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

public class chat_skeleton {
	static String host;
	static int port;
	static Socket s;
	static String username;
	
	static String privateKeyAlice;
	static String privateKeyBob;
	static String publicKeyAlice;
	static String publicKeyBob;
	static String aliceModulus;
	static String bobModulus;


	
	
	public static void main(String[] args) throws IOException {

		
		@SuppressWarnings("resource")
		Scanner keyboard = new Scanner(System.in);
//		Process command line arguments
		pcl(args);
						
//		set up server, or join server
		setupServer();

//		Set up username
		System.out.println("Welcome to (soon to be) encrypted chat program.\nChat starting below:");

//		Make thread to print out incoming messages...
		ChatListenter chatListener = new ChatListenter();
		chatListener.start();

//		loop through sending and receiving messages
		PrintStream output = null;
		try {
			output = new PrintStream(s.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
		} 
		String input = "";
		while(true){
			
			input = keyboard.nextLine();
			input = username + ": " + input;

			output.println(input);
			output.flush();	
		}
	}



	/**
	 * Upon running this function it first tries to make a connection on 
	 * the given ip:port pairing. If it find another client, it will accept
	 * and leave function. 
	 * If there is no client found then it becomes the listener and waits for
	 * a new client to join on that ip:port pairing. 
	*/
	private static void setupServer() {
		try {
			// This line will catch if there isn't a waiting port
			s = new Socket(host, port);
			
		} catch (IOException e1) {
			System.out.println("There is no other client on this IP:port pairing, waiting for them to join.");
			
			try {
				ServerSocket listener = new ServerSocket(port);
				s = listener.accept();
				listener.close();
				
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(1);
			}

		}
		System.out.println("Client Connected.");

	}

	/**
	 * This function Processes the Command Line Arguments.
	 * Right now the three accepted Arguments are:
	 * -p for the port number you are using
	 * -i for the IP address/host name of system
	 * -h for calling the usage statement.
	 */
	private static void pcl(String[] args) {
		/*
		 * http://www.urbanophile.com/arenn/hacking/getopt/gnu.getopt.Getopt.html
		*/
		LongOpt[] longopts = new LongOpt[2];
		longopts[0] = new LongOpt("alice", LongOpt.NO_ARGUMENT, null, 1);
		longopts[1] = new LongOpt("bob", LongOpt.NO_ARGUMENT, null, 2);
		Getopt g = new Getopt("Chat Program", args, "p:i:a:b:m:n:", longopts);
		int c;
		String arg;
		while ((c = g.getopt()) != -1){
		     switch(c){
		     	  case 1:
		     		  username = "alice";
		     		  break;
		     	  case 2:
		     		  username = "bob";
		     		  break;
		          case 'p':
		        	  arg = g.getOptarg();
		        	  port = Integer.parseInt(arg);
		        	  break;
		          case 'i':
		        	  arg = g.getOptarg();
		        	  host = arg;
		        	  break;
		          case 'a':
		        	  arg = g.getOptarg();
		        	  privateKeyAlice = arg;
		        	  break;
		          case 'm':
		        	  arg = g.getOptarg();
		        	  aliceModulus = arg;
		        	  break;
		          case 'b':
		        	  arg = g.getOptarg();
		        	  publicKeyBob = arg;
		        	  break;
		          case 'n':
		        	  arg = g.getOptarg();
		        	  bobModulus = arg;
		        	  break;
		          case 'h':
		        	  callUsage(0);
		          case '?':
		            break; // getopt() already printed an error
		            //
		          default:
		              break;
		       }
		   }
	}

	/**
	 * A helper function that prints out the useage help statement
	 * and exits with the given exitStatus
	 * @param exitStatus
	 */
	private static void callUsage(int exitStatus) {
		
		String useage = "";
		
		System.err.println(useage);
		System.exit(exitStatus);
		
	}

	/**
	 * A private class which runs as a thread listening to the other 
	 * client. It prints out the message on screen.
	 */
	static private class ChatListenter implements Runnable {
		private Thread t;
		ChatListenter(){
		}
		
		@Override
		public void run() {
			BufferedReader input = null;
			try {
				input = new BufferedReader(new InputStreamReader(s.getInputStream()));
			} catch (IOException e1) {
				e1.printStackTrace();
				System.err.println("System would not make buffer reader");
				System.exit(1);
			}
			String inputStr;
			while(true){
				try {
//					Read lines off the scanner
					inputStr = input.readLine();
					System.out.println(inputStr);
					
					if(inputStr == null){
						System.err.println("The other user has disconnected, closing program...");
						System.exit(1);
					}
					
				} catch (IOException e) {
					e.printStackTrace();
					System.exit(1);
				}
			}
		}
		   
		public void start(){
			if (t == null){
				t = new Thread(this);
				t.start();
			}
		}
	}
}
