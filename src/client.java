/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Scanner;

/**
 *
 * @author Nish
 */
public class client {

    String username;
    String pass;
    int validation_flag = 0;
    Socket sock;// = new Socket("127.0.0.1", 3000);
    BufferedReader keyRead;// = new BufferedReader(new InputStreamReader(System.in));
    OutputStream ostream;//= sock.getOutputStream();
    PrintWriter pwrite;// = new PrintWriter(ostream, true);
    InputStream istream;// = sock.getInputStream();
    BufferedReader receiveRead;// = new BufferedReader(new InputStreamReader(istream));
    String receiveMessage, sendMessage;
    int hash_key;
    String cb_session_key;
    String encrypted;
    String cs_session_key;
    BigInteger e, n,e1,n1;
    BigInteger d1;
    String long_key;
    String msg;
    String productname;
    String encrypted_pass;
    String ecommercename;

    public String private_encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(this.e1, this.n1).toString();
    }

    public void printProductlist(String sCurrentLine) {
        String[] tokens = sCurrentLine.split(",");
        System.out.println("Product,Price(in $)");
        for (int i = 0; i < tokens.length; i++) {
            if (i % 2 != 0) {
                System.out.println(tokens[i]);
            } else {
                System.out.print(tokens[i] + ",");
            }
            // System.out.println(tokens[i]);
        }
    }

    public void getPublickey() throws Exception {
        
        BufferedReader br = new BufferedReader(new FileReader("../client/pub_key_clientside.txt"));
        String sCurrentLine;
        while ((sCurrentLine = br.readLine()) != null) {
        
       
        //sCurrentLine = br.readLine();
        String delims = ","; // so the delimiters are:  + - * / ^ space
        String[] tokens = sCurrentLine.split(delims);

        if(tokens[2].equals(this.ecommercename))
        {
        String encryption_key = tokens[0];
        String num = tokens[1];

        this.e = new BigInteger(encryption_key);
        this.n = new BigInteger(num);
            
        }
        }
    }
public void getPrivatekey() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("../client/client_keys.txt"));
        String sCurrentLine;
        sCurrentLine = br.readLine();
        String delims = ","; // so the delimiters are:  + - * / ^ space
        String[] tokens = sCurrentLine.split(delims);

        String encryption_key = tokens[2];
        String num = tokens[3];

        this.e = new BigInteger(encryption_key);
        this.n = new BigInteger(num);

    }

    public void init_Authentication() throws Exception {
        System.out.println("Enter Username:");
        Scanner s = new Scanner(System.in);

        this.username = s.nextLine();

        System.out.println("Enter password:");
        Scanner s1 = new Scanner(System.in);
        this.pass = s1.nextLine();

        BufferedReader br = new BufferedReader(new FileReader("../client//client_keys.txt"));
        String sCurrentline = "";
        String encrypted_key = "";

        while ((sCurrentline = br.readLine()) != null) {
            String delims = ","; // so the delimiters are:  + - * / ^ space
            String[] tokens = sCurrentline.split(delims);
            for (int i = 0; i < tokens.length; i++) {
                if (i % 2 == 0) {
                    if (tokens[i].equals(this.username)) {
                        //System.out.println(tokens[i+1]);
                        encrypted_key = tokens[i + 1];
                        
                       
        this.e1 = new BigInteger(tokens[i+2]);
        this.n1 = new BigInteger(tokens[i+3]);
                    }
                } else {
                    continue;
                }
                // System.out.println(tokens[i]);
            }
            //System.out.println(encrypted_key);

        }
        if (this.username.equals("") || this.pass.equals("") || encrypted_key.equals("") || this.pass.length() < 8) {
            this.validation_flag = 0;
        } else {
            this.validation_flag = 1;
            encrypt_decrypt myEncryptor = new encrypt_decrypt(this.pass);
            this.long_key = myEncryptor.decrypt(encrypted_key);

            if (this.long_key == null) {
                this.validation_flag = 0;
            } else {
                encrypt_decrypt myEncryptor_1 = new encrypt_decrypt(this.long_key);
                this.encrypted_pass = myEncryptor_1.encrypt(this.pass);

                this.msg = this.username + "," + this.encrypted_pass;
            }

        }

    }

    public boolean connect_to_broker() {
        try {
            this.sock = new Socket("127.0.0.1", 3000);
            this.keyRead = new BufferedReader(new InputStreamReader(System.in));
            this.ostream = sock.getOutputStream();
            this.pwrite = new PrintWriter(ostream, true);
            this.istream = sock.getInputStream();
            this.receiveRead = new BufferedReader(new InputStreamReader(istream));
            return true;
        } catch (Exception e) {
            System.out.println("Connection Failed");
            return false;
        }

    }

    public void generate_hash() throws Exception {
        //Generates hash of password

        this.hash_key = this.pass.hashCode();
    }

    public void send_message(PrintWriter pwrite_in, String msg) {
        pwrite_in.println(msg);
        pwrite_in.flush();
    }

    public String public_encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(this.e, this.n).toString();
    }
   public static byte[] sign_on_message(String msg,PrivateKey pk) throws Exception
    {
        Signature sig = Signature.getInstance("SHA1withRSA");

        //sig.initVerify(pubk); 
        sig.initSign(pk);
        sig.update("Nish".getBytes());

        byte[] sig_message = sig.sign();
        return sig_message;
    }
    public static void main(String[] args) throws Exception {

        client c = new client();

        // First phase login validation
        while (c.validation_flag == 0) {
            c.init_Authentication();
        }

        // Second Phase User Authentication check
        //Connect to Broker
        boolean connection_flag = c.connect_to_broker();

        if (connection_flag) {
            c.send_message(c.pwrite, c.msg);

            if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
            }
            c.generate_hash();
            encrypt_decrypt myEncryptor = new encrypt_decrypt(c.long_key);
            c.cb_session_key = myEncryptor.decrypt(c.receiveMessage);

           // System.out.println(c.cb_session_key);
            encrypt_decrypt myEncryptor_cb = new encrypt_decrypt(c.cb_session_key);

            // Removed temporary
            int web_server_flag = 0;
            while (web_server_flag == 0) {
                System.out.println("Enter eCommerce Website name to browse:");
                c.sendMessage = c.keyRead.readLine();
                //c.sendMessage = "Amazon";

                c.ecommercename = c.sendMessage;
                c.encrypted = myEncryptor_cb.encrypt(c.sendMessage);
                c.send_message(c.pwrite, c.encrypted);

                if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
                    //  encrypt_decrypt myEncryptor2 = new encrypt_decrypt(c.cb_session_key);
                    String decrypted = myEncryptor_cb.decrypt(c.receiveMessage);
                    //System.out.println(decrypted);
                    if (decrypted.equals("Connect Again")) {
                        web_server_flag = 0;
                        System.out.println("Ecommerce Website you have entered is not available right now!!!");
                    } else {
                        web_server_flag = 1;
                    }
                }
            }
            // Generate Session key for Web-server and send it by encrypting with Server's public key
            c.getPublickey();
            SecureRandom random = new SecureRandom();
            BigInteger big = new BigInteger(130, random);
            c.cs_session_key = big.toString();

           // System.out.println("Session key to Web server is :" + c.cs_session_key);
            encrypt_decrypt myEncryptor_cs = new encrypt_decrypt(c.cs_session_key);
            String msg = c.public_encrypt(c.cs_session_key);
            c.encrypted = myEncryptor_cb.encrypt(msg);
            String decrypted = myEncryptor_cb.decrypt(c.encrypted);
           // System.out.println("Encrypted Message:" + c.encrypted);
            // System.out.println("Decrypted Message: " + decrypted);
            c.send_message(c.pwrite, c.encrypted);

            //Receive product list from WEb server
            if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
                //  encrypt_decrypt myEncryptor2 = new encrypt_decrypt(c.cb_session_key);
                decrypted = myEncryptor_cb.decrypt(c.receiveMessage);
                String decrypted1 = myEncryptor_cs.decrypt(decrypted);
                // System.out.println("Product List is:" + decrypted1);
                c.printProductlist(decrypted1);
            }

            System.out.println("Enter Amount of the product you want to buy:");
            int amount_flag = 0;
            while (amount_flag == 0) {
                msg = c.keyRead.readLine();
                if(msg.equals(""));
                try {
                    int n = Integer.parseInt(msg);
                } catch (Exception e) {

                    System.out.println("Enter Amount in numbers only!!!!");
                    continue;
                }
                // System.out.println(msg);
                c.encrypted = myEncryptor_cb.encrypt(msg);
                c.send_message(c.pwrite, c.encrypted);
            //break;

                //Receive order id from WEb broker
                if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
                    //  encrypt_decrypt myEncryptor2 = new encrypt_decrypt(c.cb_session_key);
                    decrypted = myEncryptor_cb.decrypt(c.receiveMessage);
                    if (decrypted.equals("No")) {

                        amount_flag = 0;
                        System.out.println("Enter Correct Amount");
                        continue;

                    } else {
                        String tokens_order[] = decrypted.split(",");
                        System.out.println("Received Order ID is:" + tokens_order[2]);
               // String decrypted1 = myEncryptor_cs.decrypt(decrypted);
                        // System.out.println("Product List is:" + decrypted1);
                        //c.printProductlist(decrypted1);

                                
        
                        
                     //   c.getPrivatekey();
                         String signature = c.private_encrypt(decrypted);
                         c.encrypted = myEncryptor_cb.encrypt(signature);
               // String signature = c.private_encrypt(decrypted);

                //c.encrypted = myEncryptor_cb.encrypt(signature);
                        //c.pwrite.write(msgd.toString());
                        
                        
                        
                        
                        c.send_message(c.pwrite, c.encrypted);
                        amount_flag = 1;
                    }

                }
            }
            //Receive Product from WEb Server
            if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
                //  encrypt_decrypt myEncryptor2 = new encrypt_decrypt(c.cb_session_key);
                decrypted = myEncryptor_cb.decrypt(c.receiveMessage);
                String decrypted1 = myEncryptor_cs.decrypt(decrypted);
                System.out.println("Received Product is:" + decrypted1);
                c.productname = decrypted1;
               // String decrypted1 = myEncryptor_cs.decrypt(decrypted);
                // System.out.println("Product List is:" + decrypted1);
                //c.printProductlist(decrypted1);
                //c.encrypted = myEncryptor_cb.encrypt(decrypted);
                // c.send_message(c.pwrite, c.encrypted);
            }
            
         int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock = null;
    
     // sock = new Socket("127.0.0.1",33335);
      System.out.println("Downloading File...");

      // receive file
            //Receive Product from WEb Server
            if ((c.receiveMessage = c.receiveRead.readLine()) != null) {
                //System.out.println(c.receiveMessage);
                //  encrypt_decrypt myEncryptor2 = new encrypt_decrypt(c.cb_session_key);
                decrypted = myEncryptor_cb.decrypt(c.receiveMessage);
                
               // c.productname = decrypted;
                byte[] decrypt;
                byte[] buf = new byte[1032];
                                File f = new File(decrypted);
                    FileInputStream File_In_Stream = new FileInputStream(f);
                    			FileOutputStream File_Out_Stream = new FileOutputStream("../client/"+c.productname);
                                        
                                                            int n=0;
                                                          //  byte[] buf;
					while((n = File_In_Stream.read(buf)) != -1)
				{
                        
                                    
                                    //if(i==0)System.out.println(Arrays.toString(buf));
                                    decrypt=myEncryptor_cs.decryptBytes(buf);
                                    //System.out.println(Arrays.toString(decrypt));
                                    //decrypt  = buf;
					File_Out_Stream.write(decrypt,0,decrypt.length);
				
				}
				File_Out_Stream.close();
 


            
            
            
            }          


      
      
      
        }
        System.out.println("File Downloaded Successfully...");
    }

}
