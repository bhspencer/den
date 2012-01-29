import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import java.util.UUID;

public class Den {

	private final String xform = "RSA/ECB/PKCS1Padding";
	private String denFolderPath = "~/Dropbox/den"; //TODO doesn't actually get the home folder
	private PublicKey myPublicKey;
	private PrivateKey myPrivateKey;
	private String uuid;
	
	private File lastWrittenFile = null;
	
	public Den() {
		
	}
	
	public void createNewUser() throws NoSuchAlgorithmException, IOException {
		uuid = generateUUID();
		generateKeys();
		generateFolders();
		saveKeys();
	}
	
	private byte[] encrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	private byte[] encrypt(String inputString, PublicKey key) throws Exception {
		return encrypt(inputString.getBytes(), key, this.xform);
	}
	  
	private byte[] decrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}	
	
	private byte[] decrypt(byte[] inpBytes, PrivateKey key) throws Exception {
		return decrypt(inpBytes, key, this.xform);
	}
	
	public void generateKeys() throws NoSuchAlgorithmException {
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	    kpg.initialize(4096); 
	    KeyPair kp = kpg.generateKeyPair();
	    myPublicKey = kp.getPublic();
	    myPrivateKey = kp.getPrivate();
	    System.out.println("Keys generated");
	}
	
	public String generateUUID() {
		return String.valueOf(UUID.randomUUID()) ;
	}
	
	public void generateFolders() {
		File userFolder = new File(getPathToUserFolder(this.uuid));
		userFolder.mkdirs();
		File prefs = new File("~/.den");
		prefs.mkdirs();
	}
	
	public String getPathToUserFolder(String uuid) {
		return denFolderPath + "/" + uuid;
	}
	
	public void saveKeys() throws IOException {
		File publicKeyFile = new File(getPathToUserFolder(this.uuid), "publickey");
		publicKeyFile.createNewFile();
		byte[] publicKeyBytes = myPublicKey.getEncoded();
		writeFile(publicKeyBytes, publicKeyFile.getPath());
		File privateKeyFile = new File("~/.den", "privatekey");
		privateKeyFile.createNewFile();
		byte[] privateKeyBytes = myPrivateKey.getEncoded();
		writeFile(privateKeyBytes, privateKeyFile.getPath());		
	}
	
	public void writeFile(byte[] data, String fileName) throws IOException {
		OutputStream out = new FileOutputStream(fileName);
		try {
			out.write(data);
		} finally {
			out.close();
		}
	}	
	
    public byte[] getBytesFromFile(File file) throws IOException {        
        long length = file.length();
        if (length > Integer.MAX_VALUE) {
            throw new IOException("File is too large!");
        }
        byte[] bytes = new byte[(int)length];
        int offset = 0;
        int numRead = 0;
        InputStream is = new FileInputStream(file);
        try {
            while (offset < bytes.length
                   && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
                offset += numRead;
            }
        } finally {
            is.close();
        }
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
        return bytes;
    }

	
	public void sendMessage(String recipientUUID, String message) throws Exception {
		String messageFileName = generateUUID();
		File desitnationFile = new File(getPathToUserFolder(this.uuid), messageFileName);
		desitnationFile.createNewFile();
		byte[] encryptedBytes = encrypt(message, this.myPublicKey);
		writeFile(encryptedBytes, desitnationFile.getPath());
		lastWrittenFile = desitnationFile;
	}
	
	
	public void listMessages() {
		
	}
	
	public String readMessage(File file) throws Exception {
		byte[] bytes = getBytesFromFile(file);
		byte[] decBytes = decrypt(bytes, myPrivateKey);
		return new String(decBytes);		
	}
	
	public void getPublicKeyForUUID(String recipientUUID) {
		
	}
	
	
	public static void main(String[] args) {
		Den den = new Den();
		try {
			den.createNewUser();
			den.sendMessage(den.uuid, "Hello, drea!");
			System.out.println(den.readMessage(den.lastWrittenFile));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
