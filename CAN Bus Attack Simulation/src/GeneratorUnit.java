import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.charset.Charset;
import javax.crypto.Cipher;

public class GeneratorUnit {
	public static int NO_ENCRYPTION = 0, ENCRYPTION_NO_DEFENSE_AGAINST_REPLAY_ATTACKS = 1,
			ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE = 2;
	public static int SECURITY_LEVEL = ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE;
	// IDENTIFIERS:
	public static String ENGINE_STATUS = "00000000001";
	public static String ACCELERATION = "00000000002";
	public static String STEERING = "00000000003";
	public static String GEAR_STATUS = "00000000004";
	public static String INITIALIZE_SECURITY_COUNTER = "00000000005";
	// DATA FIELDS
	// Engine parameters:
	public static String ENGINE_OFF = "0001";
	public static String ENGINE_ON = "0002";
	// Acceleration parameters:
	public static String ACCELERATE = "0001";
	public static String DECELERATE = "0002";// (Apply brakes)
	// Steering parameters:
	public static String STEER_RIGHT = "0001";
	public static String STEER_LEFT = "0002";
	// Gear parameters
	public static String PARK = "0001";
	public static String REVERSE = "0002";
	public static String NEUTRAL = "0003";
	public static String DRIVE = "0004";
	// Initialization parameters
	// Set counter
	public static String SET_SECURITY_COUNTER = "0005";

	public static final Charset UTF_8 = Charset.forName("UTF-8");

	private long securityCounter; // let's make it a long so that the number rarely wraps around.

	private static KeyPair KEYPAIR_FOR_DIGITAL_SIGNATURE;

	public static int maxDigitsInLong = 19;
	public static int sizeOfMessageBeforeHash;

	private ArrayList<String> presetList;

	public GeneratorUnit() {
		KEYPAIR_FOR_DIGITAL_SIGNATURE = generateKeyPair();// intialize RSA
		securityCounter = new Random().nextLong() & Long.MAX_VALUE; // Create a random long that is positive
	}

	// Required for signature verification
	public static PublicKey getPublicKeyForDigitalSignature() {
		return KEYPAIR_FOR_DIGITAL_SIGNATURE.getPublic();
	}

	public static KeyPair generateKeyPair() {
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048, new SecureRandom());
			KeyPair pair = generator.generateKeyPair();
			return pair;

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("EXCEPTION OCCURED");
			e.printStackTrace();
		}
		return null;
	}

	private String encrypt(String plainText, PublicKey publicKey) {
		try {
			Cipher encryptCipher = Cipher.getInstance("RSA");
			encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

			byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
			return Base64.getEncoder().encodeToString(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String sign(String plainText, PrivateKey privateKey) {
		try {
			Signature privateSignature = Signature.getInstance("SHA256withRSA");
			privateSignature.initSign(privateKey);
			privateSignature.update(plainText.getBytes(UTF_8));

			byte[] signature = privateSignature.sign();

			return Base64.getEncoder().encodeToString(signature);
		} catch (Exception e) {
			System.out.println("EXCEPTION OCCURED");
			e.printStackTrace();
		}
		return "";
	}

	public static String getHashDigest(String message) {
		MessageDigest messageDigest;
		byte[] messageDigestMD5;
		try {

			messageDigest = MessageDigest.getInstance("MD5");

			messageDigest.update(message.getBytes());

			messageDigestMD5 = messageDigest.digest();

			StringBuffer stringBuffer = new StringBuffer();

			for (byte bytes : messageDigestMD5) {

				stringBuffer.append(String.format("%02x", bytes & 0xff));

			}
			return stringBuffer.toString();

		} catch (NoSuchAlgorithmException exception) {
			System.out.println("EXCEPTION OCCURED");
			exception.printStackTrace();
			// TODO Auto-generated catch block
			return "";
		}

	}

	public String generateCANMessage(String CANID, String CANData) {
		String ret = "";
		ret = ret + CANID; // Identifier
		ret = ret + CANData; // data field
		if (SECURITY_LEVEL == ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE) // add counter (encrypted) to can message
		{
			String numberAsString = Long.toString(securityCounter);
			StringBuilder sb = new StringBuilder();
			while (sb.length() + numberAsString.length() < maxDigitsInLong) {
				sb.append('0');
			}
			sb.append(securityCounter);
			String paddedNumberAsString = sb.toString();
			String encryptedPaddedNumberAsString = encrypt(paddedNumberAsString,
					DetectorUnit.getPublicKeyForEncryption());
			ret = ret + encryptedPaddedNumberAsString;
			securityCounter++;
		}
		sizeOfMessageBeforeHash = ret.length();
		// Hash the message
		String hashedMessage = getHashDigest(ret);
		//
		if (SECURITY_LEVEL == ENCRYPTION_NO_DEFENSE_AGAINST_REPLAY_ATTACKS
				|| SECURITY_LEVEL == ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE)// Encryption is enabled
		{
			String signature = sign(hashedMessage, KEYPAIR_FOR_DIGITAL_SIGNATURE.getPrivate());
			ret = ret + signature;
		}
		// ret = ret + "0001111111";// DEL+ACK+DEL+EOF. Keep these default values for
		// now
		return ret;
	}

	/**
	 * 1. turn on engine 2. Put car into drive 3. Accelerate for 10 seconds to 50
	 * mph. (Let’s consider each acceleration message increases car speed by 5
	 * miles/hr) 4. brake for 3 seconds to slow down to 5mph (each break message
	 * slows car down by 15miles/hr) 5. Turn steering left 6. Turn steering right.
	 * 7. Break for for 3 seconds. 8. Put car into park 9. Turn engine off
	 */
	private ArrayList<String> generateCANPresets() {
		presetList = new ArrayList<String>();
		if (SECURITY_LEVEL == ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE)
		{
			presetList.add(generateCANMessage(INITIALIZE_SECURITY_COUNTER, SET_SECURITY_COUNTER));// set counter variable
		}
		presetList.add(generateCANMessage(ENGINE_STATUS, ENGINE_ON));// Turn engine on.
		presetList.add(generateCANMessage(STEERING, STEER_LEFT));
		presetList.add(generateCANMessage(STEERING, STEER_LEFT));//Let's make a u-turn
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, ACCELERATE));// Accelerate
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(STEERING, STEER_LEFT));
		presetList.add(generateCANMessage(ACCELERATION, STEER_RIGHT));
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(ACCELERATION, DECELERATE));
		presetList.add(generateCANMessage(GEAR_STATUS, PARK));
		presetList.add(generateCANMessage(ENGINE_STATUS, ENGINE_OFF));
		return presetList;
	}

	public void broadcastPresets() {
		generateCANPresets();
		for (int i = 0; i < presetList.size(); i++) 
		{
			notifyObservers(presetList.get(i));
			if (SECURITY_LEVEL == ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE)
			{
				securityCounter++;
			}
		}
	}

	public interface Observer {
		void receiveCANMessage(String canMessage);
	}

	// Can use CopyOnWriteArraySet too
	private final static Set<Observer> mObservers = Collections
			.newSetFromMap(new ConcurrentHashMap<Observer, Boolean>(0));

	/**
	 * This method adds a new Observer - it will be notified when Observable changes
	 */
	public void registerObserver(Observer observer) {
		if (observer == null)
			return;
		mObservers.add(observer); // this is safe due to thread-safe Set
	}

	public static void notifyObservers(String canMessage) {
		for (Observer observer : mObservers) { // this is safe due to thread-safe Set
			observer.receiveCANMessage(canMessage);
		}
	}

	/**
	 * This method removes an Observer - it will no longer be notified when
	 * Observable changes
	 */
	public static void unregisterObserver(Observer observer) {
		if (observer != null) {
			mObservers.remove(observer); // this is safe due to thread-safe Set
		}
		/**
		 * This method notifies currently registered observers about Observable's change
		 */
	}
}