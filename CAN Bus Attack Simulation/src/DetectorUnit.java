import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

public class DetectorUnit implements GeneratorUnit.Observer {
	boolean engineOn = false;
	int speed = 0;
	boolean steerRight = false;
	String gear_status = "PARK";
	private long securityCounter; // let's make it a long so that the number rarely wraps around.
	private static KeyPair KEYPAIR_FOR_ENCRYPTION;

	public DetectorUnit() {
		KEYPAIR_FOR_ENCRYPTION = GeneratorUnit.generateKeyPair();
	}

	public static PublicKey getPublicKeyForEncryption() {
		return KEYPAIR_FOR_ENCRYPTION.getPublic();
	}

	private boolean verify(String plainText, String signature, PublicKey publicKey) {
		try {
			Signature publicSignature = Signature.getInstance("SHA256withRSA");
			publicSignature.initVerify(publicKey);
			publicSignature.update(plainText.getBytes(GeneratorUnit.UTF_8));

			byte[] signatureBytes = Base64.getDecoder().decode(signature);
			return publicSignature.verify(signatureBytes);
		} catch (Exception e) {
			// System.out.println("EXCEPTION OCCURED");
			// e.printStackTrace();
		}
		return false;
	}

	private void interpretCANMessage(String canMessage) {
		String CANid = canMessage.substring(0, GeneratorUnit.ENGINE_STATUS.length());
		String CANdata = canMessage.substring(GeneratorUnit.ENGINE_STATUS.length(),
				GeneratorUnit.ENGINE_STATUS.length() + GeneratorUnit.ENGINE_ON.length());
		if (CANid.equals(GeneratorUnit.ENGINE_STATUS)) {
			if (CANdata.equals(GeneratorUnit.ENGINE_ON)) {
				System.out.println("ENGINE TURNED ON");
				engineOn = true;
			} else if (CANdata.equals(GeneratorUnit.ENGINE_OFF)) {
				System.out.println("ENGINE TURNED OFF");
				engineOn = false;
			}
		} else if (engineOn) // We can process CAN messages only if engine is turned on
		{
			if (CANid.equals(GeneratorUnit.ACCELERATION)) {
				if (CANdata.equals(GeneratorUnit.ACCELERATE)) {
					speed += 5;
					System.out.println("SPEED INCREASED TO" + speed);
				} else if (CANdata.equals(GeneratorUnit.DECELERATE)) {
					speed -= 10;
					if (speed < 0) {
						speed = 0;
					}
					System.out.println("SPEED DECREASED TO" + speed);
				} else {
					System.out.println("UNRECOGNIZED CAN DATA");
				}
			} else if (CANid.equals(GeneratorUnit.GEAR_STATUS)) {
				if (CANdata.equals(GeneratorUnit.PARK)) {
					gear_status = "PARK";
					System.out.println("GEAR STATUS SET TO " + gear_status);
				} else if (CANdata.equals(GeneratorUnit.REVERSE)) {
					gear_status = "REVERSE";
					System.out.println("GEAR STATUS SET TO " + gear_status);
				} else if (CANdata.equals(GeneratorUnit.NEUTRAL)) {
					gear_status = "NEUTRAL";
					System.out.println("GEAR STATUS SET TO " + gear_status);
				} else if (CANdata.equals(GeneratorUnit.DRIVE)) {
					gear_status = "DRIVE";
					System.out.println("GEAR STATUS SET TO " + gear_status);
				}
			} else if (CANid.equals(GeneratorUnit.STEERING)) {
				if (speed > 25) {
					System.out.println("PERFORMING TURN AT DANGEROUSLY HIGH SPEED!!!!!");
				}
				if (CANdata.equals(GeneratorUnit.STEER_LEFT)) {
					System.out.println("Steering left");
				} else if (CANdata == GeneratorUnit.STEER_RIGHT) {
					System.out.println("Steering right");
				} else {
					System.out.println("CAN DATA NOT RECOGNIZED");
				}
			}
		} 
		else {
			System.out.println("NOT ABLE TO PERFORM ANY ACTIONS WHEN ENGINE IS NOT ON!");
		}
	}
	
	private long extractSecurityCounterFromCANMessage (String canMessage)
	{
		String CANid = canMessage.substring(0, GeneratorUnit.ENGINE_STATUS.length());
		String CANdata = canMessage.substring(GeneratorUnit.ENGINE_STATUS.length(),
				GeneratorUnit.ENGINE_STATUS.length() + GeneratorUnit.ENGINE_ON.length());
		String substring = canMessage.substring(CANid.length()+CANdata.length(), GeneratorUnit.sizeOfMessageBeforeHash);
		String temp = decrypt (substring, KEYPAIR_FOR_ENCRYPTION.getPrivate());
		return Long.parseLong(temp);
	}
	
	public static String decrypt(String cipherText, PrivateKey privateKey)
	{
		try
		{
	    byte[] bytes = Base64.getDecoder().decode(cipherText);

	    Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

	    return new String(decriptCipher.doFinal(bytes), GeneratorUnit.UTF_8);
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private boolean verifyAndIncrementCounter(String canMessage) 
	{
		boolean ret = false;
		long temp = extractSecurityCounterFromCANMessage (canMessage);
		if (temp == securityCounter)
		{
			ret = true;
		}
		securityCounter++;
		return ret;
	}

	@Override
	public void receiveCANMessage(String canMessage) {
		if (GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_NO_DEFENSE_AGAINST_REPLAY_ATTACKS
				|| GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE) {
			// first verify if this message should be interpreted
			if (verify(GeneratorUnit.getHashDigest(canMessage.substring(0, GeneratorUnit.sizeOfMessageBeforeHash)),
					canMessage.substring(GeneratorUnit.sizeOfMessageBeforeHash),
					GeneratorUnit.getPublicKeyForDigitalSignature())) 
			{
				if (GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE)
				{
					String CANid = canMessage.substring(0, GeneratorUnit.ENGINE_STATUS.length());
					String CANdata = canMessage.substring(GeneratorUnit.ENGINE_STATUS.length(),
							GeneratorUnit.ENGINE_STATUS.length() + GeneratorUnit.ENGINE_ON.length());
					if (CANid.equals(GeneratorUnit.INITIALIZE_SECURITY_COUNTER))
					{
						if (CANdata.equals(GeneratorUnit.SET_SECURITY_COUNTER))
						{
							//Decrypt the counter, and set it.
							securityCounter = extractSecurityCounterFromCANMessage(canMessage);
						}
					}
					if (verifyAndIncrementCounter(canMessage)== false)
					{
						System.out.println("REPLAY ATTACK THWARTED!");
						return;
					}
				}
				interpretCANMessage(canMessage);
			} 
			else 
			{
				System.out.println("HASHES DON'T MATCH! ATTACK THWARTED!");
			}
		} else // proceed without hash checking
		{
			interpretCANMessage(canMessage);
		}
		/**
		 * String test = "dkjk"; String a =
		 * GeneratorUnit.sign(GeneratorUnit.getHashDigest(test),
		 * GeneratorUnit.KEYPAIR.getPrivate()); if ( verify
		 * (GeneratorUnit.getHashDigest(test), a, GeneratorUnit.getPublicKey())) {
		 * System.out.println("YAY"); } else { System.out.print("FAIL"); }
		 */
	}

}
