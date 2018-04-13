import java.util.ArrayList;

public class AttackCode implements GeneratorUnit.Observer 
{
	ArrayList<String> listOfReceivedCanMessages;
	private int speed = 0;

	
	public AttackCode() 
	{
		listOfReceivedCanMessages = new ArrayList<String>();
	}

	@Override
	public void receiveCANMessage(String canMessage) {
		listOfReceivedCanMessages.add(canMessage);// Used for replay attacks!
		String CANid = canMessage.substring(0, GeneratorUnit.ENGINE_STATUS.length());
		String CANdata = canMessage.substring(GeneratorUnit.ENGINE_STATUS.length(),
				GeneratorUnit.ENGINE_STATUS.length() + GeneratorUnit.ENGINE_ON.length());
		// TODO Auto-generated method stub
		if (CANid.equals(GeneratorUnit.ACCELERATION)) {
			if (CANdata.equals(GeneratorUnit.ACCELERATE)) {
				speed += 5;
			}
		}
		// Let's do something bad when the car is moving fast at 45 mph!!!
		if (speed == 45) 
		{
			if (GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_NO_DEFENSE_AGAINST_REPLAY_ATTACKS)
			{
				attackWithoutEncryption();
			}
			else if (GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE 
					|| GeneratorUnit.SECURITY_LEVEL == GeneratorUnit.ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE)
			{
				performReplayAttack();
			}
		}
	}

	private void attackWithoutEncryption() 
	{
		GeneratorUnit.unregisterObserver(this);// Don't want to go into an infinite loop
		System.out.println("PERFORMING ATTACK WITHOUT ENCRYPTION");
		// Let's be really evil and turn off the engine!!!
		GeneratorUnit.notifyObservers(GeneratorUnit.ENGINE_STATUS + GeneratorUnit.ENGINE_OFF);
	}

	private void performReplayAttack() 
	{
		GeneratorUnit.unregisterObserver(this);// Don't want to go into an infinite loop
		System.out.println("PERFORMING REPLAY ATTACK");
		GeneratorUnit.notifyObservers(listOfReceivedCanMessages.get(2));// Let's see what havoc this does :)
	}
}
