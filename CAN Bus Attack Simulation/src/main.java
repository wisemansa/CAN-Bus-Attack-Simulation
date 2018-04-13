import java.util.Random;
import java.util.Scanner;

public class main {

	public static void main(String[] args) 
	{
		// TODO Auto-generated method stub
		GeneratorUnit g = new GeneratorUnit();
		
		Scanner reader = new Scanner(System.in);  // Reading from System.in
		System.out.println("Choose security level:"
				+ "0 for NO_ENCRYPTION"
				+ "1 for ENCRYPTION_NO_DEFENSE_AGAINST_REPLAY_ATTACKS"
				+ "2 ENCRYPTION_WITH_REPLAY_ATTACK_DEFENSE ");
		int n = reader.nextInt(); // Scans the next token of the input as an int.
		if (n != 0 && n!=1 && n!=2)
		{
			System.out.println("INCORRECT INPUT. Terminating program");
			System.exit(-1);
		}
		GeneratorUnit.SECURITY_LEVEL = n;
		System.out.println("Security level has been set");
		//once finished
		reader.close();
		
		
		DetectorUnit d = new DetectorUnit();
		AttackCode a = new AttackCode();
		g.registerObserver(d);
		g.registerObserver(a);
		g.broadcastPresets();
	}

}
