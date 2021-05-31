package org.cryptomator.cracker;

import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MasterkeyFile;
import org.cryptomator.cryptolib.common.Scrypt;

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedTransferQueue;
import java.util.concurrent.TransferQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public class Cracker implements Runnable {

	private static final String POISON = "";
	private static final int CORES = Runtime.getRuntime().availableProcessors();
	private static final TransferQueue<String> PASSWORDS = new LinkedTransferQueue<>();
	private static final ExecutorService EXECUTOR_SERVICE = Executors.newCachedThreadPool();
	private static final AtomicBoolean SUCCESS = new AtomicBoolean(false);

	private final MasterkeyFile mk;

	public Cracker(MasterkeyFile mk) {
		this.mk = mk;
	}

	@Override
	public void run() {
		try {
			String pw;
			while ((pw = PASSWORDS.take()) != POISON) {
				if (tryUnlock(pw)) {
					System.out.println("Success: " + pw);
					SUCCESS.set(true);
				}
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			e.printStackTrace();
		}
	}

	private boolean tryUnlock(String pw) {
		try {
			byte[] kekBytes = Scrypt.scrypt(pw, mk.scryptSalt, mk.scryptCostParam, mk.scryptBlockSize, 32);
			var kek = new SecretKeySpec(kekBytes, "AES");
			AesKeyWrap.unwrap(kek, mk.macMasterKey, "HmacSHA256");
			return true;
		} catch (InvalidKeyException e) {
			return false;
		}
	}

	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("Arg 1 needs to be masterkey file");
			System.exit(2);
		}
		var path = Path.of(args[0]);


		// parse masterkey file and spawn brute force threads:
		try {
			var mk = readMasterkeyFile(path);
			for (int i = 0; i < CORES; i++) {
				EXECUTOR_SERVICE.submit(new Cracker(mk));
			}
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(2);
		}

		// read passwords from STDIN:
		try (var reader = new BufferedReader(new InputStreamReader(System.in))) {
			String pw;
			int n = 0;
			long startTime = System.nanoTime();
			while (!SUCCESS.get() && (pw = reader.readLine()) != null) {
				PASSWORDS.transfer(pw);
				n++;
				if (n % 100 == 0) {
					// progress reporting
					long currentTime = System.nanoTime();
					long elapsedNanos = currentTime - startTime;
					double elapsedSeconds = elapsedNanos / 1_000_000_000.0;
					double guessesPerSecond = n / elapsedSeconds;
					System.out.println("Guesses per second: " + String.format("%3.1f", guessesPerSecond));
				}
			}
			for (int i = 0; i < CORES; i++) {
				PASSWORDS.put(POISON);
			}
			EXECUTOR_SERVICE.shutdown();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(2);
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.exit(3);
		}
	}

	private static MasterkeyFile readMasterkeyFile(Path path) throws IOException {
		try (var in = Files.newInputStream(path, StandardOpenOption.READ);
			 var reader = new InputStreamReader(in)) {
			return MasterkeyFile.read(reader);
		}
	}
}
