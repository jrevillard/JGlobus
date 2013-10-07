/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.tools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PasswordException;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.globus.common.CoGProperties;
import org.globus.common.Version;
import org.globus.gsi.util.CertificateLoadUtil;
import org.globus.gsi.util.CertificateUtil;
import org.globus.util.Util;

/**
 * Changes the Passphrase.
 * 
 * <pre>
 * Syntax: java ChangePassPhrase [-help] [-version] [-file private_key_file]
 * Changes the passphrase that protects the private key. If the -file
 * argument is not given, the default location of the file containing
 * the private key is assumed:
 *   --  Config.getUserKeyFile() 
 * Options
 *   -help, -usage                Display usage
 *   -version                     Display version
 *   -file location               Change passphrase on key stored in the 
 *                                file at the non-standard 
 *                                location 'location';
 * </pre>
 */
public class ChangePassPhrase {

	private static String message = "\n"
			+ "Syntax: java ChangePassPhrase [-help] [-version] [-file private_key_file]\n\n"
			+ "\tChanges the passphrase that protects the private key. If the\n"
			+ "\t-file argument is not given, the default location of the file\n"
			+ "\tcontaining the private key is assumed:\n\n" + "\t  -- " + CoGProperties.getDefault().getUserKeyFile()
			+ "\n\n" + "\tOptions\n" + "\t-help | -usage\n" + "\t\tDisplay usage.\n" + "\t-version\n"
			+ "\t\tDisplay version.\n" + "\t-file location\n" + "\t\tChange passphrase on key stored in the file at\n"
			+ "\t\tthe non-standard location 'location'.\n\n";

	public static void main(String args[]) {

		String file = null;
		boolean error = false;
		boolean debug = false;

		for (int i = 0; i < args.length; i++) {
			if (args[i].equalsIgnoreCase("-file")) {
				file = args[++i];
			} else if (args[i].equalsIgnoreCase("-version")) {
				System.err.println(Version.getVersion());
				System.exit(1);
			} else if (args[i].equalsIgnoreCase("-debug")) {
				debug = true;
			} else if (args[i].equalsIgnoreCase("-help") || args[i].equalsIgnoreCase("-usage")) {
				System.err.println(message);
				System.exit(1);
			} else {
				System.err.println("Error: argument not recognized : " + args[i]);
				error = true;
			}
		}

		if (error) {
			System.err.println("\nUsage: java ChangePassPhrase [-help] [-version] [-file private_key_file]\n");
			System.err.println("Use -help to display full usage.");
			System.exit(1);
		}

		CertificateUtil.init();

		if (file == null) {
			file = CoGProperties.getDefault().getUserKeyFile();
		}

		PrivateKey key = null;
		String pwd1, pwd2 = null;

		try {
			try {
				key = CertificateLoadUtil.loadPrivateKey(file, null);
			} catch (PasswordException e) {
				pwd1 = Util.getPrivateInput("Enter OLD pass phrase: ");
				if (pwd1 == null || pwd1.length() == 0)
					return;
				try {
					key = CertificateLoadUtil.loadPrivateKey(file, null);
				} catch (Exception e1) {
					System.err.println("Error: Wrong pass phrase or key is invalid.");
					if (debug) {
						e1.printStackTrace();
					}
					System.exit(1);
				}
			}

			pwd1 = Util.getPrivateInput("Enter NEW pass phrase: ");
			if (pwd1 == null || pwd1.length() == 0)
				return;

			pwd2 = Util.getPrivateInput("Verifying password - Enter NEW pass phrase: ");
			if (pwd2 == null || pwd2.length() == 0)
				return;

			if (!pwd1.equals(pwd2)) {
				System.err.println("Error: Passwords do not match!");
				System.exit(1);
			}

			PemObjectGenerator pemObjectGenerator;
			if ("PKCS#8".equals(key.getFormat())) {
				pemObjectGenerator = new JcaPKCS8Generator(key,new JceOpenSSLPKCS8EncryptorBuilder(PKCSObjectIdentifiers.sha1WithRSAEncryption).setPasssword(pwd1.toCharArray()).build());
			} else {
				pemObjectGenerator = new MiscPEMGenerator(key, new JcePEMEncryptorBuilder("DES-EDE3-CBC").build(pwd1.toCharArray()));
			}

			File newFile = Util.createFile(file + ".new");
			Util.setOwnerAccessOnly(newFile.getAbsolutePath());
			File oldFile = Util.createFile(file + ".old");
			Util.setOwnerAccessOnly(oldFile.getAbsolutePath());
			File crFile = Util.createFile(file);
			Util.setOwnerAccessOnly(crFile.getAbsolutePath());

			copy(crFile, oldFile);

			PemWriter pemWriter = null;
			try {
				pemWriter = new PemWriter(new FileWriter(newFile));
				pemWriter.writeObject(pemObjectGenerator);
			}catch(IOException io){
				System.err.println("Error: Unable to write the new generated private key in " +newFile+ ": " + io.getMessage());
				System.exit(1);
			} finally {
				if (pemWriter != null) {
					try {
						pemWriter.close();
					} catch (IOException e) {}
				}
			}

			if (!crFile.delete()) {
				System.err.println("Error: failed to remove " + file + " file.");
				System.exit(1);
			}

			if (newFile.renameTo(crFile)) {
				System.out.println("Pass phrase successfully changed.");
			} else {
				System.err.println("Error: failed to rename the files.");
				System.exit(1);
			}

		} catch (GeneralSecurityException e) {
			System.err.println("Error: " + e.getMessage());
			System.exit(1);
		} catch (Exception e) {
			System.err.println("Unable to load the private key : " + e.getMessage());
			System.exit(1);
		}

	}

	private static void copy(File srcFile, File dstFile) throws IOException {

		InputStream in = null;
		OutputStream out = null;
		byte[] buffer = new byte[1024];
		int bytes = 0;

		try {
			in = new FileInputStream(srcFile);
			out = new FileOutputStream(dstFile);

			Util.setOwnerAccessOnly(dstFile.getAbsolutePath());

			while ((bytes = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytes);
				out.flush();
			}

		} finally {
			try {
				if (in != null)
					in.close();
				if (out != null)
					out.close();
			} catch (Exception e) {}
		}
	}

}