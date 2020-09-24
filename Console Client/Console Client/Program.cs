// MIT License

// Copyright (c) 2020 Bryce Tuton

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Console_Client {
    class Program {
        private static X509Certificate2 ca;
        private enum Requests : byte { Login = 0x0, NewUser = 0x1 };
        private enum Actions : byte { Close, Message, KeyRequest, MessageRequest };
        private enum ClientMess : byte { Keys, Message };
        private static string us;

        static byte[] Encrypt(string plain, Aes aes) {
            byte[] cipher;
            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream()) {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt)) {
                        //Write all data to the stream.
                        swEncrypt.Write(plain);
                    }
                    cipher = msEncrypt.ToArray();
                }
            }
            return cipher;
        }

        static string Decrypt(byte[] cipher, Aes aes) {
            string plain = null;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipher)) {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plain = srDecrypt.ReadToEnd();
                    }
                }
            }
            return plain;
        }

        static bool AuthenticateStream(SslStream stream, X509Certificate2 clientCert) {
            X509Certificate2[] coll = new X509Certificate2[1];
            coll[0] = clientCert;

            stream.AuthenticateAsClient("server", new X509CertificateCollection(coll), SslProtocols.None, false);

            DisplaySecurityLevel(stream);
            DisplaySecurityServices(stream);
            DisplayCertificateInformation(stream);

            stream.ReadTimeout = 600000;
            stream.WriteTimeout = 600000;
            DisplayStreamProperties(stream);

            return stream.IsEncrypted && stream.IsSigned && !stream.IsServer && stream.CanRead && stream.CanWrite &&
                stream.IsMutuallyAuthenticated && stream.CipherStrength >= 256 && stream.RemoteCertificate.Issuer == ca.Issuer;
        }

        static void DisplaySecurityLevel(SslStream stream) {
            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }

        static void DisplaySecurityServices(SslStream stream) {
            Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
            Console.WriteLine("Is Mutual authenticated: {0}", stream.IsMutuallyAuthenticated);
        }

        static void DisplayStreamProperties(SslStream stream) {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
            if (stream.CanTimeout) {
                Console.WriteLine("Read timeout: {0}", stream.ReadTimeout);
                Console.WriteLine("Write timeout: {0}", stream.WriteTimeout);
            }
        }

        static void DisplayCertificateInformation(SslStream stream) {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null) {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            } else {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null) {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            } else {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        static byte[] ReceiveData(SslStream stream) {
            byte[] size = new byte[sizeof(int)];
            byte[] data;
            try {
                int read = stream.Read(size, 0, size.Length);
                Console.WriteLine("Read {0} bytes from Stream", read);
                data = new byte[BitConverter.ToInt32(size, 0)];
                read = stream.Read(data, 0, data.Length);
                Console.WriteLine("Read {0} bytes from Stream", read);
            } catch {
                Console.WriteLine("Exception Receiving Data");
                throw;
            }
            return data;
        }

        static void SendData(SslStream stream, byte[] data) {
            byte[] size = BitConverter.GetBytes(data.Length);
            try {
                stream.Write(size);
                stream.Write(data);
            } catch {
                Console.WriteLine("Exception Sending Data");
                throw;
            }
        }

        static void SendSignedData(SslStream stream, byte[] data, RSA rsa) {
            byte[] validSignature = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            byte[] dataSig = new byte[data.Length + validSignature.Length];
            data.CopyTo(dataSig, 0);
            validSignature.CopyTo(dataSig, data.Length);
            try {
                byte[] size = new byte[sizeof(int) * 2];
                BitConverter.GetBytes(data.Length).CopyTo(size, 0);
                BitConverter.GetBytes(validSignature.Length).CopyTo(size, sizeof(int));
                stream.Write(size);
                stream.Write(dataSig);
            } catch {
                Console.WriteLine("Exception Sending Data");
                throw;
            }
        }

        static Tuple<byte[], byte[]> ReceiveSignedData(SslStream stream) {
            byte[] size = new byte[sizeof(int) * 2];
            byte[] data;
            byte[] sig;
            try {
                int read = 0;
                while (read != size.Length)
                    read += stream.Read(size, read, size.Length);
                int dataS = BitConverter.ToInt32(size, 0);
                int sigS = BitConverter.ToInt32(size, sizeof(int));
                data = new byte[dataS];
                sig = new byte[sigS];
                byte[] dataSig = new byte[dataS + sigS];
                read ^= read;
                while (read != dataSig.Length)
                    read += stream.Read(dataSig, read, dataSig.Length);
                for (int i = 0; i < dataS; i++)
                    data[i] = dataSig[i];
                for (int i = 0; i < sigS; i++)
                    sig[i] = dataSig[i + dataS];
            } catch {
                Console.WriteLine("Exception Receiving Data");
                throw;
            }
            return new Tuple<byte[], byte[]>(data, sig);
        }

        static async Task<Tuple<byte[], byte[]>> ReceiveSignedDataAsync(SslStream stream) {
            byte[] size = new byte[sizeof(int) * 2];
            byte[] data;
            byte[] sig;
            try {
                int read = 0;
                while (read != size.Length)
                    read += await stream.ReadAsync(size, read, size.Length);
                int dataS = BitConverter.ToInt32(size, 0);
                int sigS = BitConverter.ToInt32(size, sizeof(int));
                data = new byte[dataS];
                sig = new byte[sigS];
                byte[] dataSig = new byte[dataS + sigS];
                read ^= read;
                while (read != dataSig.Length)
                    read += await stream.ReadAsync(dataSig, read, dataSig.Length);
                for (int i = 0; i < dataS; i++)
                    data[i] = dataSig[i];
                for (int i = 0; i < sigS; i++)
                    sig[i] = dataSig[i + dataS];
            } catch {
                Console.WriteLine("Exception Receiving Data");
                throw;
            }
            return new Tuple<byte[], byte[]>(data, sig);
        }

        static byte[] ReceiveAndVerify(SslStream stream, RSA crsa) {
            Tuple<byte[], byte[]> dataSig = ReceiveSignedData(stream);
            if (!crsa.VerifyData(dataSig.Item1, dataSig.Item2, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)) {
                throw new AuthenticationException("Received Data Failed Verification (Data-Signature is Invalid)");
            }
            return dataSig.Item1;
        }

        static async Task<byte[]> ReceiveAndVerifyAsync(SslStream stream, RSA crsa) {
            Tuple<byte[], byte[]> dataSig = await ReceiveSignedDataAsync(stream);
            if (!crsa.VerifyData(dataSig.Item1, dataSig.Item2, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)) {
                throw new AuthenticationException("Received Data Failed Verification (Data-Signature is Invalid)");
            }
            return dataSig.Item1;
        }

        static void EncryptSend(SslStream stream, byte[] data, RSA rsa, Aes aes) {
            string plain = Convert.ToBase64String(data);
            byte[] encrypted = Encrypt(plain, aes);
            SendSignedData(stream, encrypted, rsa);
        }

        static void EncryptSend(SslStream stream, string data, RSA rsa, Aes aes) {
            byte[] encrypted = Encrypt(data, aes);
            SendSignedData(stream, encrypted, rsa);
        }

        static void EncryptSend(SslStream stream, byte[] data, RSA rsa, RSA crsa) {
            byte[] encrypted = crsa.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
            SendSignedData(stream, encrypted, rsa);
        }

        static string ReceiveDecrypt(SslStream stream, RSA crsa, Aes aes) {
            byte[] data;
            try {
                data = ReceiveAndVerify(stream, crsa);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return Decrypt(data, aes);
        }

        static byte[] ReceiveDecrypt(SslStream stream, RSA crsa, RSA rsa) {
            byte[] data;
            try {
                data = ReceiveAndVerify(stream, crsa);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA512);
        }
        static async Task<string> ReceiveDecryptAsync(SslStream stream, RSA crsa, Aes aes) {
            byte[] data;
            try {
                data = await ReceiveAndVerifyAsync(stream, crsa);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return Decrypt(data, aes);
        }

        static async Task<byte[]> ReceiveDecryptAsync(SslStream stream, RSA crsa, RSA rsa) {
            byte[] data;
            try {
                data = await ReceiveAndVerifyAsync(stream, crsa);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA512);
        }

        static X509Certificate2 ExchangeCertificates(SslStream stream, X509Certificate2 serverCert) {
            Console.WriteLine("Certificate Exchange\nReceive Their Certificate");
            byte[] clientCert = ReceiveData(stream);
            Console.WriteLine("Send our Certificate");
            SendData(stream, serverCert.Export(X509ContentType.Cert));
            X509Certificate2 client = new X509Certificate2(clientCert);

            Console.WriteLine("Verify Their Certificate");
            using (X509Chain chain = new X509Chain()) {
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool valid = chain.Build(client);
                Console.WriteLine(valid);
                Console.WriteLine("Chain Status");
                foreach (X509ChainStatus cs in chain.ChainStatus) {
                    Console.WriteLine(cs.Status);
                    Console.WriteLine(cs.StatusInformation);
                    Console.WriteLine();
                }
                if (!valid || client.Issuer != ca.Issuer)
                    throw new AuthenticationException("Client Certificate Invalid");
            }

            return client;
        }

        static RSA CreateUserPassword(SslStream stream, string userName, RSA rsa, RSA crsa, Aes sAes) {
            HashAlgorithm ha = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
            EncryptSend(stream, ha.ComputeHash(Encoding.UTF8.GetBytes(userName)), rsa, sAes);
            Console.Write("Checking if Username Exists... ");
            string exists = ReceiveDecrypt(stream, crsa, sAes);
            while (bool.Parse(exists)) {
                Console.Write("User Exists, Try Another Username: ");
                userName = Console.ReadLine();
                EncryptSend(stream, ha.ComputeHash(Encoding.UTF8.GetBytes(userName)), rsa, sAes);
                exists = ReceiveDecrypt(stream, crsa, sAes);
            }
            Console.Write("Password: ");
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] salt = new byte[1024];
            rng.GetBytes(salt);
            string pass = "";
            ConsoleKeyInfo key = Console.ReadKey();
            while (key.Key != ConsoleKey.Enter) {
                if (key.Key != ConsoleKey.Backspace) {
                    pass += key.KeyChar;
                    Console.Write("\b");
                    Console.Write("*");
                }
                key = Console.ReadKey();
            }
            byte[] passb = Encoding.UTF8.GetBytes(pass);
            byte[] usernameB = Encoding.UTF8.GetBytes(userName);
            byte[] hash = new byte[usernameB.Length + passb.Length + salt.Length];
            usernameB.CopyTo(hash, 0);
            passb.CopyTo(hash, usernameB.Length);
            rng.GetBytes(passb);
            salt.CopyTo(hash, usernameB.Length + passb.Length);
            byte[] hashed = ha.ComputeHash(hash);
            rng.GetBytes(hash);
            Console.WriteLine();
            Console.Write("Generating User... ");
            Aes aes = Aes.Create();
            int largest = int.MinValue;
            foreach (KeySizes ks in aes.LegalKeySizes)
                if (ks.MaxSize > largest)
                    largest = ks.MaxSize;
            aes.KeySize = largest;
            Rfc2898DeriveBytes db = new Rfc2898DeriveBytes(pass, aes.KeySize, 1024, HashAlgorithmName.SHA512);
            pass = Encoding.UTF8.GetString(passb);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = db.GetBytes(32);
            aes.IV = db.GetBytes(16);
            Console.Write("AES Done... ");

            RSA userRSA = RSA.Create(8192);
            byte[] pvk = userRSA.ExportRSAPrivateKey();
            Console.Write("RSA Done... ");
            pvk = Encrypt(Convert.ToBase64String(pvk), aes);
            Console.Write("Private Key Encrypted... ");
            EncryptSend(stream, userRSA.ExportRSAPublicKey(), rsa, sAes);
            Console.Write("Public Key Sent... ");
            EncryptSend(stream, salt, rsa, sAes);
            Console.Write("Salt Sent... ");
            EncryptSend(stream, hashed, rsa, sAes);
            Console.Write("Login Credentials Sent... ");
            EncryptSend(stream, db.Salt, rsa, sAes);
            EncryptSend(stream, pvk, rsa, sAes);
            Console.WriteLine("User Info Sent. Done.");
            db.Dispose();
            return userRSA;
        }

        static RSA LoginUserPassword(SslStream stream, string userName, RSA rsa, RSA crsa, Aes sAes) {
            HashAlgorithm ha = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
            byte[] usernameB = Encoding.UTF8.GetBytes(userName);
            Console.Write("Sending Username... ");
            EncryptSend(stream, ha.ComputeHash(usernameB), rsa, sAes);
            Console.Write("Password: ");
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] salt = Convert.FromBase64String(ReceiveDecrypt(stream, crsa, sAes));
            string pass = "";
            ConsoleKeyInfo key = Console.ReadKey();
            while (key.Key != ConsoleKey.Enter) {
                pass += key.KeyChar;
                Console.Write("\b");
                Console.Write("*");
                key = Console.ReadKey();
            }
            byte[] passb = Encoding.UTF8.GetBytes(pass);
            byte[] hash = new byte[usernameB.Length + passb.Length + salt.Length];
            usernameB.CopyTo(hash, 0);
            passb.CopyTo(hash, usernameB.Length);
            rng.GetBytes(passb);
            salt.CopyTo(hash, usernameB.Length + passb.Length);
            byte[] hashed = ha.ComputeHash(hash);
            rng.GetBytes(hash);
            Console.WriteLine();
            Console.Write("Getting User Ready... ");
            Aes aes = Aes.Create();
            int largest = int.MinValue;
            foreach (KeySizes ks in aes.LegalKeySizes)
                if (ks.MaxSize > largest)
                    largest = ks.MaxSize;
            aes.KeySize = largest;
            Rfc2898DeriveBytes db = new Rfc2898DeriveBytes(pass, aes.KeySize, 1024, HashAlgorithmName.SHA512);
            pass = Encoding.UTF8.GetString(passb);
            Console.Write("Sending Password... ");
            EncryptSend(stream, hashed, rsa, sAes);
            Console.Write("Wait for Server Response... ");
            string result = ReceiveDecrypt(stream, crsa, sAes);
            if (!bool.Parse(result))
                return null;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = db.GetBytes(32);
            aes.IV = db.GetBytes(16);
            Console.Write("AES Done... ");
            return null;
        }

        static void SendDetails(SslStream stream, RSA rsa, RSA userRSA, Aes sAes) {
            byte[] pub = userRSA.ExportRSAPublicKey();
            EncryptSend(stream, pub, rsa, sAes);
            EncryptSend(stream, rsa.SignData(pub, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1), rsa, sAes);
        }

        static RSA CreateUserRSA(SslStream stream, string userName, RSA rsa, RSA crsa, Aes sAes) {
            us = userName;
            string path = AppDomain.CurrentDomain.BaseDirectory + userName + ".pfx";
            HashAlgorithm ha = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
            byte[] ub = Encoding.UTF8.GetBytes(userName);
            Console.Write("Sending Username... ");
            EncryptSend(stream, ha.ComputeHash(ub), rsa, sAes);
            Console.Write("Wait to see if User Exists... ");
            string exists = ReceiveDecrypt(stream, crsa, sAes);
            while (bool.Parse(exists)) {
                Console.Write("User Exists, Try Another Username: ");
                userName = Console.ReadLine();
                path = AppDomain.CurrentDomain.BaseDirectory + userName + ".pfx";
                while (File.Exists(path)) {
                    Console.Write("User Exists on Machine, Try Another Username: ");
                    userName = Console.ReadLine();
                    path = AppDomain.CurrentDomain.BaseDirectory + userName + ".pfx";
                }
                EncryptSend(stream, ha.ComputeHash(Encoding.UTF8.GetBytes(userName)), rsa, sAes);
                exists = ReceiveDecrypt(stream, crsa, sAes);
            }
            Console.Write("Create User RSA... ");
            RSA userRSA = RSA.Create(8192);
            Console.Write("Save Public Key... ");
            string[] pub = new string[2];
            pub[0] = "B64 " + Convert.ToBase64String(userRSA.ExportRSAPublicKey()) + " " + userName;
            pub[1] = "XML " + userRSA.ToXmlString(false) + " " + userName;
            File.WriteAllLines(AppDomain.CurrentDomain.BaseDirectory + userName + ".pub", pub);
            File.Create(AppDomain.CurrentDomain.BaseDirectory + userName + "_known_keys");
            Console.Write("Send Details to Server... ");
            SendDetails(stream, rsa, userRSA, sAes);
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            Console.Write("Enter Key Password: ");
            //StringBuilder sb = new StringBuilder();
            //ConsoleKeyInfo key = Console.ReadKey(true);
            //while (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Escape) {
            //    if (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Escape)
            //        sb.Append(key.KeyChar);
            //    key = Console.ReadKey(true);
            //}
            string pass = Console.ReadLine();//sb.ToString();
            Console.Clear();
            //sb.Clear();
            //sb.Capacity = 0;
            byte[] passb = Encoding.UTF8.GetBytes(pass);
            byte[] encPriv = userRSA.ExportEncryptedPkcs8PrivateKey(passb, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 1024));
            rng.GetBytes(passb);
            pass = Encoding.UTF8.GetString(passb);
            File.WriteAllBytes(path, encPriv);
            Console.WriteLine("Saved Private Key to {0}", path);
            return userRSA;
        }

        static void GetMessages(SslStream stream, RSA crsa, Aes aes, int number, RSA userRSA) {
            Console.WriteLine("Get Waiting Messages");
            List<Tuple<Aes, string>> ciphers = new List<Tuple<Aes, string>>();
            for (int i = 0; i < number; i++) {
                string mess = ReceiveDecrypt(stream, crsa, aes);
                string[] parts = mess.Split('-');

                byte[] type = userRSA.Decrypt(Convert.FromBase64String(parts[0]), RSAEncryptionPadding.OaepSHA512);

                if (type[0] == (byte)ClientMess.Keys) {
                    Console.WriteLine("Keys. Create AES.");
                    Aes oAes = Aes.Create();
                    int largest = int.MinValue;
                    foreach (KeySizes ks in oAes.LegalKeySizes)
                        if (ks.MaxSize > largest)
                            largest = ks.MaxSize;
                    oAes.KeySize = largest;
                    oAes.Mode = CipherMode.CBC;
                    oAes.Padding = PaddingMode.PKCS7;
                    Console.Write("Message is Keys... ");
                    //Console.Write("Verify: ");
                    //List<byte> data = new List<byte>();
                    //foreach (byte b in Convert.FromBase64String(parts[0]))
                    //    data.Add(b);
                    //foreach (byte b in Convert.FromBase64String(parts[1]))
                    //    data.Add(b);
                    //foreach (byte b in Convert.FromBase64String(parts[2]))
                    //    data.Add(b);
                    //foreach (byte b in Convert.FromBase64String(parts[3]))
                    //    data.Add(b);
                    //Console.WriteLine(userRSA.VerifyData(data.ToArray(), Convert.FromBase64String(parts[^1]), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
                    Console.Write("Decrypt Key... ");
                    oAes.Key = userRSA.Decrypt(Convert.FromBase64String(parts[1]), RSAEncryptionPadding.OaepSHA512);
                    Console.Write("Decrypt IV... ");
                    oAes.IV = userRSA.Decrypt(Convert.FromBase64String(parts[2]), RSAEncryptionPadding.OaepSHA512);
                    Console.Write("Decrypt Sender... ");
                    string sender = Decrypt(Convert.FromBase64String(parts[3]), oAes);
                    Console.WriteLine("Key for User {0}", sender);
                    ciphers.Add(new Tuple<Aes, string>(oAes, parts[3]));
                } else if (type[0] == (byte)ClientMess.Message) {
                    foreach (Tuple<Aes, string> cipher in ciphers) {
                        if (cipher.Item2.Equals(parts[^1])) {
                            Console.WriteLine("Message is From: {0}", Decrypt(Convert.FromBase64String(cipher.Item2), cipher.Item1));
                            Console.WriteLine(Decrypt(Convert.FromBase64String(parts[1]), cipher.Item1));
                            break;
                        }
                    }
                }
            }
        }

        static void LoadPrivateKey(RSA userRSA, string path) {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            Console.Write("Enter Key Password: ");
            //StringBuilder sb = new StringBuilder();
            //ConsoleKeyInfo key = Console.ReadKey(true);
            //while (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Escape) {
            //    if (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Escape)
            //        sb.Append(key.KeyChar);
            //    key = Console.ReadKey(true);
            //}
            string pass = Console.ReadLine();//sb.ToString();
            Console.Clear();
            //sb.Clear();
            //sb.Capacity = 0;
            byte[] passb = Encoding.UTF8.GetBytes(pass);
            try {
                userRSA.ImportEncryptedPkcs8PrivateKey(passb, File.ReadAllBytes(path), out _);
            } catch (CryptographicException ce) {
                Console.WriteLine("CryptographicException: {0}", ce.Message);
                Console.WriteLine("Try Again");
                LoadPrivateKey(userRSA, path);
            }
            rng.GetBytes(passb);
            pass = Encoding.UTF8.GetString(passb);
        }

        static RSA LoginUserRSA(SslStream stream, string userName, RSA rsa, RSA crsa, Aes sAes) {
            us = userName;
            string path = AppDomain.CurrentDomain.BaseDirectory + userName + ".pfx";
            HashAlgorithm ha = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
            byte[] ub = Encoding.UTF8.GetBytes(userName);

            Console.Write("Check We Have Login Key... ");
            while (!File.Exists(path)) {
                Console.Write("User Doesn't Exist on Machine, Try Another Username: ");
                userName = Console.ReadLine();
                path = AppDomain.CurrentDomain.BaseDirectory + userName + ".pfx";
            }

            Console.Write("Get User RSA... ");
            RSA userRSA = RSA.Create();
            LoadPrivateKey(userRSA, path);

            Console.Write("Sending Username... ");
            EncryptSend(stream, ha.ComputeHash(ub), rsa, sAes);
            string exists = ReceiveDecrypt(stream, crsa, sAes);
            if (!bool.Parse(exists)) {
                Console.Write("Server Doesn't Have Us. Re-Send Details? ");
                char send = Console.ReadKey().KeyChar;
                Console.WriteLine();
                if (send.Equals('y')) {
                    Console.WriteLine("Sending Details");
                    EncryptSend(stream, true.ToString(), rsa, sAes);
                    SendDetails(stream, rsa, userRSA, sAes);
                } else {
                    EncryptSend(stream, false.ToString(), rsa, sAes);
                    return null;
                }
            }

            Console.WriteLine("Receive Server Challenge");
            byte[] challenge = Convert.FromBase64String(ReceiveDecrypt(stream, crsa, sAes));
            byte[] sig = userRSA.SignData(challenge, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            EncryptSend(stream, sig, rsa, sAes);

            int messages = int.Parse(ReceiveDecrypt(stream, crsa, sAes));
            Console.WriteLine("Messages to Receive: {0}", messages);
            if (messages > 0) {
                GetMessages(stream, crsa, sAes, messages, userRSA);
            }

            return userRSA;
        }

        static async void ReceiveMessagesBackground(SslStream stream, RSA crsa, Aes aes, RSA userRSA) {
            List<Tuple<Aes, string>> ciphers = new List<Tuple<Aes, string>>();
            while (true) {
                byte[] m = Convert.FromBase64String(await ReceiveDecryptAsync(stream, crsa, aes));
                if ((Actions)m[0] == Actions.Message) {
                    string message = await ReceiveDecryptAsync(stream, crsa, aes);
                    string[] contents = message.Split("-");
                    byte[] d = userRSA.Decrypt(Convert.FromBase64String(contents[0]), RSAEncryptionPadding.OaepSHA512);
                    switch ((ClientMess)d[0]) {
                        case ClientMess.Keys:
                            Console.WriteLine("Received Keys. Create AES");
                            Aes oAes = Aes.Create();
                            int largest = int.MinValue;
                            foreach (KeySizes ks in oAes.LegalKeySizes)
                                if (ks.MaxSize > largest)
                                    largest = ks.MaxSize;
                            oAes.KeySize = largest;
                            oAes.Mode = CipherMode.CBC;
                            oAes.Padding = PaddingMode.PKCS7;
                            Console.Write("Decrypt Key... ");
                            oAes.Key = userRSA.Decrypt(Convert.FromBase64String(contents[1]), RSAEncryptionPadding.OaepSHA512);
                            Console.Write("Decrypt IV... ");
                            oAes.IV = userRSA.Decrypt(Convert.FromBase64String(contents[2]), RSAEncryptionPadding.OaepSHA512);
                            Console.Write("Decrypt Sender... ");
                            string sender = Decrypt(Convert.FromBase64String(contents[3]), oAes);
                            Console.WriteLine("Key for User {0}", sender);
                            ciphers.Add(new Tuple<Aes, string>(oAes, contents[3]));
                            break;
                        case ClientMess.Message:
                            Console.WriteLine("Received a Message");
                            foreach (Tuple<Aes, string> cipher in ciphers) {
                                if (cipher.Item2.Equals(contents[^1])) {
                                    Console.WriteLine("From: {0}\n{1}", Decrypt(Convert.FromBase64String(cipher.Item2), cipher.Item1),
                                        Decrypt(Convert.FromBase64String(contents[1]), cipher.Item1));
                                }
                            }
                            break;
                    }
                }
            }
        }

        static void ConnectWithServer(X509Certificate2 cert, RSA rsa, int tries = 0, int max = 2) {
            Console.WriteLine("Creating Client");
            TcpClient client = new TcpClient();
            try {
                Console.WriteLine("Client created, Connecting");
                client.Connect("YOUR SERVER IP/HOSTNAME HERE", 56168); // ----------------------- MUST FILL YOURSELF---------------------

                Console.WriteLine("Connected. Create SSL Stream");
                SslStream stream = new SslStream(client.GetStream(), false);

                Console.WriteLine("Authenticate");
                if (AuthenticateStream(stream, cert)) {
                    //X509Certificate2 server = ExchangeCertificates(stream, cert);
                    Console.WriteLine("Import Public Key to RSA");
                    RSA sRSA = /*server.GetRSAPublicKey()*/RSA.Create();
                    sRSA.ImportRSAPublicKey(stream.RemoteCertificate.GetPublicKey(), out _);

                    Console.WriteLine("Receive Server Challenge");
                    byte[] challenge = ReceiveAndVerify(stream, sRSA);
                    Console.WriteLine("Sign Challenge and send back");
                    byte[] challengeSign = rsa.SignData(challenge, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    SendData(stream, challengeSign);

                    Console.WriteLine("Receive Session Public Key");
                    RSA sessionRSA = RSA.Create();
                    sessionRSA.ImportRSAPublicKey(ReceiveAndVerify(stream, sRSA), out _);

                    Console.WriteLine("Create AES");
                    Aes aes = Aes.Create();
                    int largest = int.MinValue;
                    foreach (KeySizes ks in aes.LegalKeySizes)
                        if (ks.MaxSize > largest)
                            largest = ks.MaxSize;
                    aes.KeySize = largest;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.GenerateKey();
                    aes.GenerateIV();

                    Console.WriteLine("Send AES Key and IV");
                    EncryptSend(stream, aes.Key, rsa, sRSA);
                    EncryptSend(stream, aes.IV, rsa, sRSA);

                    RSA userRSA = null;
                    Console.Clear();
                    Console.Write("Create User or Login? (N or L) ");
                    char r = Console.ReadKey().KeyChar;
                    Console.Clear();
                    byte[] req = new byte[1];
                    string username = null;
                    switch (r) {
                        case 'n':
                            req[0] = (byte)Requests.NewUser;
                            Console.WriteLine("Sending {0} Request", (Requests)req[0]);
                            EncryptSend(stream, req, rsa, aes);
                            Console.Write("Creating New User\nUsername: ");
                            username = Console.ReadLine();
                            userRSA = CreateUserRSA(stream, username, rsa, sRSA, aes);
                            break;
                        case 'l':
                            req[0] = (byte)Requests.Login;
                            Console.WriteLine("Sending {0} Request", (Requests)req[0]);
                            EncryptSend(stream, req, rsa, aes);
                            Console.Write("Login\nUsername: ");
                            username = Console.ReadLine();
                            userRSA = LoginUserRSA(stream, username, rsa, sRSA, aes);
                            break;
                    }

                    ReceiveMessagesBackground(stream, sRSA, aes, userRSA);

                    Console.Write("Send message? ");
                    char yn = Console.ReadKey().KeyChar;
                    Console.WriteLine();
                    if (yn.Equals('y')) {
                        Console.Write("User to send to: ");
                        string user = Console.ReadLine();
                        Console.WriteLine("Check if we Have Their Key");
                        string path = AppDomain.CurrentDomain.BaseDirectory + username;
                        string[] knownKeys = File.ReadAllLines(path + "_known_keys");
                        RSA other = null;
                        foreach (string key in knownKeys) {
                            string[] k = key.Split(" ");
                            if (k[2].Equals(user)) {
                                Console.WriteLine("Found Their Key. Import");
                                other = RSA.Create();
                                if (k[0].Equals("XML"))
                                    other.FromXmlString(k[1]);
                                else if (k[0].Equals("B64"))
                                    other.ImportRSAPublicKey(Convert.FromBase64String(k[1]), out _);
                                else {
                                    Console.WriteLine("Unknown Format");
                                    continue;
                                }
                                break;
                            }
                        }
                        HashAlgorithm ha = HashAlgorithm.Create(HashAlgorithmName.SHA512.Name);
                        byte[] ub = Encoding.UTF8.GetBytes(user);
                        byte[] hb = ha.ComputeHash(ub);
                        if (other == null) {
                            Console.Write("We Don't Know Their Key. Check for Import File? ");
                            if (Console.ReadKey().KeyChar.Equals('y') && File.Exists(AppDomain.CurrentDomain.BaseDirectory + user + ".pub")) {
                                Console.WriteLine();
                                Console.WriteLine("Import File Exists");
                                other = RSA.Create();
                                string[] pubKey = File.ReadAllLines(AppDomain.CurrentDomain.BaseDirectory + user + ".pub");
                                foreach (string key in pubKey) {
                                    string[] k = key.Split(" ");
                                    if (k[2].Equals(user)) {
                                        other = RSA.Create();
                                        if (k[0].Equals("XML"))
                                            other.FromXmlString(k[1]);
                                        else if (k[0].Equals("B64"))
                                            other.ImportRSAPublicKey(Convert.FromBase64String(k[1]), out _);
                                        else {
                                            Console.WriteLine("Unknown Format");
                                            continue;
                                        }
                                        File.AppendAllLines(path + "_known_keys", new string[1] { key });
                                        break;
                                    }
                                }
                                Console.Write("Key Imported. Remove Import File? ");
                                if (Console.ReadKey().KeyChar.Equals('y'))
                                    File.Delete(AppDomain.CurrentDomain.BaseDirectory + user + ".pub");
                                Console.WriteLine();
                            } else {
                                Console.WriteLine();
                                if (!File.Exists(AppDomain.CurrentDomain.BaseDirectory + user + ".pub"))
                                    Console.WriteLine("No Key to Import");
                                Console.WriteLine("Check if Server Has Key");
                            }
                        }
                        if (other == null) {
                            EncryptSend(stream, new byte[1] { (byte)Actions.KeyRequest }, rsa, aes);
                            Console.WriteLine("Request {0} Public Key", Convert.ToBase64String(hb));
                            EncryptSend(stream, Convert.ToBase64String(hb), rsa, aes);
                            Console.WriteLine("Wait to See if Server Knows Our Client");
                            string re = ReceiveDecrypt(stream, sRSA, aes);
                            Console.WriteLine(re);
                            bool known = bool.Parse(re);
                            if (!known) {
                                Console.WriteLine("Server Doesn't Know the Person You're Trying To Send To");
                                Console.WriteLine(Convert.ToBase64String(hb));
                            } else {
                                Console.WriteLine("Recieve Key");
                                byte[] pk = Convert.FromBase64String(ReceiveDecrypt(stream, sRSA, aes));
                                Console.WriteLine("Import the Received Key");
                                other = RSA.Create();
                                other.ImportRSAPublicKey(pk, out _);
                            }
                        }
                        if (other != null) {
                            Console.WriteLine("Generate \"Session\" AES");
                            Aes oAes = Aes.Create();
                            oAes.KeySize = largest;
                            oAes.Mode = CipherMode.CBC;
                            oAes.Padding = PaddingMode.PKCS7;

                            oAes.GenerateKey();
                            oAes.GenerateIV();
                            byte[] usEnc = Encrypt(us, oAes);
                            string usStr = Convert.ToBase64String(usEnc);
                            Console.WriteLine("Send AES Information");
                            EncryptSend(stream, new byte[1] { (byte)Actions.Message }, rsa, aes);
                            EncryptSend(stream, Convert.ToBase64String(hb), rsa, aes);
                            List<byte> data = new List<byte>();
                            byte[] toAdd = other.Encrypt(new byte[1] { (byte)ClientMess.Keys }, RSAEncryptionPadding.OaepSHA512);
                            foreach (byte b in toAdd)
                                data.Add(b);
                            string initKey = Convert.ToBase64String(toAdd);
                            toAdd = other.Encrypt(oAes.Key, RSAEncryptionPadding.OaepSHA512);
                            foreach (byte b in toAdd)
                                data.Add(b);
                            initKey += "-" + Convert.ToBase64String(toAdd);
                            toAdd = other.Encrypt(oAes.IV, RSAEncryptionPadding.OaepSHA512);
                            foreach (byte b in toAdd)
                                data.Add(b);
                            initKey += "-" + Convert.ToBase64String(toAdd);
                            foreach (byte b in usEnc)
                                data.Add(b);
                            initKey += "-" + usStr;
                            //initKey += "-" + Convert.ToBase64String(userRSA.SignData(data.ToArray(), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
                            EncryptSend(stream, initKey, rsa, aes);
                            string message = null;
                            do {
                                Console.Write("Message for {0}: ", user);
                                message = Console.ReadLine();
                                if (message != null) {
                                    EncryptSend(stream, new byte[1] { (byte)Actions.Message }, rsa, aes);
                                    EncryptSend(stream, Convert.ToBase64String(hb), rsa, aes);
                                    Console.WriteLine("Encrypt");
                                    string mess = Convert.ToBase64String(other.Encrypt(new byte[1] { (byte)ClientMess.Message }, RSAEncryptionPadding.OaepSHA512));
                                    mess += "-";
                                    mess += Convert.ToBase64String(Encrypt(message, oAes));
                                    mess += "-" + usStr;
                                    Console.WriteLine("Send");
                                    EncryptSend(stream, mess, rsa, aes);
                                }
                            } while (message != null);
                        }
                    }

                    Console.WriteLine("Done. Inform Server");
                    EncryptSend(stream, new byte[1] { (byte)Actions.Close }, rsa, aes);

                    //byte[] size = new byte[sizeof(int)];
                    //stream.Read(size, 0, sizeof(int));
                    //Console.WriteLine("Data size: {0}", BitConverter.ToInt32(size, 0));
                    //byte[] data = new byte[BitConverter.ToInt32(size, 0)];
                    //stream.Read(data, 0, data.Length);
                    //Console.WriteLine("Certificate Recieved. Verifying");
                    //X509Certificate2 serverCert = new X509Certificate2(data);
                    //if (chain.Build(serverCert)) {
                    //    Console.WriteLine("Valid Certificate\nSend Our Certificate");
                    //    RSA sRSA = RSA.Create();
                    //    sRSA.ImportRSAPublicKey(serverCert.GetPublicKey(), out _);
                    //    stream.Write(BitConverter.GetBytes(cert.Export(X509ContentType.Cert).Length), 0, sizeof(int));
                    //    stream.Write(cert.Export(X509ContentType.Cert), 0, cert.Export(X509ContentType.Cert).Length);
                    //    Console.WriteLine("Server Validated Us\nSign Challenge");
                    //    Console.WriteLine("Receive Data");
                    //    byte[] challenge = ReceiveAndVerify(stream, sRSA);
                    //    Console.WriteLine("Verify Data");
                    //    if (sRSA.VerifyData(challenge, csig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)) {
                    //        Console.WriteLine("Signature Valid");
                    //        Console.WriteLine("Sign Data");
                    //        byte[] signature = rsa.SignData(challenge, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //        Console.WriteLine("Send Signature Back");
                    //        stream.Write(BitConverter.GetBytes(signature.Length), 0, sizeof(int));
                    //        stream.Write(signature, 0, signature.Length);
                    //        Console.WriteLine("Recieve Session Public Key");
                    //        byte[] sessionPK = new byte[1038];
                    //        byte[] sessionPKSig = new byte[1024];
                    //        stream.Read(sessionPK, 0, sessionPK.Length);
                    //        stream.Read(sessionPKSig, 0, sessionPKSig.Length);
                    //        Console.WriteLine("Verify Key");
                    //        bool validSesKey = sRSA.VerifyData(sessionPK, sessionPKSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //        Console.WriteLine(validSesKey);
                    //        if (validSesKey) {
                    //            Console.WriteLine("Session Key Valid");
                    //            Console.WriteLine("Creating AES Class and Key");
                    //            RSA sessionRSASer = RSA.Create();
                    //            sessionRSASer.ImportRSAPublicKey(sessionPK, out _);
                    //            Aes aes = Aes.Create();
                    //            aes.KeySize = 256;
                    //            aes.Mode = CipherMode.CBC;
                    //            aes.Padding = PaddingMode.PKCS7;
                    //            aes.GenerateKey();
                    //            aes.GenerateIV();

                    //            Console.WriteLine("Encrypting AES Key");
                    //            byte[] symKey = sessionRSASer.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA512);
                    //            byte[] symKeyIV = sessionRSASer.Encrypt(aes.IV, RSAEncryptionPadding.OaepSHA512);

                    //            Console.WriteLine("Sending Key");
                    //            stream.Write(BitConverter.GetBytes(symKey.Length), 0, sizeof(int));
                    //            stream.Write(symKey, 0, symKey.Length);
                    //            byte[] sig = rsa.SignData(symKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            stream.Write(BitConverter.GetBytes(symKeyIV.Length), 0, sizeof(int));
                    //            stream.Write(symKeyIV, 0, symKeyIV.Length);
                    //            sig = rsa.SignData(symKeyIV, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            string login = "New User";
                    //            byte[] enc = Encrypt(login, aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            Console.WriteLine("Enter a Username");
                    //            string username = Console.ReadLine();
                    //            enc = Encrypt(username, aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            Console.WriteLine("Enter a Password");
                    //            string pass = Console.ReadLine();
                    //            enc = Encrypt(pass, aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            Console.WriteLine("Recieve Token");
                    //            stream.Read(size, 0, sizeof(int));
                    //            enc = new byte[BitConverter.ToInt32(size, 0)];
                    //            stream.Read(enc, 0, enc.Length);
                    //            stream.Read(size, 0, sizeof(int));
                    //            sig = new byte[BitConverter.ToInt32(size, 0)];
                    //            stream.Read(sig, 0, sig.Length);
                    //            Console.WriteLine(Convert.ToBase64String(enc));
                    //            Console.WriteLine(sRSA.VerifyData(enc, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
                    //            string[] token = new string[2];
                    //            token[0] = Decrypt(enc, aes.Key, aes.IV);
                    //            Console.WriteLine("Token[0]: {0}", Decrypt(enc, aes.Key, aes.IV));
                    //            stream.Read(size, 0, sizeof(int));
                    //            enc = new byte[BitConverter.ToInt32(size, 0)];
                    //            stream.Read(enc, 0, enc.Length);
                    //            stream.Read(size, 0, sizeof(int));
                    //            sig = new byte[BitConverter.ToInt32(size, 0)];
                    //            stream.Read(sig, 0, sig.Length);
                    //            Console.WriteLine(sRSA.VerifyData(enc, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
                    //            token[1] = Decrypt(enc, aes.Key, aes.IV);
                    //            Console.WriteLine("Token[1]: {0}", Decrypt(enc, aes.Key, aes.IV));

                    //            Console.WriteLine("Login");
                    //            enc = Encrypt(username, aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            Console.WriteLine("Send Login Tokens");
                    //            enc = Encrypt(token[0], aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);
                    //            enc = Encrypt(token[1], aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(enc.Length), 0, sizeof(int));
                    //            stream.Write(enc, 0, enc.Length);
                    //            sig = rsa.SignData(enc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(sig.Length), 0, sizeof(int));
                    //            stream.Write(sig, 0, sig.Length);

                    //            Console.WriteLine("Message to Send");
                    //            string message = Console.ReadLine();
                    //            Console.WriteLine("Encrypting");
                    //            byte[] messEnc = Encrypt(message, aes.Key, aes.IV);
                    //            stream.Write(BitConverter.GetBytes(messEnc.Length), 0, sizeof(int));
                    //            stream.Write(messEnc, 0, messEnc.Length);
                    //            byte[] messSig = rsa.SignData(messEnc, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                    //            stream.Write(BitConverter.GetBytes(messSig.Length), 0, sizeof(int));
                    //            stream.Write(messSig, 0, messSig.Length);
                    //            Console.WriteLine("Done. Sent {0} bytes", messEnc.Length + messSig.Length);
                    //        }
                    //    } else {
                    //        Console.WriteLine("Data Signature Invalid");
                    //    }
                    //}
                } else
                    Console.WriteLine("Authentication Failure");
            } catch (Exception e) {
                Console.WriteLine("Exception: {0}", e.Message);
                Console.WriteLine(e.GetType());
                Console.WriteLine(e.StackTrace);
                if (e.InnerException != null) {
                    Console.WriteLine("Inner Exception: {0}", e.InnerException.Message);
                    Exception ie = e.InnerException;
                    while (ie.InnerException != null) {
                        Console.WriteLine("Inner Exception: {0}", ie.InnerException);
                        ie = ie.InnerException;
                    }
                }
                Console.WriteLine(e.StackTrace);
                Console.WriteLine(e.Source);
                Console.WriteLine();
                Console.WriteLine("Retry Communcation with the Server");
                client.Close();
                //if (tries < max)
                //    ConnectWithServer(cert, rsa, tries + 1);
                //else {
                //Console.WriteLine("Too Many Failed Connections, Finishing");
                //}
            }
            Console.WriteLine("Done");
            client.Close();
        }

        static void Main(string[] args) {
            ca = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "ca.crt");
            ca.Verify();
            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "Users"))
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "Users");
            //X509Store store = new X509Store(StoreName.Root);
            //store.Open(OpenFlags.ReadWrite);
            //store.Add(ca);
            Console.WriteLine("Loading Certificate and information");
            X509Certificate2 cert = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "client.pfx", args[0]);
            RSA rsa = cert.GetRSAPrivateKey();

            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            Console.WriteLine(chain.Build(cert));
            Console.WriteLine("Chain Status");
            foreach (X509ChainStatus cs in chain.ChainStatus) {
                Console.WriteLine(cs.Status);
                Console.WriteLine(cs.StatusInformation);
                Console.WriteLine();
            }
            chain.Reset();

            ConnectWithServer(cert, rsa);
        }
    }
}
