// MIT License

// Copyright (c) 2020 Bryce Tuton

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Server {
    class Program {
        private static int port = 56168;
        private static int rsaKeySize = 8192;
        private static X509Certificate2 ca;
        private static bool listen;
        private enum Requests : byte { Login = 0x0, NewUser = 0x1 };
        private enum Actions : byte { Close, Message, KeyRequest, MessageRequest, MessageRetrieve };
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions() {
            WriteIndented = true
        };
        private static List<Tuple<string, SslStream, Aes>> clients = new List<Tuple<string, SslStream, Aes>>();

        /// <summary>
        /// Encryption method
        /// </summary>
        /// <param name="plain">The plain text to encrypt</param>
        /// <param name="aes">The AES Class to encrypt with</param>
        /// <returns>The cipher encrypted cipher text</returns>
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

        /// <summary>
        /// Decryption method
        /// </summary>
        /// <param name="cipher">The cipher text to decrypt</param>
        /// <param name="aes">The AES Class to use for decryption</param>
        /// <returns>The decrypted plain text</returns>
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

        /// <summary>
        /// Add a certificate to the specified certificate store
        /// </summary>
        /// <param name="store">The store to add the certificate to</param>
        /// <param name="cert">The certificate to add to the store</param>
        private static void AddToStore(X509Store store, X509Certificate2 cert) {
            // Check if certificate is already in the store
            // Else add to store.
            X509Certificate2Collection matches = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, true);
            Console.WriteLine("Matching certs in store {0}", matches.Count);
            if (matches == null || matches.Count == 0) {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                store.Open(OpenFlags.ReadOnly);
            } else
                Console.WriteLine("In Store");
        }

        /// <summary>
        /// Removes the certificate from the specified store
        /// </summary>
        /// <param name="store">The certificate to remove</param>
        /// <param name="cert">The store to remove the certificate from</param>
        private static void RemoveFromStore(X509Store store, X509Certificate2 cert) {
            store.Open(OpenFlags.ReadWrite);
            foreach (X509Certificate2 certificate in store.Certificates) {
                if (cert.SubjectName.Name == certificate.SubjectName.Name)
                    store.Remove(certificate);
            }
            store.Open(OpenFlags.ReadOnly);
        }

        /// <summary>
        /// Method to load the Server Certificate, verify it and add it to the Certificate store
        /// </summary>
        /// <param name="path">Certificate storage path</param>
        /// <param name="password">Certificate password</param>
        /// <returns>X509Certificate of the specified certificate</returns>
        static X509Certificate2 LoadServerCert(string path, string password) {
            using (X509Chain chain = new X509Chain()) {
                // Things to check on the Certificate
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                // Load the Server Certificate
                X509Certificate2 cert = new X509Certificate2(path, password);
                Console.WriteLine("Server Certificate");

                Console.WriteLine(cert.Subject);
                Console.WriteLine(cert.Verify());

                // Make sure the Certificate is in the store
                using (X509Store serverStore = new X509Store(StoreName.My)) {
                    serverStore.Open(OpenFlags.ReadOnly);
                    AddToStore(serverStore, cert);
                }

                // Check Certificate Validity
                chain.Reset();
                Console.WriteLine(chain.Build(cert));
                Console.WriteLine(cert.Verify());
                Console.WriteLine("Chain Status");
                foreach (X509ChainStatus cs in chain.ChainStatus) {
                    Console.WriteLine(cs.Status);
                    Console.WriteLine(cs.StatusInformation);
                    Console.WriteLine();
                }
                return cert;
            }
        }

        /// <summary>
        /// Method to remove the server certificate from the store after use
        /// </summary>
        /// <param name="cert">Certificate to unload</param>
        /// <param name="store">Store the certificate was stored in</param>
        static void UnLoadCertificate(X509Certificate2 cert, StoreName store) {
            using (X509Store serverStore = new X509Store(store)) {
                serverStore.Open(OpenFlags.ReadOnly);
                RemoveFromStore(serverStore, cert);
            }
        }

        /// <summary>
        /// Asyncronously listens for messages from the client
        /// </summary>
        /// <param name="client">TCPClient class to be listenting to</param>
        /// <param name="rsa">RSA class used for verification</param>
        static async void ListenToClient(TcpClient client, RSA rsa) {
            NetworkStream stream = client.GetStream();
            byte[] data;

            while (client.Connected) {
                Console.WriteLine("Waiting for a message");
                byte[] ds = new byte[4];
                await stream.ReadAsync(ds, 0, sizeof(int)).ConfigureAwait(true);
                data = new byte[BitConverter.ToInt32(ds, 0)];
                int bytes = await stream.ReadAsync(data, 0, data.Length).ConfigureAwait(true);
                await stream.ReadAsync(ds, 0, sizeof(int)).ConfigureAwait(true);
                byte[] sig = new byte[BitConverter.ToInt32(ds, 0)];
                bytes += await stream.ReadAsync(sig, 0, sig.Length).ConfigureAwait(true);
                if (data.Length == 0) {
                    Console.WriteLine("Receive Triggered But There Was no Data. Stopping");
                    break;
                }
                Console.WriteLine("Received {1} Bytes of Data from {0}, Verifying.", client.Client.RemoteEndPoint, bytes);
                bool dataVerify = rsa.VerifyData(data, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                Console.WriteLine("Data from {0} returned {1}", client.Client.RemoteEndPoint, dataVerify);
                if (dataVerify) {
                    // Save the data and it's signature
                } // Else do nothing
            }
            Console.WriteLine("Client Disconnected. Exit");
        }

        /// <summary>
        /// Send the client a challenge to verify if they have a valid private key for their public key
        /// </summary>
        /// <param name="rsa">RSA Class used for signing (verification)</param>
        /// <param name="crsa">RSA Class for the clients public key</param>
        /// <param name="stream">SSLStream used for sending the data to the client</param>
        /// <param name="bytesToGen">Number of bytes to generate for the client to sign</param>
        /// <returns>True for a valid signature from the client, false otherwise</returns>
        static async Task<bool> ChallengeClient(RSA rsa, RSA crsa, SslStream stream, int bytesToGen) {
            Console.WriteLine("Generate Data to Send and Sign");
            byte[] validation = new byte[bytesToGen];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(validation);

            Console.WriteLine("Send The Data");
            await SendSignedData(stream, validation, rsa).ConfigureAwait(true);

            Console.WriteLine("Receive Client Response");
            byte[] sig = await ReceiveData(stream).ConfigureAwait(true);

            Console.Write("Verify Signature: ");
            bool valid = crsa.VerifyData(validation, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            Console.WriteLine(valid);
            return valid;
        }

        /// <summary>
        /// receive data from the stream
        /// </summary>
        /// <param name="stream">SSLStream to receive data from</param>
        /// <returns>The data received from the stream (Client)</returns>
        static async Task<byte[]> ReceiveData(SslStream stream) {
            byte[] size = new byte[sizeof(int)];
            byte[] data;
            try {
                int read = await stream.ReadAsync(size);
                while (read != size.Length)
                    read += await stream.ReadAsync(size, read, size.Length).ConfigureAwait(true);
                data = new byte[BitConverter.ToInt32(size, 0)];
                read = await stream.ReadAsync(data);
                while (read != data.Length)
                    read += await stream.ReadAsync(data, read, data.Length).ConfigureAwait(true);
            } catch {
                Console.WriteLine("Exception Receiving Data");
                throw;
            }
            return data;
        }

        /// <summary>
        /// Send data to the stream (Client)
        /// </summary>
        /// <param name="stream">SSLStream to send the data on</param>
        /// <param name="data">The Data to send</param>
        static async Task SendData(SslStream stream, byte[] data) {
            byte[] size = BitConverter.GetBytes(data.Length);
            try {
                await stream.WriteAsync(size).ConfigureAwait(true);
                await stream.WriteAsync(data).ConfigureAwait(true);
            } catch {
                Console.WriteLine("Exception Sending Data");
                throw;
            }
        }

        /// <summary>
        /// Signs then sends data to the stream
        /// </summary>
        /// <param name="stream">SSLStream to send data on</param>
        /// <param name="data">The data to sign then send</param>
        /// <param name="rsa">RSA Class used for signing the data</param>
        static async Task SendSignedData(SslStream stream, byte[] data, RSA rsa) {
            byte[] validSignature = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            byte[] dataSig = new byte[data.Length + validSignature.Length];
            data.CopyTo(dataSig, 0);
            validSignature.CopyTo(dataSig, data.Length);
            try {
                byte[] size = new byte[sizeof(int) * 2];
                BitConverter.GetBytes(data.Length).CopyTo(size, 0);
                BitConverter.GetBytes(validSignature.Length).CopyTo(size, sizeof(int));
                await stream.WriteAsync(size).ConfigureAwait(true);
                await stream.WriteAsync(dataSig).ConfigureAwait(true);
            } catch {
                Console.WriteLine("Exception Sending Data");
                throw;
            }
        }

        /// <summary>
        /// receive data from the stream that has been signed
        /// </summary>
        /// <param name="stream">SSLStream to receive data on</param>
        /// <returns>A tuple containing the data (Item1) and the signature (Item2)</returns>
        static async Task<Tuple<byte[], byte[]>> ReceiveSignedData(SslStream stream) {
            byte[] size = new byte[sizeof(int) * 2];
            byte[] data;
            byte[] sig;
            try {
                int read = await stream.ReadAsync(size);
                while (read != size.Length)
                    read += await stream.ReadAsync(size, read, size.Length).ConfigureAwait(true);
                int dataS = BitConverter.ToInt32(size, 0);
                int sigS = BitConverter.ToInt32(size, sizeof(int));
                data = new byte[dataS];
                sig = new byte[sigS];
                byte[] dataSig = new byte[dataS + sigS];
                read = await stream.ReadAsync(dataSig);
                while (read != dataSig.Length)
                    read += await stream.ReadAsync(dataSig, read, dataSig.Length).ConfigureAwait(true);
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

        /// <summary>
        /// Recieve data and verify with the received signature
        /// </summary>
        /// <param name="stream">SSLStream to receive data on</param>
        /// <param name="crsa">RSA Class used for verifying the data-signature</param>
        /// <returns>The data, if valid, throws an exception otherwise</returns>
        static async Task<byte[]> ReceiveAndVerify(SslStream stream, RSA crsa) {
            Tuple<byte[], byte[]> dataSig = await ReceiveSignedData(stream).ConfigureAwait(true);
            if (!crsa.VerifyData(dataSig.Item1, dataSig.Item2, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)) {
                throw new AuthenticationException("Received Data Failed Verification (Data-Signature is Invalid)");
            }
            return dataSig.Item1;
        }

        /// <summary>
        /// Encrypt data, sign it then send it
        /// </summary>
        /// <param name="stream">SSLStream to send the data on</param>
        /// <param name="data">The data (as a byte array) to Encrypt, sign and send</param>
        /// <param name="rsa">RSA Class used for signing</param>
        /// <param name="aes">AES Class used for encryption</param>
        static async Task EncryptSend(SslStream stream, byte[] data, RSA rsa, Aes aes) {
            string plain = Convert.ToBase64String(data);
            byte[] encrypted = Encrypt(plain, aes);
            await SendSignedData(stream, encrypted, rsa).ConfigureAwait(true);
        }

        /// <summary>
        /// Encrypt data, sign it then send it
        /// </summary>
        /// <param name="stream">SSLStream to send the data on</param>
        /// <param name="data">The data (as a string) to Encrypt, sign and send</param>
        /// <param name="rsa">RSA Class used for signing</param>
        /// <param name="aes">AES Class used for encryption</param>
        static async Task EncryptSend(SslStream stream, string data, RSA rsa, Aes aes) {
            byte[] encrypted = Encrypt(data, aes);
            await SendSignedData(stream, encrypted, rsa).ConfigureAwait(true);
        }

        /// <summary>
        /// Encrypt data, sign it then send it
        /// </summary>
        /// <param name="stream">SSLStream to send the data on</param>
        /// <param name="data">The data (as a byte array) to Encrypt (via RSA), sign and send</param>
        /// <param name="rsa">RSA Class used for signing</param>
        /// <param name="crsa">RSA Class used for Encryption</param>
        static async Task EncryptSend(SslStream stream, byte[] data, RSA rsa, RSA crsa) {
            byte[] encrypted = crsa.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
            await SendSignedData(stream, encrypted, rsa).ConfigureAwait(true);
        }

        /// <summary>
        /// Receive data, verify then decrypt
        /// </summary>
        /// <param name="stream">SSLStream to receive the data on</param>
        /// <param name="crsa">RSA Class used for verification</param>
        /// <param name="aes">AES Class used for decryption</param>
        /// <returns>The decrypted data if the data-signature is valid, re-throws exception otherwise</returns>
        static async Task<string> ReceiveDecrypt(SslStream stream, RSA crsa, Aes aes) {
            byte[] data;
            try {
                data = await ReceiveAndVerify(stream, crsa).ConfigureAwait(true);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return Decrypt(data, aes);
        }

        /// <summary>
        /// Receive data, verify then decrypt (using RSA)
        /// </summary>
        /// <param name="stream">SSLStream to receive the data on</param>
        /// <param name="crsa">RSA Class used for verification</param>
        /// <param name="rsa">RSA Class used for decryption</param>
        /// <returns>The decrypted data if the data-signature is valid, re-throws exception otherwise</returns>
        static async Task<byte[]> ReceiveDecrypt(SslStream stream, RSA crsa, RSA rsa) {
            byte[] data;
            try {
                data = await ReceiveAndVerify(stream, crsa).ConfigureAwait(true);
            } catch {
                Console.WriteLine("Exception Receiving Data to Decrypt");
                throw;
            }
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA512);
        }

        /// <summary>
        /// Authenticates SSL Stream
        /// </summary>
        /// <param name="stream">SSLStream to authenticate</param>
        /// <param name="serverCert">Server certificate to use</param>
        /// <returns>True if the stream authenticates successfully</returns>
        static async Task<bool> AuthenticateStream(SslStream stream, X509Certificate2 serverCert) {
            try {
                SslServerAuthenticationOptions sslServerAuthenticationOptions = new SslServerAuthenticationOptions() {
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ClientCertificateRequired = true,
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = SslProtocols.None,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    AllowRenegotiation = true,
                };

                await stream.AuthenticateAsServerAsync(sslServerAuthenticationOptions).ConfigureAwait(true);//serverCert, true, SslProtocols.None, false).ConfigureAwait(true);

                DisplaySecurityLevel(stream);
                DisplaySecurityServices(stream);
                DisplayCertificateInformation(stream);

                stream.ReadTimeout = 600000;
                stream.WriteTimeout = 600000;
                DisplayStreamProperties(stream);

                return stream.IsEncrypted && stream.IsSigned && stream.IsServer && stream.CanRead && stream.CanWrite &&
                    stream.IsMutuallyAuthenticated && stream.CipherStrength >= 256 && stream.RemoteCertificate.Issuer == ca.Issuer;
            } catch (AuthenticationException ae) {
                Console.WriteLine("AuthenticationException: {0}", ae.Message);
                if (ae.InnerException != null)
                    Console.WriteLine("Inner Exception: {0}", ae.InnerException.Message);
                Console.WriteLine("Authentication Failed");
                return false;
            }
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

        /// <summary>
        /// Exchanges certificates with the client.
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="serverCert">Server certificate to use</param>
        /// <returns>Client certificate</returns>
        static async Task<X509Certificate2> ExchangeCertificates(SslStream stream, X509Certificate2 serverCert) {
            Console.WriteLine("Certificate Exchange\nSend our Certificate");
            await SendData(stream, serverCert.Export(X509ContentType.Cert)).ConfigureAwait(true);
            Console.WriteLine("Receive Their Certificate");
            byte[] clientCert = await ReceiveData(stream).ConfigureAwait(true);
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

        /// <summary>
        /// ------------------- Incomplete ---------------------
        /// Creates a new user using password authentication
        /// ------------------- Incomplete ---------------------
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class for signing data</param>
        /// <param name="crsa">RSA Class for verifying data</param>
        /// <param name="aes">AES Class for Encryption/Decryption</param>
        /// <returns></returns>
        static async Task<byte[]> CreateNewUserPassword(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Get Username");
            string username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            // Sanitize the Username a little
            username = username.Replace('\\', '-');
            username = username.Replace('/', '-');

            while (File.Exists(AppDomain.CurrentDomain.BaseDirectory + username)) {
                Console.WriteLine("User Exists");
                await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);
                username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
                username = username.Replace('\\', '-');
                username = username.Replace('/', '-');
            }

            await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
            Console.WriteLine("Receive Their Public Key");

            string[] userInfo = new string[5];
            userInfo[0] = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            Console.WriteLine("Receive User Information");
            userInfo[1] = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            userInfo[2] = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            userInfo[3] = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            userInfo[4] = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);

            Console.WriteLine("Save User Information");
            await File.WriteAllLinesAsync(AppDomain.CurrentDomain.BaseDirectory + username, userInfo).ConfigureAwait(true);
            byte[] userBytes = await File.ReadAllBytesAsync(AppDomain.CurrentDomain.BaseDirectory + username).ConfigureAwait(true);
            byte[] userSig = rsa.SignData(userBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            await File.AppendAllLinesAsync(AppDomain.CurrentDomain.BaseDirectory + username,
                new string[1] { Convert.ToBase64String(userSig) }).ConfigureAwait(true);

            return Convert.FromBase64String(userInfo[0]);
        }

        /// <summary>
        /// ------------------- Not Implemented ---------------------
        /// Process login of a user using password authentication
        /// ------------------- Not Implemented ---------------------
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="rsa"></param>
        /// <param name="crsa"></param>
        /// <param name="aes"></param>
        /// <returns></returns>
        static async Task<byte[]> ProcessLoginPassword(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            return null;
        }

        /// <summary>
        /// Class for storing user information
        /// </summary>
        public class User {
            public byte[] publicKey { get; set; }
            public byte[] certSignature { get; set; }
            public List<string> messages { get; set; } = new List<string>();
        }

        /// <summary>
        /// Receives user information from the client
        /// </summary>
        /// <param name="stream">SSLStream to receive data on</param>
        /// <param name="crsa">RSA Class used for verification</param>
        /// <param name="aes">AES Class used for encryption/decryption</param>
        /// <param name="path">File path to save the user information to</param>
        /// <returns>User class containing their new information</returns>
        static async Task<User> ReceiveDetails(SslStream stream, RSA crsa, Aes aes, string path) {
            User newUser = new User();
            newUser.publicKey = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
            newUser.certSignature = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
            using (FileStream fs = File.Create(path)) {
                await JsonSerializer.SerializeAsync(fs, newUser, JsonSerializerOptions).ConfigureAwait(true);
            }

            return newUser;
        }

        /// <summary>
        /// Creates a new user using RSA as client authentication.
        /// This authentication is used for a client to access a user's information (pending messages).
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class for signing</param>
        /// <param name="crsa">RSA Class for verifying</param>
        /// <param name="aes">AES Class for encryption/decryption</param>
        /// <returns>Username, SSLStream for data transfer and the AES class for encryption/decryption</returns>
        static async Task<Tuple<string, SslStream, Aes>> CreateNewUserRSA(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Get Username");
            string username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            // Sanitize the Username a little
            username = username.Replace('\\', '-');
            username = username.Replace('/', '-');

            string path = AppDomain.CurrentDomain.BaseDirectory + username;
            while (File.Exists(path)) {
                Console.WriteLine("User Exists");
                await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);
                username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
                username = username.Replace('\\', '-');
                username = username.Replace('/', '-');
                path = AppDomain.CurrentDomain.BaseDirectory + username;
            }

            // Inform client that user insn't already known
            await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
            Console.WriteLine("Receive Their Public Key");

            User newUser = await ReceiveDetails(stream, crsa, aes, path).ConfigureAwait(true);
            return new Tuple<string, SslStream, Aes>(username, stream, aes);
        }

        /// <summary>
        /// Handles a user logging in with RSA as the user authentication.
        /// Gets username, then gets the user's data and checks it hasn't been tampered with.
        /// If valid, sends the client a challenge to verify it's actually them.
        /// Finally sends the client their waiting messages.
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class used for signing</param>
        /// <param name="crsa">RSA Class used for verification</param>
        /// <param name="aes">AES Class used for encryption/decryption</param>
        /// <returns>Username, SSLStream for data transfer and the AES class for encryption/decryption</returns>
        static async Task<Tuple<string, SslStream, Aes>> ProcessLoginRSA(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Get Username");
            string username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            Console.WriteLine("Finding Details for {0}", username);
            // Sanitize the Username a little
            username = username.Replace('\\', '-');
            username = username.Replace('/', '-');
            User user = null;

            string path = AppDomain.CurrentDomain.BaseDirectory + username;
            if (!File.Exists(path)) {
                Console.WriteLine("User Doesn't Exist");
                await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
                string resend = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
                if (bool.Parse(resend)) {
                    username = username.Replace('\\', '-');
                    username = username.Replace('/', '-');
                    path = AppDomain.CurrentDomain.BaseDirectory + username;
                    user = await ReceiveDetails(stream, crsa, aes, path).ConfigureAwait(true);
                }
            } else {
                await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);

                using (FileStream fs = File.OpenRead(path)) {
                    user = (User)await JsonSerializer.DeserializeAsync(fs, typeof(User), JsonSerializerOptions);
                }
            }

            Console.WriteLine("Verify Data Hasn't Been Tampered With");
            using (RSA userRSA = RSA.Create()) {
                if (!crsa.VerifyData(user.publicKey, user.certSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                    throw new AuthenticationException("User Public Key-Signature Invalid (Certificate Signature Doesn't Match Key)");

                userRSA.ImportRSAPublicKey(user.publicKey, out _);

                byte[] challenge = new byte[1024];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    rng.GetBytes(challenge);

                await EncryptSend(stream, challenge, rsa, aes).ConfigureAwait(true);

                byte[] sig = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
                if (!userRSA.VerifyData(challenge, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                    throw new AuthenticationException("Client Failed Challenge.");
            }

            // Get then send the user their waiting messages
            await EncryptSend(stream, user.messages.Count.ToString(), rsa, aes).ConfigureAwait(true);
            if (user.messages.Count > 0) {
                foreach (string message in user.messages)
                    await EncryptSend(stream, message, rsa, aes).ConfigureAwait(true);
                user.messages.Clear();
                using (FileStream fs = File.Create(path))
                    await JsonSerializer.SerializeAsync(fs, user, JsonSerializerOptions).ConfigureAwait(true);
            }

            return new Tuple<string, SslStream, Aes>(username, stream, aes);
        }

        /// <summary>
        /// Get's and sends another user's public key to the current user (provided we know it)
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class used for signing</param>
        /// <param name="crsa">RSA Class used for verifying</param>
        /// <param name="aes">AES Class used for Encryption/Decryption</param>
        /// <returns>void</returns>
        static async Task SendKey(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Find and Send Public Key.\nWait to Get User");
            string user = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            Console.WriteLine("Getting {0}'s Public Key", user);
            user = user.Replace('\\', '-');
            user = user.Replace('/', '-');
            string path = AppDomain.CurrentDomain.BaseDirectory + user;
            if (!File.Exists(path)) {
                Console.WriteLine("User Isn't Known to Us");
                await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
                Console.WriteLine("Informed Client, Return");
                return;
            }
            await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);
            User u = null;
            using (FileStream fs = File.OpenRead(path))
                u = (User)await JsonSerializer.DeserializeAsync(fs, typeof(User), JsonSerializerOptions).ConfigureAwait(true);
            Console.WriteLine("Loaded User's details. Send to Client");
            await EncryptSend(stream, u.publicKey, rsa, aes).ConfigureAwait(true);
            Console.WriteLine("Sent Details.");
        }

        /// <summary>
        /// Checks if the user to send to is online, if so it just relays the message directly to that user.
        /// Otherwise the message is saved to the user's file, and message list.
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class for signing</param>
        /// <param name="crsa">RSA Class for verifying</param>
        /// <param name="aes">AES Class for Encryption/Decryption</param>
        /// <returns>void</returns>
        static async Task ReceiveMessageUser(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Receiving Messages Directed to Another User");
            string user = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            user = user.Replace('\\', '-');
            user = user.Replace('/', '-');
            Console.WriteLine("Relaying Messages to {0}", user);
            bool online = false;
            Console.WriteLine("Online Users {0}", clients.Count);
            // Check is the requested user is currently online
            foreach (Tuple<string, SslStream, Aes> client in clients) {
                if (client.Item1.Equals(user)) {
                    online = true;
                    Console.WriteLine("{0} Online, relay directly to them", user);
                    await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);
                    await EncryptSend(client.Item2, new byte[1] { (byte)Actions.Message }, rsa, client.Item3).ConfigureAwait(true);
                    await EncryptSend(client.Item2, await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true), rsa, client.Item3).ConfigureAwait(true);
                    Console.WriteLine("Messaged relayed");
                    break;
                }
            }
            if (!online) {
                string path = AppDomain.CurrentDomain.BaseDirectory + user;
                User u = null;
                Console.WriteLine("Checking User Exists on Server (We have a place to Save Their Messages)");
                if (!File.Exists(path)) {
                    Console.WriteLine("We Don't Have Details for the Specified User");
                    await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
                    Console.WriteLine("Informed Client, Return");
                    return;
                }
                await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);
                Console.WriteLine("User Exists. Load Their Data.");
                using (FileStream fs = File.OpenRead(path))
                    u = (User)await JsonSerializer.DeserializeAsync(fs, typeof(User), JsonSerializerOptions).ConfigureAwait(true);
                Console.WriteLine("Receive The Message to Relay");
                u.messages.Add(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
                Console.WriteLine("Save Their New Data");
                using (FileStream fs = File.Create(path))
                    await JsonSerializer.SerializeAsync(fs, u, typeof(User), JsonSerializerOptions).ConfigureAwait(true);
                Console.WriteLine("Done.");
            }
        }

        /// <summary>
        /// Receieves message from client with what they would like us (the server) to do for them.
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="rsa">RSA Class for signing</param>
        /// <param name="crsa">RSA Class for verifying</param>
        /// <param name="aes">AES Class for Encryption/Decryption</param>
        /// <returns>void</returns>
        static async Task ReceiveMessages(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Receive Messages to relay for User");
            bool clientListen = listen;
            while (clientListen && listen) {
                string action = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
                Actions act = (Actions)Convert.FromBase64String(action)[0];
                Console.Write("Received Message from Client: ");
                Console.WriteLine(act.ToString());
                switch (act) {
                    case Actions.Close: // Client done, close connection
                        clientListen = false;
                        break;
                    case Actions.Message: // Message to send to another user
                        await ReceiveMessageUser(stream, rsa, crsa, aes).ConfigureAwait(true);
                        break;
                    case Actions.KeyRequest: // Request another user's public key
                        await SendKey(stream, rsa, crsa, aes).ConfigureAwait(true);
                        break;
                    case Actions.MessageRetrieve: // User to login and retrieve their messages
                        await ProcessLoginRSA(stream, rsa, crsa, aes).ConfigureAwait(true);
                        break;
                }
            }
            Console.WriteLine("Client is Done.");
        }

        /// <summary>
        /// Handles initial client authentication and setups the session RSA and AES Classes.
        /// Once these are ready, processes whether the client wants to login or create a new user.
        /// </summary>
        /// <param name="stream">SSLStream to send/receive data on</param>
        /// <param name="serverCert">Certificate for the server to use</param>
        /// <returns>void</returns>
        static async Task HandleClient(SslStream stream, X509Certificate2 serverCert) {
            Console.WriteLine("Server Cert Has Private: {0}", serverCert.HasPrivateKey);
            using (RSA rsa = serverCert.GetRSAPrivateKey()) {
                //using (X509Certificate2 client = await ExchangeCertificates(stream, serverCert)) {
                Console.WriteLine("Import Client Public Key...");
                using (RSA crsa = RSA.Create()/*client.GetRSAPublicKey()*/) {
                    crsa.ImportRSAPublicKey(stream.RemoteCertificate.GetPublicKey(), out _);
                    Tuple<string, SslStream, Aes> c = null;
                    try {
                        Console.WriteLine("Challenge Client...");
                        if (await ChallengeClient(rsa, crsa, stream, 256).ConfigureAwait(true)) {
                            Console.WriteLine("Client Challenged. Generate Session RSA...");
                            using (RSA sessionRSA = RSA.Create(rsaKeySize)) {
                                Console.WriteLine("RSA Created. Send to Client...");
                                await SendSignedData(stream, sessionRSA.ExportRSAPublicKey(), rsa).ConfigureAwait(true);
                                Console.WriteLine("RSA Created and Sent. Create AES...");
                                using (Aes aes = Aes.Create()) {
                                    int largest = int.MinValue;
                                    foreach (KeySizes ks in aes.LegalKeySizes)
                                        if (ks.MaxSize > largest)
                                            largest = ks.MaxSize;
                                    aes.KeySize = largest;
                                    aes.Mode = CipherMode.CBC;
                                    aes.Padding = PaddingMode.PKCS7;

                                    aes.Key = await ReceiveDecrypt(stream, crsa, rsa).ConfigureAwait(true);
                                    aes.IV = await ReceiveDecrypt(stream, crsa, rsa).ConfigureAwait(true);

                                    Console.WriteLine("AES Ready. Get Client Request");
                                    byte[] r = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
                                    Console.WriteLine(((Requests)r[0]).ToString());
                                    switch ((Requests)r[0]) {
                                        case Requests.NewUser:
                                            c = await CreateNewUserRSA(stream, rsa, crsa, aes).ConfigureAwait(true);
                                            break;
                                        case Requests.Login:
                                            c = await ProcessLoginRSA(stream, rsa, crsa, aes).ConfigureAwait(true);
                                            break;
                                    }
                                    clients.Add(c);

                                    await ReceiveMessages(stream, rsa, crsa, aes).ConfigureAwait(true);
                                }
                            }
                        } else {
                            Console.WriteLine("Client Failed the Challenge");
                        } // Exception handling, so the whole server doesn't go offline when something goes wrong with a client.
                    } catch (IOException ioe) {
                        Console.WriteLine("IOException: {0}", ioe.Message);
                        Console.WriteLine(ioe.StackTrace);
                        if (ioe.InnerException != null) {
                            Console.WriteLine("Inner Exception: {0}", ioe.InnerException.Message);
                            Console.WriteLine(ioe.InnerException.GetType());
                        }
                    } catch (ArgumentOutOfRangeException are) {
                        Console.WriteLine("ArgumentOutOfRangeException: {0}", are.Message);
                        Console.WriteLine(are.StackTrace);
                        if (are.InnerException != null)
                            Console.WriteLine("Inner Exception: {0}", are.InnerException.Message);
                    } catch (ObjectDisposedException ode) {
                        Console.WriteLine("ObjectDisposedException: {0}", ode.Message);
                        Console.WriteLine(ode.StackTrace);
                        if (ode.InnerException != null)
                            Console.WriteLine("Inner Exception: {0}", ode.InnerException.Message);
                    } catch (AuthenticationException ae) {
                        Console.WriteLine("AuthenticationException: {0}", ae.Message);
                        Console.WriteLine(ae.StackTrace);
                        if (ae.InnerException != null)
                            Console.WriteLine("Inner Exception: {0}", ae.InnerException.Message);
                    } catch (OperationCanceledException oce) {
                        Console.WriteLine("OperationCanceledException: {0}", oce.Message);
                        Console.WriteLine(oce.StackTrace);
                        if (oce.InnerException != null)
                            Console.WriteLine("Inner Exception: {0}", oce.InnerException.Message);
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
                    } finally {
                        if (clients.Contains(c))
                            clients.Remove(c);
                    }
                }
            }
            //}
        }

        /// <summary>
        /// Listens for client connection requests
        /// </summary>
        /// <param name="server">TCPListener to listen for client TCP connection requests</param>
        /// <param name="serverCert">Ceritificate for the server to use</param>
        /// <param name="chain">Certificate chain, used for certificate verification</param>
        static async void ListenForClients(TcpListener server, X509Certificate2 serverCert, X509Chain chain) {
            TcpClient client = null;
            Console.WriteLine("Await Connection");
            try {
                client = await server.AcceptTcpClientAsync().ConfigureAwait(true);
                if (listen) // Start listening again for a new connection if we're still wanting to get new connections
                    ListenForClients(server, serverCert, chain);
            } catch (SocketException se) {
                Console.WriteLine("SocketException Waiting for Client to Connect: {0}", se.Message);
                Console.WriteLine(se.Source);
            } catch (ObjectDisposedException ode) {
                Console.WriteLine("ObjectDisposedException: {0}", ode.Message);
                Console.WriteLine("Exception likely caused by stopping the server while it was listening for a new client. Exiting ListenForClients()");
                return;
            }
            // Once client connects switch to a SSLStream and authenticate it
            Console.WriteLine("Connected {0}", client.Client.RemoteEndPoint);
            SslStream stream = new SslStream(client.GetStream(), false);
            if (await AuthenticateStream(stream, serverCert).ConfigureAwait(true)) {
                await HandleClient(stream, serverCert).ConfigureAwait(true);
            } else
                Console.WriteLine("Client Authenticated but wasn't up to standard");

            Console.WriteLine("Closing Stream and Client");
            stream.Close();
            await stream.DisposeAsync().ConfigureAwait(true);
            client.Close();
        }

        static void DisplayHelp() {
            Console.WriteLine("-p [listen port number]");
            Console.WriteLine("-b [RSA key size in bits]");
            Console.WriteLine("-a [add ca certificate to the certificate store]");
            Console.WriteLine("-r [remove the ca certificate store once done]");
            Console.WriteLine("--password [certificate password]");
        }

        static void Main(string[] args) {
            string certPass = "";
            bool addToStore = false;
            bool removeFromStore = false;
            if (args.Length > 0) { // CLI Commands
                for (int i = 0; i < args.Length; i++) {
                    switch (args[i]) {
                        case "-p":
                            port = int.Parse(args[i + 1]);
                            i++;
                            break;
                        case "-b":
                            rsaKeySize = int.Parse(args[i + 1]);
                            i++;
                            break;
                        case "--password":
                            certPass = args[i + 1];
                            i++;
                            break;
                        case "-a":
                            addToStore = true;
                            break;
                        case "-r":
                            removeFromStore = true;
                            break;
                        case "-h":
                            DisplayHelp();
                            break;
                        default:
                            Console.WriteLine("Unknown command {0}", args[i]);
                            DisplayHelp();
                            return;
                    }
                }
            }
            TcpListener server = new TcpListener(IPAddress.Any, port);

            using (X509Certificate2 serverCert = LoadServerCert(AppDomain.CurrentDomain.BaseDirectory + "server.pfx", certPass)) {
                ca = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "ca.crt");
                listen = true;

                if (addToStore)
                    using (X509Store store = new X509Store(StoreName.Root))
                        AddToStore(store, ca);

                // Check our certificates are all valid, then start server listening
                using (X509Chain chain = new X509Chain()) {
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    Console.WriteLine(chain.Build(ca));
                    Console.WriteLine("Chain Status");
                    foreach (X509ChainStatus cs in chain.ChainStatus) {
                        Console.WriteLine(cs.Status);
                        Console.WriteLine(cs.StatusInformation);
                        Console.WriteLine();
                    }
                    chain.Reset();

                    Console.WriteLine("CA verify");
                    Console.WriteLine(ca.Verify());

                    chain.Reset();

                    Console.WriteLine("Server Verify");
                    Console.WriteLine(chain.Build(serverCert));
                    chain.Reset();

                    Console.WriteLine("Server Started, Waiting Connection");
                    server.Start();

                    ListenForClients(server, serverCert, chain);
                    Console.WriteLine("Press a Key to Stop");
                    Console.ReadKey();
                    listen = false;
                    Console.WriteLine("Creating a local \"Client\" to connect and stop the server listening gracefully");
                    TcpClient stopper = new TcpClient();
                    stopper.Connect("127.0.0.1", port);
                    SslStream sslStop = new SslStream(stopper.GetStream(), false);
                    sslStop.AuthenticateAsClient("server");
                    sslStop.Dispose();
                    stopper.Close();
                    server.Stop();
                    if (removeFromStore)
                        using (X509Store store = new X509Store(StoreName.Root))
                            RemoveFromStore(store, ca);

                    using (X509Store serverStore = new X509Store(StoreName.My))
                        RemoveFromStore(serverStore, serverCert);

                    ca.Dispose();
                }
            }
        }
    }
}
