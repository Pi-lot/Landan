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
using System.Threading.Tasks;

namespace Server {
    class Program {
        private static X509Certificate2 ca;
        private static bool listen;
        private enum Requests : byte { Login = 0x0, NewUser = 0x1 };
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions() {
            WriteIndented = true
        };

        public class User {
            public byte[] publicKey { get; set; }
            public byte[] selfSignature { get; set; }
            public byte[] certSignature { get; set; }
        }

        private static void AddToStore(X509Store store, X509Certificate2 cert) {
            X509Certificate2Collection matches = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, true);
            Console.WriteLine("Matching certs in store {0}", matches.Count);
            if (matches == null || matches.Count == 0) {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                store.Open(OpenFlags.ReadOnly);
            } else
                Console.WriteLine("In Store");
        }

        private static void RemoveFromStore(X509Store store, X509Certificate2 cert) {
            store.Open(OpenFlags.ReadWrite);
            store.Remove(cert);
            foreach (X509Certificate2 certificate in store.Certificates) {
                if (cert.SubjectName.Name == certificate.SubjectName.Name)
                    store.Remove(certificate);
            }
            store.Open(OpenFlags.ReadOnly);
        }

        static X509Certificate2 LoadServerCert(string path, string password) {
            using (X509Chain chain = new X509Chain()) {
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                X509Certificate2 cert = new X509Certificate2(path, password);
                Console.WriteLine("Server Certificate");

                Console.WriteLine(cert.Subject);
                Console.WriteLine(cert.Verify());

                using (X509Store serverStore = new X509Store(StoreName.My)) {
                    serverStore.Open(OpenFlags.ReadOnly);
                    AddToStore(serverStore, cert);
                }

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

        static void UnLoadCertificate(X509Certificate2 cert, StoreName store) {
            using (X509Store serverStore = new X509Store(store)) {
                serverStore.Open(OpenFlags.ReadOnly);
                RemoveFromStore(serverStore, cert);
            }
        }

        static async Task<bool> AuthenticateStream(SslStream stream, X509Certificate2 serverCert) {
            try {
                await stream.AuthenticateAsServerAsync(serverCert, true, SslProtocols.None, false).ConfigureAwait(true);

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

        static async Task<byte[]> ReceiveData(SslStream stream) {
            byte[] size = new byte[sizeof(int)];
            byte[] data;
            try {
                int read = await stream.ReadAsync(size);
                while (read != size.Length)
                    read += await stream.ReadAsync(size, read, size.Length).ConfigureAwait(true);
                Console.WriteLine("Read {0} bytes from Stream", read);
                data = new byte[BitConverter.ToInt32(size, 0)];
                read = await stream.ReadAsync(data);
                while (read != data.Length)
                    read += await stream.ReadAsync(data, read, data.Length).ConfigureAwait(true);
                Console.WriteLine("Read {0} bytes from Stream", read);
            } catch {
                Console.WriteLine("Exception Receiving Data");
                throw;
            }
            return data;
        }

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

        static async Task<Tuple<byte[], byte[]>> ReceiveSignedData(SslStream stream) {
            byte[] size = new byte[sizeof(int) * 2];
            byte[] data;
            byte[] sig;
            try {
                int read = await stream.ReadAsync(size);
                while (read != size.Length)
                    read += await stream.ReadAsync(size, read, size.Length).ConfigureAwait(true);
                Console.WriteLine("Read {0} bytes from Stream", read);
                int dataS = BitConverter.ToInt32(size, 0);
                int sigS = BitConverter.ToInt32(size, sizeof(int));
                data = new byte[dataS];
                sig = new byte[sigS];
                byte[] dataSig = new byte[dataS + sigS];
                read = await stream.ReadAsync(dataSig);
                while (read != dataSig.Length)
                    read += await stream.ReadAsync(dataSig, read, dataSig.Length).ConfigureAwait(true);
                Console.WriteLine("Read {0} bytes from Stream", read);
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

        static async Task<byte[]> ReceiveAndVerify(SslStream stream, RSA crsa) {
            Tuple<byte[], byte[]> dataSig = await ReceiveSignedData(stream).ConfigureAwait(true);
            if (!crsa.VerifyData(dataSig.Item1, dataSig.Item2, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)) {
                throw new AuthenticationException("Received Data Failed Verification (Data-Signature is Invalid)");
            }
            return dataSig.Item1;
        }

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

        static async Task EncryptSend(SslStream stream, string data, RSA rsa, Aes aes) {
            byte[] encrypted = Encrypt(data, aes);
            await SendSignedData(stream, encrypted, rsa).ConfigureAwait(true);
        }

        static async Task<User> ReceiveDetails(SslStream stream, RSA crsa, Aes aes, string path) {
            User newUser = new User();
            newUser.publicKey = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
            newUser.selfSignature = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
            newUser.certSignature = Convert.FromBase64String(await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true));
            using (FileStream fs = File.Create(path)) {
                await JsonSerializer.SerializeAsync(fs, newUser, JsonSerializerOptions).ConfigureAwait(true);
            }

            return newUser;
        }

        static async Task<RSA> CreateNewUserRSA(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Get Username");
            string username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
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

            await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
            Console.WriteLine("Receive Their Public Key");

            User newUser = await ReceiveDetails(stream, crsa, aes, path).ConfigureAwait(true);

            RSA userRSA = RSA.Create();
            userRSA.ImportRSAPublicKey(newUser.publicKey, out _);

            return userRSA;
        }

        static async Task<RSA> ProcessLoginRSA(SslStream stream, RSA rsa, RSA crsa, Aes aes) {
            Console.WriteLine("Get Username");
            string username = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
            Console.WriteLine("Finding Details for {0}", username);
            username = username.Replace('\\', '-');
            username = username.Replace('/', '-');
            User user = null;

            string path = AppDomain.CurrentDomain.BaseDirectory + username;
            while (!File.Exists(path)) {
                Console.WriteLine("User Doesn't Exist");
                await EncryptSend(stream, false.ToString(), rsa, aes).ConfigureAwait(true);
                string resend = await ReceiveDecrypt(stream, crsa, aes).ConfigureAwait(true);
                if (bool.Parse(resend)) {
                    username = username.Replace('\\', '-');
                    username = username.Replace('/', '-');
                    path = AppDomain.CurrentDomain.BaseDirectory + username;
                    user = await ReceiveDetails(stream, crsa, aes, path).ConfigureAwait(true);
                } else
                    return null;
            }

            await EncryptSend(stream, true.ToString(), rsa, aes).ConfigureAwait(true);

            using (FileStream fs = File.OpenRead(path)) {
                user = (User)await JsonSerializer.DeserializeAsync(fs, typeof(User), JsonSerializerOptions);
            }

            Console.WriteLine("Verify Data Hasn't Been Tampered With");
            using (RSA userRSA = RSA.Create()) {
                if (!crsa.VerifyData(user.publicKey, user.certSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                    throw new AuthenticationException("User Public Key-Signature Invalid (Certificate Signature Doesn't Match Key)");

                userRSA.ImportRSAPublicKey(user.publicKey, out _);
                if (userRSA.VerifyData(user.publicKey, user.selfSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                    throw new AuthenticationException("User Public Key-Signature Invalid (Self Signature Doesn't Match Key)");

                if (!await ChallengeClient(rsa, userRSA, stream, 1024).ConfigureAwait(true))
                    throw new AuthenticationException("Client Failed Challenge.");

                return userRSA;
            }
        }

        static async Task ReceiveMessages(SslStream stream, RSA crsa, RSA userRSA, Aes aes) {
            Console.WriteLine("Receive Messages to relay for User");
        }

        static async Task HandleClient(SslStream stream, X509Certificate2 serverCert) {
            Console.WriteLine("Server Cert Has Private: {0}", serverCert.HasPrivateKey);
            using (RSA rsa = serverCert.GetRSAPrivateKey()) {
                Console.WriteLine("Import Client Public Key...");
                using (RSA crsa = RSA.Create()) {
                    crsa.ImportRSAPublicKey(stream.RemoteCertificate.GetPublicKey(), out _);
                    try {
                        Console.WriteLine("Challenge Client...");
                        if (await ChallengeClient(rsa, crsa, stream, 256).ConfigureAwait(true)) {
                            Console.WriteLine("Client Challenged. Generate Session RSA...");
                            using (RSA sessionRSA = RSA.Create(8192/*16384*/)) {
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
                                    RSA userRSA = null;
                                    switch ((Requests)r[0]) {
                                        case Requests.NewUser:
                                            userRSA = await CreateNewUserRSA(stream, rsa, crsa, aes).ConfigureAwait(true);
                                            break;
                                        case Requests.Login:
                                            userRSA = await ProcessLoginRSA(stream, rsa, crsa, aes).ConfigureAwait(true);
                                            break;
                                    }

                                    if (userRSA != null)
                                        await ReceiveMessages(stream, crsa, userRSA, aes).ConfigureAwait(true);
                                }
                            }
                        } else {
                            Console.WriteLine("Client Failed the Challenge");
                        }
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
                    }
                }
            }
        }

        static async void ListenForClients(TcpListener server, X509Certificate2 serverCert, X509Chain chain) {
            TcpClient client = null;
            Console.WriteLine("Await Connection");
            try {
                client = await server.AcceptTcpClientAsync().ConfigureAwait(true);
                if (listen)
                    ListenForClients(server, serverCert, chain);
            } catch (SocketException se) {
                Console.WriteLine("SocketException Waiting for Client to Connect: {0}", se.Message);
                Console.WriteLine(se.Source);
            }
            Console.WriteLine("Connected {0}", client.Client.RemoteEndPoint);
            SslStream stream = new SslStream(client.GetStream(), false);
            if (await AuthenticateStream(stream, serverCert).ConfigureAwait(true)) {
                await HandleClient(stream, serverCert).ConfigureAwait(true);
            } else
                Console.WriteLine("Client Authenticated but wasn't up to standard");

            //ClientServerVerify(client, chain, serverCert);

            Console.WriteLine("Closing Stream and Client");
            stream.Close();
            await stream.DisposeAsync().ConfigureAwait(true);
            client.Close();
        }

        static void Main(string[] args) {
            TcpListener server = new TcpListener(IPAddress.Any, 56168);
            if (args.Length == 0) {
                Console.WriteLine("Specify Arguments");
                return;
            }
            using (X509Certificate2 serverCert = LoadServerCert(AppDomain.CurrentDomain.BaseDirectory + "server.pfx", args[0])) {
                ca = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "ca.crt");
                listen = true;

                using (X509Store store = new X509Store(StoreName.Root)) {
                    store.Open(OpenFlags.ReadOnly);
                    AddToStore(store, ca);

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
                        server.Stop();
                        RemoveFromStore(store, ca);
                        using (X509Store serverStore = new X509Store(StoreName.My)) {
                            serverStore.Open(OpenFlags.ReadOnly);
                            RemoveFromStore(serverStore, serverCert);
                        }

                        ca.Dispose();
                    }
                }
            }
        }
    }
}
