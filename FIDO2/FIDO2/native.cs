using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class native
    {
        
        public const int NO_ERROR = unchecked((int)0x00000000);

        public enum scope : uint
        {
            SCARD_SCOPE_USER = 0,
            SCARD_SCOPE_TERMINAL = 1,
            SCARD_SCOPE_SYSTEM = 2
        };

        public enum share : uint
        {
            SCARD_SHARE_EXCLUSIVE = 1,
            SCARD_SHARE_SHARED = 2,
            SCARD_SHARE_DIRECT = 3
        }

        public enum protocol : uint
        {
            SCARD_PROTOCOL_UNDEFINED = 0x00000000,
            SCARD_PROTOCOL_T0 = 0x00000001,
            SCARD_PROTOCOL_T1 = 0x00000002,
            SCARD_PROTOCOL_T0orT1 = 0x00000003,
            SCARD_PROTOCOL_RAW = 0x00010000
        }

        public enum disposition : uint
        {
            SCARD_LEAVE_CARD = 0,
            SCARD_RESET_CARD = 1,
            SCARD_UNPOWER_CARD = 2,
            SCARD_EJECT_CARD = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SCARD_IO_REQUEST
        {
            public protocol dwProtocol;
            public UInt32 cbPciLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
        }


        public enum KERB_LOGON_SUBMIT_TYPE
        {
            KerbInteractiveLogon = 2,
            KerbSmartCardLogon = 6,
            KerbWorkstationUnlockLogon = 7,
            KerbSmartCardUnlockLogon = 8,
            KerbProxyLogon = 9,
            KerbTicketLogon = 10,
            KerbTicketUnlockLogon = 11,
            //#if (_WIN32_WINNT >= 0x0501) -- Disabled until IIS fixes their target version. 
            KerbS4ULogon = 12,
            //#endif 
            //#if (_WIN32_WINNT >= 0x0600) 
            KerbCertificateLogon = 13,
            KerbCertificateS4ULogon = 14,
            KerbCertificateUnlockLogon = 15,
            //#endif
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CERTIFICATE_LOGON
        {
            public KERB_LOGON_SUBMIT_TYPE MessageType;
            public UnicodeStringOut DomainName;
            public UnicodeStringOut UserName;
            public UnicodeStringOut Pin;
            public int Flags;
            public int CspDataLength;
            public IntPtr CspData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UnicodeStringOut
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

            [Flags]
        public enum PromptForWindowsCredentialsFlags : uint
        {
            GenericCredentials = 0x1,
            ShowCheckbox = 0x2,
            AuthpackageOnly = 0x10,
            InCredOnly = 0x20,
            EnumerateAdmins = 0x100,
            EnumerateCurrentUser = 0x200,
            SecurePrompt = 0x1000,
            PREPROMPTING = 0x2000,
            AzureAAD = 0x40000,
            Pack32Wow = 0x10000000,
            WindowsHello = 0x80000000,

            ALWAYS_SHOW_UI = 0x00080,
            COMPLETE_USERNAME = 0x00800,
            NO_NOT_PERSIST = 0x00002,
            EXCLUDE_CERTIFICATES = 0x00008,
            EXPECT_CONFIRMATION = 0x20000,
            GENERIC_CREDENTIALS = 0x40000,
            FLAGS_INCORRECT_PASSWORD = 0x00001,
            KEEP_USERNAME = 0x100000,
            PASSWORD_ONLY_OK = 0x00200,
            PERSIST = 0x01000,
            REQUEST_ADMINISTRATOR = 0x00004,
            REQUIRE_CERTIFICATE = 0x00010,
            REQUIRE_SMARTCARD = 0x00100,
            SERVER_CREDENTIAL = 0x04000,
            SHOW_SAVE_CHECK_BOX = 0x00040,
            USERNAME_TARGET_CREDENTIALS = 0x80000,
            VALIDATE_USERNAME = 0x00400
        }

        public enum FORMAT_MESSAGE : uint
        {
            ALLOCATE_BUFFER = 0x00000100,
            IGNORE_INSERTS = 0x00000200,
            FROM_SYSTEM = 0x00001000,
            ARGUMENT_ARRAY = 0x00002000,
            FROM_HMODULE = 0x00000800,
            FROM_STRING = 0x00000400
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CredentialUIInfo
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }


        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage);

        [DllImport("credui.dll", EntryPoint = "SspiPromptForCredentialsW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int SspiPromptForCredentials(
            string pszTargetName,
            ref CredentialUIInfo pUiInfo,
            uint dwAuthError,
            string pszPackage,
            IntPtr pInputAuthIdentity,
            IntPtr ppAuthIdentity,
            ref bool pfSave,
            uint dwFlags
            );

        [DllImport("credui.dll", EntryPoint = "CredUIPromptForWindowsCredentialsW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int CredUIPromptForWindowsCredentials(ref CredentialUIInfo creditUR,
            int authError,
            ref uint authPackage,
            KERB_CERTIFICATE_LOGON inAuthBuffer,
            int inAuthBufferSize,
            out IntPtr refOutAuthBuffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            PromptForWindowsCredentialsFlags flags);

        [DllImport("kernel32.dll")]
        public static extern int FormatMessage(
            FORMAT_MESSAGE dwFlags,
            IntPtr lpSource,
            int dwMessageId,
            uint dwLanguageId,
            out StringBuilder msgOut,
            int nSize,
            IntPtr Arguments);

        [DllImport("winscard.dll", EntryPoint = "SCardConnectA", CharSet = CharSet.Ansi)]
        public static extern uint SCardConnect(IntPtr context, String reader, share ShareMode, protocol PreferredProtocols, out IntPtr cardHandle, out protocol ActiveProtocol);

        [DllImport("winscard.dll")]
        public static extern uint SCardDisconnect(IntPtr hCard, disposition Disposition);

        [DllImport("winscard.dll")]
        public static extern uint SCardGetAttrib(IntPtr hCard, uint AttrId, byte[] Attrib, ref int AttribLen);

        [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi)]
        public static extern uint SCardListReaders(IntPtr hContext, byte[] mszGroups, byte[] mszReaders, ref UInt32 pcchReaders);

        [DllImport("winscard.dll")]
        public static extern uint SCardEstablishContext(scope Scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

        [DllImport("winscard.dll")]
        public static extern uint SCardIsValidContext(IntPtr context);

        [DllImport("WinScard.dll")]
        public static extern uint SCardTransmit(IntPtr hCard, ref SCARD_IO_REQUEST pioSendRequest, Byte[] SendBuff, int SendBuffLen, ref SCARD_IO_REQUEST pioRecvRequest, Byte[] RecvBuff, ref int RecvBuffLen);

        [DllImport("winscard.dll")]
        public static extern int SCardStatus(uint hCard, IntPtr szReaderName, ref int pcchReaderLen, ref int pdwState, ref uint pdwProtocol, byte[] pbAtr, ref int pcbAtrLen);

        
    }
}
