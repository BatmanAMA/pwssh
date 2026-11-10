// ==========================================================================
// pwssh model types, known_hosts handling and SSH.NET event handlers.
//
// Everything that SSH.NET calls back into lives here, in compiled code:
// SSH.NET raises HostKeyReceived and AuthenticationPrompt on its own
// message-listener thread, where a PowerShell script block has no runspace
// and cannot run.
//
// SSH.NET is reached through reflection only, so this file compiles (and the
// key-management cmdlets work) without Renci.SshNet.dll being present.
//
// Language level: C# 5, so that Windows PowerShell 5.1 can compile it.
// ==========================================================================
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

// ----------------------------------------------------------------------
// Output types (global namespace: referenced by name from the ps1xml files)
// ----------------------------------------------------------------------

public class SSHHostKey
{
    public string ComputerName { get; set; }
    public int Port { get; set; }
    public string KeyType { get; set; }          // ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256, ...
    public string Fingerprint { get; set; }      // SHA256 fingerprint
    public string FingerprintMD5 { get; set; }   // MD5 fingerprint (legacy)
    public int KeyLength { get; set; }
    public byte[] RawKey { get; set; }

    public SSHHostKey() { Port = 22; }

    public override string ToString()
    {
        return String.Format("{0} {1} ({2})", ComputerName, KeyType, Fingerprint);
    }
}

public class SSHKnownHost
{
    public string HostName { get; set; }         // host pattern, or the |1|salt|hash token
    public int Port { get; set; }
    public string KeyType { get; set; }
    public string KeyData { get; set; }          // base64 public key
    public string Fingerprint { get; set; }
    public string Marker { get; set; }           // "", "@revoked" or "@cert-authority"
    public bool Hashed { get; set; }
    public string Comment { get; set; }
    public string Source { get; set; }
    public int LineNumber { get; set; }

    public SSHKnownHost() { Port = 22; Marker = ""; Comment = ""; }

    public string ToKnownHostsLine()
    {
        string hostEntry = (Port == 22 || Hashed) ? HostName : String.Format("[{0}]:{1}", HostName, Port);
        string line = String.Format("{0} {1} {2}", hostEntry, KeyType, KeyData);
        if (!String.IsNullOrEmpty(Marker)) line = Marker + " " + line;
        if (!String.IsNullOrEmpty(Comment)) line = line + " " + Comment;
        return line;
    }

    public override string ToString()
    {
        return String.Format("{0} {1}", HostName, KeyType);
    }
}

public class SSHCommandResult
{
    public int SessionId { get; set; }
    public string ComputerName { get; set; }
    public string Command { get; set; }
    public int ExitCode { get; set; }
    public string ExitSignal { get; set; }
    public string Output { get; set; }
    public string Error { get; set; }
    public TimeSpan Duration { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }

    // Success and OutputLines are ScriptProperties in pwssh.Types.ps1xml

    public override string ToString() { return Output ?? ""; }
}

public class SSHPortForward
{
    public int ForwardId { get; set; }
    public int SessionId { get; set; }
    public string Type { get; set; }             // Local, Remote, Dynamic
    public string BoundHost { get; set; }
    public int BoundPort { get; set; }
    public string RemoteHost { get; set; }
    public int RemotePort { get; set; }
    public bool IsStarted { get; set; }
    public object InternalForward { get; set; }  // Renci.SshNet.ForwardedPort*

    // Stop() is a ScriptMethod in pwssh.Types.ps1xml

    public override string ToString()
    {
        switch (Type)
        {
            case "Local":
                return String.Format("L:{0}:{1} -> {2}:{3}", BoundHost, BoundPort, RemoteHost, RemotePort);
            case "Remote":
                // Listener first, then destination, as for Local
                return String.Format("R:{0}:{1} -> {2}:{3}", BoundHost, BoundPort, RemoteHost, RemotePort);
            case "Dynamic":
                return String.Format("D:{0}:{1}", BoundHost, BoundPort);
            default:
                return String.Format("{0}:{1}", Type, BoundPort);
        }
    }
}

public class SSHSessionInfo
{
    public int SessionId { get; set; }
    public string ComputerName { get; set; }
    public int Port { get; set; }
    public string UserName { get; set; }
    public string AuthMethod { get; set; }
    public bool Connected { get; set; }
    public DateTime ConnectedAt { get; set; }
    public string ServerVersion { get; set; }
    public string ClientVersion { get; set; }
    public string HostKeyType { get; set; }
    public string HostKeyFingerprint { get; set; }
    public byte[] HostKey { get; set; }          // key accepted at connect; pinned for SFTP/SCP
    public object InternalSession { get; set; }      // Renci.SshNet.SshClient
    public object InternalSftpClient { get; set; }   // cached Renci.SshNet.SftpClient
    public object InternalScpClient { get; set; }    // cached Renci.SshNet.ScpClient

    public SSHSessionInfo()
    {
        Port = 22;
        ConnectedAt = DateTime.UtcNow;
    }

    // Disconnect() is a ScriptMethod in pwssh.Types.ps1xml

    public override string ToString()
    {
        return String.Format("[{0}] {1}@{2}:{3} ({4})", SessionId, UserName, ComputerName, Port,
            Connected ? "Open" : "Closed");
    }
}

namespace PwSSH
{
    // ------------------------------------------------------------------
    // known_hosts
    // ------------------------------------------------------------------

    public enum HostKeyStatus
    {
        None,
        Ok,
        New,
        Changed,
        Revoked
    }

    public class KnownHostEntry
    {
        public string Marker;        // "", "@revoked", "@cert-authority"
        public string HostField;     // raw first field: pattern list or |1|salt|hash
        public string KeyType;
        public string KeyBase64;
        public string Comment;
        public string Source;
        public int LineNumber;
        public byte[] KeyBlob;       // null if the base64 is invalid

        public bool IsHashed
        {
            get { return HostField != null && HostField.StartsWith("|1|", StringComparison.Ordinal); }
        }

        /// <summary>
        /// True if this entry applies to hostSpec ("host" or "[host]:port"),
        /// using OpenSSH pattern-list semantics.
        /// </summary>
        public bool MatchesHost(string hostSpec)
        {
            if (String.IsNullOrEmpty(hostSpec) || String.IsNullOrEmpty(HostField)) return false;
            string host = hostSpec.ToLowerInvariant();

            if (IsHashed) return KnownHostsFile.MatchHashed(HostField, host);

            bool matched = false;
            foreach (string raw in HostField.Split(','))
            {
                string pattern = raw;
                if (pattern.Length == 0) continue;
                bool negated = pattern[0] == '!';
                if (negated) pattern = pattern.Substring(1);
                if (KnownHostsFile.WildcardMatch(pattern.ToLowerInvariant(), host))
                {
                    if (negated) return false;   // a negated match vetoes the whole line
                    matched = true;
                }
            }
            return matched;
        }
    }

    public class HostKeyCheckResult
    {
        public HostKeyStatus Status;
        public KnownHostEntry Entry;   // matching entry (Ok), offending entry (Changed/Revoked)
    }

    public static class KnownHostsFile
    {
        private static readonly char[] Blank = new char[] { ' ', '\t' };

        public static string FormatHost(string host, int port)
        {
            if (port == 22 || port <= 0) return host;
            return String.Format("[{0}]:{1}", host, port);
        }

        public static List<KnownHostEntry> Parse(string path)
        {
            var list = new List<KnownHostEntry>();
            if (String.IsNullOrEmpty(path) || !File.Exists(path)) return list;

            string[] lines = File.ReadAllLines(path);
            for (int i = 0; i < lines.Length; i++)
            {
                KnownHostEntry e = ParseLine(lines[i]);
                if (e == null) continue;
                e.Source = path;
                e.LineNumber = i + 1;
                list.Add(e);
            }
            return list;
        }

        /// <summary>Parse one known_hosts line; null for blanks, comments and garbage.</summary>
        public static KnownHostEntry ParseLine(string line)
        {
            if (line == null) return null;
            string t = line.Trim();
            if (t.Length == 0 || t[0] == '#') return null;

            string marker = "";
            if (t[0] == '@')
            {
                string[] m = t.Split(Blank, 2, StringSplitOptions.RemoveEmptyEntries);
                if (m.Length < 2) return null;
                marker = m[0];
                if (marker != "@revoked" && marker != "@cert-authority") return null;
                t = m[1].TrimStart();
            }

            string[] parts = t.Split(Blank, 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3) return null;

            var e = new KnownHostEntry();
            e.Marker = marker;
            e.HostField = parts[0];
            e.KeyType = parts[1];
            e.KeyBase64 = parts[2];
            e.Comment = parts.Length > 3 ? parts[3].Trim() : "";
            try { e.KeyBlob = Convert.FromBase64String(e.KeyBase64); }
            catch (FormatException) { e.KeyBlob = null; }
            return e;
        }

        public static bool WildcardMatch(string pattern, string text)
        {
            // Iterative glob match supporting '*' and '?'.
            int p = 0, t = 0, star = -1, mark = 0;
            while (t < text.Length)
            {
                if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t])) { p++; t++; }
                else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; }
                else if (star >= 0) { p = star + 1; t = ++mark; }
                else return false;
            }
            while (p < pattern.Length && pattern[p] == '*') p++;
            return p == pattern.Length;
        }

        public static bool MatchHashed(string hostField, string host)
        {
            // |1|base64(salt)|base64(HMAC-SHA1(salt, host))
            string[] parts = hostField.Split('|');
            if (parts.Length != 4 || parts[1] != "1") return false;
            byte[] salt, expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException) { return false; }

            using (var hmac = new HMACSHA1(salt))
            {
                return BytesEqual(hmac.ComputeHash(Encoding.UTF8.GetBytes(host)), expected);
            }
        }

        public static string HashHost(string hostSpec)
        {
            byte[] salt = new byte[20];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(salt); }
            using (var hmac = new HMACSHA1(salt))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(hostSpec.ToLowerInvariant()));
                return "|1|" + Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(hash);
            }
        }

        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>
        /// Look a host key up the way OpenSSH does: a revoked key always loses, an exact
        /// match wins, and any other key recorded for the host means it has changed.
        /// </summary>
        public static HostKeyCheckResult Check(IEnumerable<string> paths, string host, int port, byte[] keyBlob)
        {
            var all = new List<KnownHostEntry>();
            if (paths != null)
            {
                foreach (string path in paths)
                {
                    try { all.AddRange(Parse(path)); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }

            var result = new HostKeyCheckResult();
            result.Status = HostKeyStatus.New;

            string spec = FormatHost(host, port);
            KnownHostEntry ok = null, changed = null;

            foreach (KnownHostEntry e in all)
            {
                if (e.Marker == "@revoked")
                {
                    // Revocations apply to the key wherever the line's pattern matches.
                    if (e.KeyBlob != null && BytesEqual(e.KeyBlob, keyBlob) &&
                        (e.MatchesHost(spec) || e.MatchesHost(host)))
                    {
                        result.Status = HostKeyStatus.Revoked;
                        result.Entry = e;
                        return result;
                    }
                    continue;
                }
                if (e.Marker == "@cert-authority") continue;   // host certificates are not supported
                if (e.KeyBlob == null) continue;
                if (!e.MatchesHost(spec)) continue;

                if (BytesEqual(e.KeyBlob, keyBlob)) { if (ok == null) ok = e; }
                else if (changed == null) changed = e;
            }

            if (ok != null) { result.Status = HostKeyStatus.Ok; result.Entry = ok; return result; }
            if (changed != null) { result.Status = HostKeyStatus.Changed; result.Entry = changed; return result; }

            // OpenSSH also accepts a key recorded for the bare host name when connecting
            // to a non-default port.
            if (spec != host)
            {
                foreach (KnownHostEntry e in all)
                {
                    if (e.Marker.Length != 0 || e.KeyBlob == null) continue;
                    if (e.MatchesHost(host) && BytesEqual(e.KeyBlob, keyBlob))
                    {
                        result.Status = HostKeyStatus.Ok;
                        result.Entry = e;
                        return result;
                    }
                }
            }
            return result;
        }

        /// <summary>Append one line, making sure it does not run into an unterminated last line.</summary>
        public static void AppendLine(string path, string line)
        {
            if (line.IndexOf('\n') >= 0 || line.IndexOf('\r') >= 0)
                throw new ArgumentException("known_hosts entries must be a single line.");

            string dir = Path.GetDirectoryName(path);
            if (!String.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            using (var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read))
            {
                bool needNewline = false;
                if (fs.Length > 0)
                {
                    fs.Seek(-1, SeekOrigin.End);
                    needNewline = fs.ReadByte() != '\n';
                }
                fs.Seek(0, SeekOrigin.End);
                byte[] bytes = new UTF8Encoding(false).GetBytes((needNewline ? "\n" : "") + line + "\n");
                fs.Write(bytes, 0, bytes.Length);
            }
        }

        public static string KeyTypeOfBlob(byte[] blob)
        {
            if (blob == null || blob.Length < 4) return null;
            int len = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
            if (len <= 0 || len > 64 || len > blob.Length - 4) return null;
            return Encoding.ASCII.GetString(blob, 4, len);
        }

        public static string Sha256Fingerprint(byte[] blob)
        {
            using (var sha = SHA256.Create())
            {
                return "SHA256:" + Convert.ToBase64String(sha.ComputeHash(blob)).TrimEnd('=');
            }
        }
    }

    // ------------------------------------------------------------------
    // Host key verification (handler for SSH.NET's HostKeyReceived event)
    // ------------------------------------------------------------------

    public enum HostKeyMode
    {
        Strict,      // StrictHostKeyChecking=yes: only keys already in known_hosts
        Ask,         // unknown hosts are rejected with Status=New so the caller can prompt and retry
        AcceptNew,   // unknown hosts are recorded and trusted; changed keys are refused
        Off,         // StrictHostKeyChecking=no: as AcceptNew, and a changed key is tolerated
                     // only when no password would be sent (AllowChangedKey)
        Pinned,      // only PinnedKey is acceptable (secondary connections of a session)
        Capture      // record the key and refuse the connection (Get-SSHHostKey)
    }

    public class HostKeyVerifier
    {
        public HostKeyMode Mode;
        public string Host;
        public int Port = 22;
        public string[] KnownHostsPaths = new string[0];
        public string UserKnownHostsPath;
        public byte[] PinnedKey;
        public bool AllowChangedKey;

        // Results
        public bool Invoked;
        public bool Trusted;
        public HostKeyStatus Status = HostKeyStatus.None;
        public byte[] KeyBlob;
        public string KeyType;
        public int KeyLength;
        public string Fingerprint;
        public string Error;
        public List<string> Warnings = new List<string>();

        /// <summary>Subscribe to client.HostKeyReceived (client is any Renci.SshNet.BaseClient).</summary>
        public void Attach(object client)
        {
            if (client == null) throw new ArgumentNullException("client");
            EventInfo ev = client.GetType().GetEvent("HostKeyReceived");
            if (ev == null) throw new InvalidOperationException("Object has no HostKeyReceived event.");
            MethodInfo handler = typeof(HostKeyVerifier).GetMethod("OnHostKeyReceived");
            ev.AddEventHandler(client, Delegate.CreateDelegate(ev.EventHandlerType, this, handler));
        }

        public void OnHostKeyReceived(object sender, EventArgs e)
        {
            bool trust = false;
            try
            {
                Invoked = true;
                Type t = e.GetType();
                KeyBlob = (byte[])t.GetProperty("HostKey").GetValue(e, null);
                PropertyInfo lenProp = t.GetProperty("KeyLength");
                if (lenProp != null) KeyLength = (int)lenProp.GetValue(e, null);
                KeyType = KnownHostsFile.KeyTypeOfBlob(KeyBlob);
                if (KeyType == null)
                {
                    PropertyInfo nameProp = t.GetProperty("HostKeyName");
                    KeyType = nameProp != null ? (string)nameProp.GetValue(e, null) : "unknown";
                }
                Fingerprint = KnownHostsFile.Sha256Fingerprint(KeyBlob);
                trust = Evaluate();
            }
            catch (Exception ex)
            {
                trust = false;
                Error = "Host key verification failed: " + ex.Message;
            }
            finally
            {
                Trusted = trust;
                // Fail closed: SSH.NET defaults CanTrust to true.
                e.GetType().GetProperty("CanTrust").SetValue(e, trust, null);
            }
        }

        /// <summary>Decide on a key directly (also used by tests).</summary>
        public bool Verify(byte[] keyBlob)
        {
            Invoked = true;
            KeyBlob = keyBlob;
            KeyType = KnownHostsFile.KeyTypeOfBlob(keyBlob) ?? "unknown";
            Fingerprint = KnownHostsFile.Sha256Fingerprint(keyBlob);
            Trusted = Evaluate();
            return Trusted;
        }

        private bool Evaluate()
        {
            string where = KnownHostsFile.FormatHost(Host, Port);

            if (Mode == HostKeyMode.Capture) return false;

            if (Mode == HostKeyMode.Pinned)
            {
                if (KnownHostsFile.BytesEqual(PinnedKey, KeyBlob))
                {
                    Status = HostKeyStatus.Ok;
                    return true;
                }
                Status = HostKeyStatus.Changed;
                Error = String.Format(
                    "Host key verification failed: {0} presented a different host key ({1}) than the one " +
                    "this session was established with.", where, Fingerprint);
                return false;
            }

            HostKeyCheckResult check = KnownHostsFile.Check(KnownHostsPaths, Host, Port, KeyBlob);
            Status = check.Status;

            switch (check.Status)
            {
                case HostKeyStatus.Ok:
                    return true;

                case HostKeyStatus.Revoked:
                    Error = String.Format(
                        "Host key verification failed: the {0} host key for {1} is marked @revoked in {2}:{3}.",
                        KeyType, where, check.Entry.Source, check.Entry.LineNumber);
                    return false;

                case HostKeyStatus.Changed:
                    string banner =
                        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
                        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
                        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
                        "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n" +
                        String.Format("The host key for {0} has changed.\n", where) +
                        String.Format("Received: {0} {1}\n", KeyType, Fingerprint) +
                        String.Format("Offending {0} key in {1}:{2}\n", check.Entry.KeyType,
                            check.Entry.Source, check.Entry.LineNumber);
                    if (Mode == HostKeyMode.Off && AllowChangedKey)
                    {
                        Warnings.Add(banner + "Continuing because StrictHostKeyChecking is 'No'.");
                        return true;
                    }
                    if (Mode == HostKeyMode.Off)
                        banner += "Password authentication is disabled to avoid man-in-the-middle attacks.\n";
                    Error = banner + "Host key verification failed.";
                    return false;

                default: // New
                    if (Mode == HostKeyMode.Strict)
                    {
                        Error = String.Format(
                            "Host key verification failed: no {0} host key for {1} is known and " +
                            "StrictHostKeyChecking is 'Yes'.", KeyType, where);
                        return false;
                    }
                    if (Mode == HostKeyMode.Ask)
                    {
                        // The caller prompts on the pipeline thread and reconnects.
                        Error = String.Format("Host key verification failed: the host key for {0} is not known.", where);
                        return false;
                    }
                    // AcceptNew / Off: record and trust
                    if (!String.IsNullOrEmpty(UserKnownHostsPath))
                    {
                        try
                        {
                            KnownHostsFile.AppendLine(UserKnownHostsPath,
                                String.Format("{0} {1} {2}", where, KeyType, Convert.ToBase64String(KeyBlob)));
                            Warnings.Add(String.Format(
                                "Permanently added '{0}' ({1}) to the list of known hosts.", where, KeyType));
                        }
                        catch (Exception ex)
                        {
                            Warnings.Add(String.Format(
                                "Failed to add the host key for '{0}' to {1}: {2}", where, UserKnownHostsPath, ex.Message));
                        }
                    }
                    return true;
            }
        }
    }

    // ------------------------------------------------------------------
    // keyboard-interactive: answer password prompts
    // ------------------------------------------------------------------

    public class KeyboardInteractiveResponder
    {
        private readonly string _password;

        public KeyboardInteractiveResponder(string password) { _password = password; }

        /// <summary>Subscribe to method.AuthenticationPrompt (a KeyboardInteractiveAuthenticationMethod).</summary>
        public void Attach(object method)
        {
            if (method == null) throw new ArgumentNullException("method");
            EventInfo ev = method.GetType().GetEvent("AuthenticationPrompt");
            if (ev == null) throw new InvalidOperationException("Object has no AuthenticationPrompt event.");
            MethodInfo handler = typeof(KeyboardInteractiveResponder).GetMethod("OnAuthenticationPrompt");
            ev.AddEventHandler(method, Delegate.CreateDelegate(ev.EventHandlerType, this, handler));
        }

        public void OnAuthenticationPrompt(object sender, EventArgs e)
        {
            var prompts = e.GetType().GetProperty("Prompts").GetValue(e, null) as IEnumerable;
            if (prompts == null) return;
            foreach (object prompt in prompts)
            {
                Type t = prompt.GetType();
                string request = t.GetProperty("Request").GetValue(prompt, null) as string;
                // Only ever answer a password prompt; anything else (OTP, ...) is left empty.
                if (request != null && request.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0)
                    t.GetProperty("Response").SetValue(prompt, _password, null);
            }
        }
    }

    // ------------------------------------------------------------------
    // Dependency resolution for the bundled assemblies in lib/
    // ------------------------------------------------------------------

    public static class AssemblyResolver
    {
        private static readonly List<string> Dirs = new List<string>();
        private static bool _hooked;

        public static void Register(string directory)
        {
            lock (Dirs)
            {
                if (!Dirs.Contains(directory)) Dirs.Add(directory);
                if (_hooked) return;
                AppDomain.CurrentDomain.AssemblyResolve += Resolve;
                _hooked = true;
            }
        }

        private static Assembly Resolve(object sender, ResolveEventArgs args)
        {
            string name = new AssemblyName(args.Name).Name;
            string[] dirs;
            lock (Dirs) { dirs = Dirs.ToArray(); }
            foreach (string dir in dirs)
            {
                string candidate = Path.Combine(dir, name + ".dll");
                if (File.Exists(candidate)) return Assembly.LoadFrom(candidate);
            }
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Small reflection helpers for ShellStream (no public API in SSH.NET 2024.x)
    // ------------------------------------------------------------------

    public static class ShellStreamHelper
    {
        /// <summary>True once the remote side has closed the shell channel.</summary>
        public static bool IsClosed(object shellStream)
        {
            if (shellStream == null) return true;
            Type t = shellStream.GetType();
            FieldInfo disposed = t.GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance);
            if (disposed != null && (bool)disposed.GetValue(shellStream)) return true;
            FieldInfo channelField = t.GetField("_channel", BindingFlags.NonPublic | BindingFlags.Instance);
            if (channelField == null) return false;
            object channel = channelField.GetValue(shellStream);
            if (channel == null) return true;
            PropertyInfo isOpen = channel.GetType().GetProperty("IsOpen");
            if (isOpen == null) return false;
            return !(bool)isOpen.GetValue(channel, null);
        }

        /// <summary>Best-effort terminal resize; returns false if this SSH.NET build has no way to do it.</summary>
        public static bool Resize(object shellStream, uint columns, uint rows)
        {
            try
            {
                Type t = shellStream.GetType();
                MethodInfo pub = t.GetMethod("ChangeWindowSize", new Type[] { typeof(uint), typeof(uint), typeof(uint), typeof(uint) });
                if (pub != null)
                {
                    pub.Invoke(shellStream, new object[] { columns, rows, 0u, 0u });
                    return true;
                }
                FieldInfo channelField = t.GetField("_channel", BindingFlags.NonPublic | BindingFlags.Instance);
                if (channelField == null) return false;
                object channel = channelField.GetValue(shellStream);
                if (channel == null) return false;
                MethodInfo send = channel.GetType().GetMethod("SendWindowChangeRequest",
                    new Type[] { typeof(uint), typeof(uint), typeof(uint), typeof(uint) });
                if (send == null) return false;
                send.Invoke(channel, new object[] { columns, rows, 0u, 0u });
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
