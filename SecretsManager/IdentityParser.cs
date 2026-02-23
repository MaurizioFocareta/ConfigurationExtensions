using System;

namespace SecretsManager
{
    public enum IdentityKind
    {
        Local,
        DomainUPN,
        DomainSam
    }

    public sealed class ParsedIdentity
    {
        public string User { get; internal set; }         // "user" (no domain prefix)
        public string Domain { get; internal set; }       // "DOMAIN" or "."; null for UPN
        public string Original { get; internal set; }     // original input
        public IdentityKind Kind { get; internal set; }
        public bool IsLocal => Kind == IdentityKind.Local;
        public bool IsDomain => Kind == IdentityKind.DomainUPN || Kind == IdentityKind.DomainSam;
    }

    public static class IdentityParser
    {
        public static ParsedIdentity Parse(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                throw new ArgumentException("Username cannot be empty.", nameof(input));
            }

            var original = input.Trim();

            // 1) UPN form: user@domain
            int at = original.IndexOf('@');
            if (at > 0 && at < original.Length - 1)
            {
                return new ParsedIdentity
                {
                    Original = original,
                    Kind = IdentityKind.DomainUPN,
                    // For UPN, LogonUser wants the entire UPN in 'username'; domain must be null/ignored
                    User = original,
                    Domain = null
                };
            }

            // 2) SAM form: DOMAIN\user (or MACHINE\user)
            int slash = original.IndexOf('\\');
            if (slash > 0 && slash < original.Length - 1)
            {
                string left = original.Substring(0, slash);
                string user = original.Substring(slash + 1);

                // .\user is an explicit local account
                if (left == ".")
                {
                    return new ParsedIdentity
                    {
                        Original = original,
                        Kind = IdentityKind.Local,
                        User = user,
                        Domain = "."
                    };
                }

                // If left equals computer name -> local
                string machine = Environment.MachineName;
                if (left.Equals(machine, StringComparison.OrdinalIgnoreCase))
                {
                    return new ParsedIdentity
                    {
                        Original = original,
                        Kind = IdentityKind.Local,
                        User = user,
                        Domain = "."
                    };
                }

                // Otherwise we assume domain/trusted realm
                return new ParsedIdentity
                {
                    Original = original,
                    Kind = IdentityKind.DomainSam,
                    User = user,
                    Domain = left
                };
            }

            // 3) Fallback: no domain info, assume local account
            return new ParsedIdentity
            {
                Original = original,
                Kind = IdentityKind.Local,
                User = original,
                Domain = null
            };
        }

        /// <summary>
        /// Returns a tuple (user, domain) ready for LogonUser based on parsing and machine state.
        /// Policy: UPN -> (user=UPN, domain=null)
        /// SAM domain -> (user, domain)
        /// Local -> (user, ".")
        /// </summary>
        public static (string user, string domain, IdentityKind kind) DecideForLogonUser(string input)
        {
            var parsed = Parse(input);

            if (parsed.Kind == IdentityKind.DomainUPN)
                return (parsed.User, null, parsed.Kind);

            if (parsed.Kind == IdentityKind.DomainSam)
                return (parsed.User, parsed.Domain, parsed.Kind);

            if (parsed.Kind == IdentityKind.Local)
                return (parsed.User, ".", parsed.Kind);

            return (parsed.User, ".", IdentityKind.Local);
        }
    }
}