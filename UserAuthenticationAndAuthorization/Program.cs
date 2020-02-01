using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static System.Console;

namespace UserAuthenticationAndAuthorization
{
    class Program
    {
        static void Main(string[] args)
        {
            
            Protector.Register("Alice", "Pa$$w0rd", new[] { "Admins" });
            Protector.Register("Bob", "Pa$$w0rd", new[] { "Sales", "TeamLeads" });
            Protector.Register("Eve", "Pa$$w0rd");
            
            //login process
            Write($"Enter your user name: ");
            string username = ReadLine();
            Write($"Enter your password: ");
            
            string password = ReadLine();
            Protector.LogIn(username, password);
            if (Thread.CurrentPrincipal == null)
            {
                WriteLine("Log in failed.");
                return;
            }
            var p = Thread.CurrentPrincipal;
            WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated}");
            WriteLine($"AuthenticationType: {p.Identity.AuthenticationType}");
            WriteLine($"Name: {p.Identity.Name}");
            WriteLine($"IsInRole(\"Admins\"): {p.IsInRole("Admins")}");
            WriteLine($"IsInRole(\"Sales\"): {p.IsInRole("Sales")}");
            
            if (p is ClaimsPrincipal)
            {
                WriteLine($"{p.Identity.Name} has the following claims:");
                foreach (Claim claim in (p as ClaimsPrincipal).Claims)
                {
                    WriteLine($"{claim.Type}: {claim.Value}");
                }
            }

        }
    }




    public class User
    {
        public string Name { get; set; }
        public string Salt { get; set; }
        public string SaltedHashedPassword { get; set; }
        public string[] Roles { get; set; }

    }

    class Protector
    {
        
        private static Dictionary<string, User> Users = new Dictionary<string, User>();

        
        public static User Register(string username, string password , string[] roles = null)
        {
            
            var rng = RandomNumberGenerator.Create();
            var saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            var saltText = Convert.ToBase64String(saltBytes);


            var saltedhashedPassword = SaltAndHashPassword(password, saltText);
            var user = new User
            {
                Name = username,
                Salt = saltText,
                SaltedHashedPassword = saltedhashedPassword,
                Roles = roles
            };
            
            Users.Add(user.Name, user);
            return user;
        }
        
        private static string SaltAndHashPassword(string password, string salt)
        {
            var sha = SHA256.Create();
            var saltedPassword = password + salt;
            return Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));
        }
        
        
        public static void LogIn(string username, string password)
        {
            if (CheckPassword(username, password))
            {
                var identity = new GenericIdentity(username, "CompanyAuth");
                var principal = new GenericPrincipal(identity, Users[username].Roles);
                System.Threading.Thread.CurrentPrincipal = principal;
            }
        }
        
        public static bool CheckPassword(string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }

            var user = Users[username];


            var saltedhashedPassword = SaltAndHashPassword(password, user.Salt);
            return (saltedhashedPassword == user.SaltedHashedPassword);
        }
    
        
    }
    
}