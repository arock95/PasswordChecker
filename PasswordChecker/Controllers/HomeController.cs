using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using RestSharp;
using System.Security.Cryptography;

namespace PasswordChecker.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        public ActionResult TestPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult TestPassword(string passwd)
        {
            // set for compatiblity w/ RestSharp
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | 
                                                              System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls12;
            // SHA1 hash the provided password
            var sb = Hash(passwd);
            
            /*
             we SHA1 hash the user password before sending. to provide more anonymity we truncate that hash to the first 5 characters
             then submit it to the API.  we are returned a list of all pwd hashes (excluding first 5 chars) that match those first 5 letters, 
             along with a count of how often they're found in leaks.  we compare, find something that matches, and return to the user the count
             */

            var client = new RestClient("https://api.pwnedpasswords.com");
            var request = new RestRequest("range/{id}", Method.GET);
            request.AddUrlSegment("id", sb.Substring(0,5));
            request.AddHeader("User-Agent", "Anthonys-Azure-Password-Tester");
            IRestResponse response = client.Execute(request);

            if (response.IsSuccessful)
            {
                string[] separators = new string[] { "\r\n" };
                string[] lines = response.Content.Split(separators, StringSplitOptions.None);

                var howMany = "0";
                var hashTrunc = sb.Substring(5).ToUpper();
                foreach (string line in lines)
                {
                    if (hashTrunc == line.Split(':')[0])
                    {
                        howMany = line.Split(':')[1];
                    }
                }

                ViewBag.content = howMany;
            }
            else
            {
                ViewBag.error = "Sorry, an error occurred.  Please try again later!";
            }

            return View();
        }

        static private string Hash(string input)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
                var sb = new System.Text.StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
            
        }
    }
}