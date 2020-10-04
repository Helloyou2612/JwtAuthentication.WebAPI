using System.Net;
using System.Net.Http;

namespace JwtAuthentication.WebAPI.Models
{
    public class LoginResponse
    {
        public HttpResponseMessage responseMsg { get; set; }
    }
}