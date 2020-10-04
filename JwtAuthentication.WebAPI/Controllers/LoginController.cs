using JwtAuthentication.WebAPI.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Web.Http;

namespace JwtAuthentication.WebAPI.Controllers
{
    public class LoginController : ApiController
    {
        private static readonly string _sec = "db3OIsj+BXE9NZDy0t8W3TcNekrF+2d/1sFnWG4HnV8TZY30iTOdtVWJG8abWvB1GlOgJuQZdcF2Luqm/hccMw==";
        [HttpPost]
        public IHttpActionResult Authenticate([FromBody] LoginRequest login)
        {
            var loginResponse = new LoginResponse { };
            var loginRequest = new LoginRequest
            {
                Username = login.Username.ToLower(),
                Password = login.Password
            };

            var isUsernamePasswordValid = loginRequest.Password == "admin@123" ? true : false;
            // if credentials are valid
            if (isUsernamePasswordValid)
            {
                var token = CreateToken(loginRequest.Username);
                //return the token
                return Ok(token);
            }

            // if credentials are not valid send unauthorized status code in response
            loginResponse.responseMsg.StatusCode = HttpStatusCode.Unauthorized;
            var response = ResponseMessage(loginResponse.responseMsg);
            return response;
        }

        private string CreateToken(string username)
        {
            //Set issued at date
            var issuedAt = DateTime.UtcNow;
            //set the time when it expires
            var expiresTime = DateTime.UtcNow.AddMinutes(5);

            var tokenHandler = new JwtSecurityTokenHandler();

            //create a identity and add claims to the user which we want to log in
            var claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "Admin.Test")
            });
            
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(_sec));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);

            //create the jwt
            var token = tokenHandler.CreateJwtSecurityToken(
                        issuer: "http://localhost:8000",
                        audience: "http://localhost:8000",
                        subject: claimsIdentity,
                        notBefore: issuedAt,
                        expires: expiresTime,
                        signingCredentials: signingCredentials);

            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
    }
}