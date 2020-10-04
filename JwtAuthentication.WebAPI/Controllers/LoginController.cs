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
                new Claim(ClaimTypes.Name, username)
            });

            const string sec = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";

            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
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