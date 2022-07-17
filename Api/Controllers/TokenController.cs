using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SharpScape.Api.Data;
using SharpScape.Api.Data.Models;
using SharpScape.Api.Services;

namespace SharpScape.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly Crypto _crypto;
        public TokenController(AppDbContext userContext, Crypto crypto)
        {
            this._context = userContext ?? throw new ArgumentNullException(nameof(userContext));
            this._crypto = crypto;
        }


        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(TokenApiModel tokenApiModel)
        {
            if (tokenApiModel is null)
                return BadRequest("Invalid client request");

            // string accessToken = tokenApiModel.AccessToken;
            string refreshToken = tokenApiModel.RefreshToken;

            var principal = _crypto.GetPrincipalFromExpiredToken(refreshToken);
            var username = principal.Identity.Name; //this is mapped to the Name claim by default

            var user = _context.Users.SingleOrDefault(u => u.Username == username);

            //Check Refresh Token Authentications
            if (user == null)
                return BadRequest("no user");
            if (user.RefreshToken != refreshToken)
                return BadRequest("something wrong with refresh token");
            if (user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest(user.RefreshTokenExpiryTime);

            var newAccessToken = _crypto.CreateToken(user);
            //var newRefreshToken = _crypto.CreateRefreshToken(user);

            _context.SaveChanges();
            return Ok(new AuthenticatedResponse()
            {
                AccessToken = newAccessToken,
                RefreshToken = tokenApiModel.RefreshToken
            });
        }


        [HttpPost, Authorize]
        [Route("revoke")]
        public IActionResult Revoke()
        {
            var username = User.Identity.Name;
            var user = _context.Users.SingleOrDefault(u => u.Username == username);
            if (user == null) return BadRequest();
            user.RefreshToken = null;
            _context.SaveChanges();
            return NoContent();
        }
    }
}
