namespace SharpScape.Api.Data.Models
{
    /// <summary>
    /// Model that went throw authentication and has a new Access Token with the old Refreh Token.
    /// </summary>
    public class AuthenticatedResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
