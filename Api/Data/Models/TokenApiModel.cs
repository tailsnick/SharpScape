namespace SharpScape.Api.Data.Models
{
    /// <summary>
    /// A Model for holding Access Token and Refresh Token
    /// </summary>
    public class TokenApiModel
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
