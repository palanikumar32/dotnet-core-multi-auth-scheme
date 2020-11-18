namespace MultipleAuthScheme.Models
{
    public class AuthenticationResult
    {
        public bool HasError { get; set; }
        public string Token { get; set; }
        public string Message { get; set; }
    }
}
