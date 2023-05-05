namespace JwtWebApi.Entity
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] Passwordhash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
