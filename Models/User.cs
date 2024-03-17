using System.ComponentModel.DataAnnotations;

namespace webAPIC_.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        [Required]
        public required string Name { get; set; }

        public required string Email { get; set; }
        public byte[]? PasswordHash { get; set; }
        public byte[]? PasswordSalt { get; set; }
    }
}
