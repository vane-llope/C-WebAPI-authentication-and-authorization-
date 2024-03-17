using Microsoft.EntityFrameworkCore;
using webAPIC_.Models;

namespace webAPIC_.Data
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options)
           : base(options) { }

        public DbSet<User> User { get; set; } = default!;
    }
}
