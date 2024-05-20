using Microsoft.EntityFrameworkCore;
using TokenProvider.Infrastructure.Data.Entities;

namespace TokenProvider.Infrastructure.Data.Contexts;

public class DataContext(DbContextOptions<DataContext> options) : DbContext(options)
{
    public DbSet<RefreshTokenEntity> RefreshTokens { get; set; }
}
