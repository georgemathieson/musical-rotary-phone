using Microsoft.EntityFrameworkCore;

namespace NetworkMonitor.Server.Data;

public sealed class MonitorDbContext(DbContextOptions<MonitorDbContext> options) : DbContext(options)
{
    public DbSet<ConnectionRecord> Connections => Set<ConnectionRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<ConnectionRecord>();
        entity.HasIndex(c => c.StartedAt);
        entity.HasIndex(c => c.Port);
        entity.HasIndex(c => c.RemoteIp);
    }
}
