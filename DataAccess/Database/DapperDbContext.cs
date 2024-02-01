using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System;
using System.Data;

namespace DataAccess.Database
{
    public class DapperDbContext
    {
        private bool _disposed = false;

        private readonly IConfiguration _configuration;
        public IDbConnection DbConnection { get; private set; }
        public IDbTransaction DbTransaction { get; set; }
        public DapperDbContext(SqlConnection dbConnection, IConfiguration configuration)
        {
            _configuration = configuration;
            DbConnection = dbConnection;
            DbConnection.ConnectionString = _configuration.GetConnectionString("DefaultConnection");
        }

        #region Disposable Members
        private void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                DbTransaction?.Dispose();
                DbTransaction = null;

                DbConnection.Dispose();
                DbConnection = null;
            }
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~DapperDbContext()
        {
            Dispose(false);
        }
        #endregion
    }
}
