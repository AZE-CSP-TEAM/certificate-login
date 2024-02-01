using System;
using DataAccess.Repositories.CustomerRepository;
using DataAccess.Repositories.UserRepository;

namespace DataAccess.UnitofWork
{
    public interface IUnitOfWork : IDisposable
    {
        // Repositories
        IUserRepository UserRepository();
        ICustomerRepository CustomerRepository();

        // Operations
        void Commit();
        void RollBack();
        void Begin();
        void Open();
        void Close();
    }
}
