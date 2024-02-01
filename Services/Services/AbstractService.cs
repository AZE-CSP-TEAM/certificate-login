using Common;
using Common.Enums.CommonEnums;
using Common.Enums.ErrorEnums;
using Common.Resources;
using DataAccess.UnitofWork;
using log4net;
using Models;
using System;
using System.Reflection;
using System.Reflection.Metadata;
using System.Threading.Tasks;

namespace Services.Services
{
    public abstract class AbstractService : IService
    {
        protected static readonly ILog _logger;
        protected readonly IUnitOfWork _uow;

        public AbstractService(IUnitOfWork uow) => _uow = uow;

        static AbstractService() => _logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        protected async Task<ContainerResult<TOutput>> ExecuteAsync<TOutput>
            (ConnectionTypes connectionType, Func<Task<ContainerResult<TOutput>>> callBack)
        {
            ContainerResult<TOutput> Result = new ContainerResult<TOutput>();
            try
            {
                _logger.Info($"Executing process started from this class : {GetType()}");

                Open(connectionType);

                Begin(connectionType);

                Result = await callBack();

                if (!Result.IsSuccess)
                {
                    RollBack(connectionType);

                    return Result;
                }

                Commit(connectionType);

                _logger.Info($"Executing process finished from this class : {GetType()}");
            }
            catch (Exception ex)
            {
                Result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.INTERNAL_ERROR,
                    ErrorMessage = Resource.UNHANDLED_EXCEPTION,
                    StatusCode = ErrorHttpStatus.INTERNAL
                });

                RollBack(connectionType);

                _logger.Error($"Error occured from this class : {GetType()} : {ex}");
            }
            finally
            {
                Close(connectionType);
            }

            return Result;
        }

        private void Open(ConnectionTypes connectionType)
        {
            if (connectionType != ConnectionTypes.NONE)
            {
                _uow.Open();
            }
        }

        private void Close(ConnectionTypes connectionType)
        {
            try
            {
                if (connectionType != ConnectionTypes.NONE)
                {
                    _uow.Close();
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Error occured close connection : {ex}");
            }
        }

        private void Begin(ConnectionTypes connectionType)
        {
            if (connectionType == ConnectionTypes.TRANSACTION)
            {
                _uow.Begin();
            }
        }

        private void Commit(ConnectionTypes connectionType)
        {
            if (connectionType == ConnectionTypes.TRANSACTION)
            {
                _uow.Commit();
            }
        }

        private void RollBack(ConnectionTypes connectionType)
        {
            if (connectionType == ConnectionTypes.TRANSACTION)
            {
                try
                {
                    _uow.RollBack();
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error occured rollback : {ex}");
                }
            }
        }

        #region Disposable Members
        public void Dispose() => _uow.Dispose();
        #endregion
    }
}
