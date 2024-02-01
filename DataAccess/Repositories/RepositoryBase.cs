using Dapper;
using DataAccess.Database;
using Models.Dtos.RepositoriesDtos;
using System;
using System.Collections.Generic;
using System.Data;
using System.Reflection;
using System.Threading.Tasks;

namespace DataAccess.Repositories
{
    public abstract class RepositoryBase
    {
        protected readonly DapperDbContext _dbContext;

        public RepositoryBase(DapperDbContext dbContext) => _dbContext = dbContext;

        protected DynamicParameters FillParameters(RepositoryInputDto input)
        {
            if (input == null)
            {
                return null;
            }

            DynamicParameters parameters = new DynamicParameters();
            PropertyInfo[] properties = input.GetType().GetProperties();
            for (int i = 0; i < properties.Length; i++)
            {
                parameters.Add(properties[i].Name, properties[i].GetValue(input));
            }
            return parameters;
        }

        protected DynamicParameters FillParameters(object input, string inputName)
        {
            DynamicParameters parameters = new DynamicParameters();
            parameters.Add(inputName, input);
            return parameters;
        }

        protected async Task ExecuteAsync(string procedureName, RepositoryInputDto input = null) =>
            await _dbContext.DbConnection.ExecuteAsync(procedureName, FillParameters(input),
                commandType: CommandType.StoredProcedure, transaction: _dbContext.DbTransaction);

        protected async Task ExecuteAsync(string procedureName, object input, string inputName) =>
            await _dbContext.DbConnection.ExecuteAsync(procedureName, FillParameters(input, inputName),
                commandType: CommandType.StoredProcedure, transaction: _dbContext.DbTransaction);

        protected async Task<object> ExecuteScalarAsync(string procedureName, RepositoryInputDto input = null)
            => await _dbContext.DbConnection.ExecuteScalarAsync(procedureName, FillParameters(input),
                commandType: CommandType.StoredProcedure, transaction: _dbContext.DbTransaction);

        protected async Task<object> ExecuteScalarAsync(string procedureName, object input, string inputName)
           => await _dbContext.DbConnection.ExecuteScalarAsync(procedureName, FillParameters(input, inputName),
               commandType: CommandType.StoredProcedure, transaction: _dbContext.DbTransaction);

        protected async Task<TReturn> QueryFirstOrLastAsync<TReturn>(string procedureName,
           RepositoryInputDto input = null, int? commandTimeout = null) =>
           await _dbContext.DbConnection.QueryFirstOrDefaultAsync<TReturn>(procedureName, FillParameters(input),
               _dbContext.DbTransaction, commandTimeout, CommandType.StoredProcedure);

        protected async Task<TReturn> QueryFirstOrLastAsync<TReturn>(string procedureName,
           object input, string inputName, int? commandTimeout = null) =>
           await _dbContext.DbConnection.QueryFirstOrDefaultAsync<TReturn>(procedureName, FillParameters(input, inputName),
               _dbContext.DbTransaction, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TReturn>(string procedureName,
            RepositoryInputDto input = null, int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync<TReturn>(procedureName, FillParameters(input),
                _dbContext.DbTransaction, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TReturn>(string procedureName,
           object input, string inputName, int? commandTimeout = null) =>
           await _dbContext.DbConnection.QueryAsync<TReturn>(procedureName, FillParameters(input, inputName),
               _dbContext.DbTransaction, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TReturn>
            (string procedureName, Func<TFirst, TSecond, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TReturn>
            (string procedureName, Func<TFirst, TSecond, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TSeventh, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TSeventh, TReturn> map,
            RepositoryInputDto input = null, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);

        protected async Task<IEnumerable<TReturn>> QueryAsync<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TSeventh, TReturn>
            (string procedureName, Func<TFirst, TSecond, TThird, TFourth, TFifth, TSixth, TSeventh, TReturn> map,
            object input, string inputName, string splitOn = "Id", int? commandTimeout = null) =>
            await _dbContext.DbConnection.QueryAsync(procedureName,
                 map, FillParameters(input, inputName), _dbContext.DbTransaction, true,
                 splitOn, commandTimeout, CommandType.StoredProcedure);
    }
}
