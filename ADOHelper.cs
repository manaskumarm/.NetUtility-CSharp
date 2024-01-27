/// <summary>
    /// An ADO.NET helper class
    /// </summary>
    public class SqlADOHelper : IDisposable
    {
        // Internal members
        private static string _connString = null;
        protected SqlConnection _conn = null;
        protected SqlTransaction _trans = null;
        protected bool _disposed = false;

        /// <summary>
        /// Returns the current SqlTransaction object or null if no transaction is in effect.
        /// </summary>
        public SqlTransaction Transaction { get { return _trans; } }
        
        /// <summary>
        /// Constructor using global connection string.
        /// </summary>
        public SqlADOHelper(IAwsManagerReadKey awsManagerReadKey)
        {
            var configuration = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json", optional: true, reloadOnChange: true).Build();
            _connString = "Server=90FDGK3\\SQLEXPRESS;Initial Catalog=db-carrierappshub-dev;Persist Security Info=False;MultipleActiveResultSets=False;Encrypt=False;Trusted_Connection=True;TrustServerCertificate=False;Max Pool Size=600;Pooling=true;Connection Timeout=30";//awsManagerReadKey.AppConfigKeys[configuration["ConnectionStrings:UM_ADOConnection"]];
        }

        /// <summary>
        /// Constructure using connection string override
        /// </summary>
        /// <param name="connString">Connection string for this instance</param>
        public SqlADOHelper(string connString)
        {
            _connString = connString;
            //Connect();
        }

        /// <summary>
        /// Creates a SqlConnection using the current connection string
        /// </summary>
        protected void Connect()
        {
            _conn = new SqlConnection(_connString);
        }

        /// <summary>
        /// Constructs a SqlCommand with the given parameters. This method is normally called
        /// from the other methods and not called directly. But here it is if you need access
        /// to it.
        /// </summary>
        /// <param name="qry">SQL query or stored procedure name</param>
        /// <param name="type">Type of SQL command</param>
        /// <param name="args">Query arguments. Arguments should be in pairs where one is the
        /// name of the parameter and the second is the value. The very last argument can
        /// optionally be a SqlParameter object for specifying a custom argument type</param>
        /// <returns></returns>
        public SqlCommand CreateCommand(string qry, CommandType type, SqlConnection connObj, params object[] args)
        {
            SqlCommand cmd = new SqlCommand(qry, connObj);

            // Associate with current transaction, if any
            if (_trans != null)
                cmd.Transaction = _trans;

            // Set command type
            cmd.CommandType = type;
            cmd.CommandTimeout = 120;

            // Construct SQL parameters
            if (args != null)
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] is string && i < (args.Length - 1))
                    {
                        SqlParameter parm = new SqlParameter();
                        parm.ParameterName = (string)args[i];
                        parm.Value = args[++i];
                        cmd.Parameters.Add(parm);
                    }
                    else if (args[i] is SqlParameter)
                    {
                        cmd.Parameters.Add((SqlParameter)args[i]);
                    }
                    else throw new ArgumentException("Invalid number or type of arguments supplied");
                }
            return cmd;
        }

        /// <summary>
        /// Constructs a SqlCommand with the given parameters. This method is normally called
        /// from the other methods and not called directly. But here it is if you need access
        /// to it.
        /// </summary>
        /// <param name="qry">SQL query or stored procedure name</param>
        /// <param name="type">Type of SQL command</param>
        /// <param name="args">Query arguments. Arguments should be in pairs where one is the
        /// name of the parameter and the second is the value. The very last argument can
        /// optionally be a SqlParameter object for specifying a custom argument type</param>
        /// <returns></returns>
        public SqlCommand CreateCommand(string qry, CommandType type, SqlParameter[] args, SqlConnection connObj)
        {
            SqlCommand cmd = new SqlCommand(qry, connObj);

            // Associate with current transaction, if any
            if (_trans != null)
                cmd.Transaction = _trans;

            cmd.CommandType = type; // Set command type
            cmd.CommandTimeout = 120;
            if (args != null)
                cmd.Parameters.AddRange(args); // Set parameters

            return cmd;
        }

        #region Execute Members

        /// <summary>
        /// Executes a query that returns no results
        /// </summary>
        /// <param name="qry">Query text</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>The number of rows affected</returns>
        public int ExecuteNonQuery(string qry, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.Text, connObj, args))
                {
                    return cmd.ExecuteNonQuery();
                }
            }
        }

        /// <summary>
        /// Executes a stored procedure that returns no results
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>The number of rows affected</returns>
        public async Task<int> ExecuteNonQueryProcAsync(string proc, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(proc, CommandType.StoredProcedure, connObj, args))
                {
                    return await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Executes a stored procedure that returns no results
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>The number of rows affected</returns>
        public int ExecuteNonQueryProc(string proc, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(proc, CommandType.StoredProcedure, connObj, args))
                {
                    return cmd.ExecuteNonQuery();
                }
            }
        }

        /// <summary>
        /// Executes a query that returns a single value
        /// </summary>
        /// <param name="qry">Query text</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Value of first column and first row of the results</returns>
        public object ExecScalar(string qry, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.StoredProcedure, connObj, args))
                {
                    return cmd.ExecuteScalar();
                }
            }
        }

        /// <summary>
        /// Executes a query that returns a single value
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Value of first column and first row of the results</returns>
        public async Task<object> ExecuteScalarProc(string qry, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.StoredProcedure, connObj, args))
                {
                    return await cmd.ExecuteScalarAsync().ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Executes a query and returns the results as a SqlDataReader
        /// </summary>
        /// <param name="qry">Query text</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Results as a SqlDataReader</returns>
        public SqlDataReader ExecuteDataReader(string qry, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.Text, connObj, args))
                {
                    return cmd.ExecuteReader();
                }
            }
        }

        /// <summary>
        /// Executes a stored procedure and returns the results as a SqlDataReader
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Results as a SqlDataReader</returns>
        public async Task<List<T>> ExecuteDataReaderProc<T>(string qry, params object[] args)
        {
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                await connObj.OpenAsync().ConfigureAwait(false);
                using (SqlCommand cmd = CreateCommand(qry, CommandType.StoredProcedure, connObj, args))
                {
                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false))
                    {
                        return DataReaderMapToList<T>(reader);
                    }
                }
            }
        }

        /// <summary>
        /// Executes a stored procedure and returns the results as a SqlDataReader
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Results as a SqlDataReader</returns>
        public async Task<Dictionary<string, string>> ExecuteDataReaderSingle(string qry, List<string> columns, params object[] args)
        {
            Dictionary<string, string> data = new Dictionary<string, string>();
            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                await connObj.OpenAsync().ConfigureAwait(false);
                using (SqlCommand cmd = CreateCommand(qry, CommandType.StoredProcedure, connObj, args))
                {
                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false))
                    {
                        while (reader.Read())
                        {
                            foreach (var column in columns)
                            {
                                data.Add(column, reader[column].ToString());
                            }
                        }
                    }
                }
            }

            return data;
        }

        /// <summary>
        /// Method converts data reader object to List
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="dr"></param>
        /// <returns>List</returns>
        private static List<T> DataReaderMapToList<T>(IDataReader dr)
        {
            List<T> list = new List<T>();
            // If reader is null return blank list
            if (dr != null)
            {
                T obj = default(T);
                while (dr.Read())
                {
                    obj = Activator.CreateInstance<T>();
                    foreach (PropertyInfo prop in obj.GetType().GetProperties())
                    {
                        if (!object.Equals(dr[prop.Name], DBNull.Value))
                        {
                            prop.SetValue(obj, dr[prop.Name], null);
                        }
                    }
                    list.Add(obj);
                }
            }

            return list;
        }

        /// <summary>
        /// Executes a query and returns the results as a DataSet
        /// </summary>
        /// <param name="qry">Query text</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Results as a DataSet</returns>
        public DataSet ExecuteDataSet(string qry, params object[] args)
        {
            DataSet resultDataset = new DataSet();

            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.Text, connObj, args))
                {
                    SqlDataAdapter adapt = new SqlDataAdapter(cmd);
                    DataSet ds = new DataSet();
                    adapt.Fill(resultDataset);
                }
            }

            return resultDataset;
        }

        /// <summary>
        /// Executes a stored procedure and returns the results as a Data Set
        /// </summary>
        /// <param name="proc">Name of stored proceduret</param>
        /// <param name="args">Any number of parameter name/value pairs and/or SQLParameter arguments</param>
        /// <returns>Results as a DataSet</returns>
        public DataSet ExecuteDataSetProc(string qry, SqlParameter[] args)
        {
            DataSet resultDataset = new DataSet();

            using (SqlConnection connObj = new SqlConnection(_connString))
            {
                connObj.Open();
                using (SqlCommand cmd = CreateCommand(qry, CommandType.StoredProcedure, args, connObj))
                {
                    cmd.CommandTimeout = 300;
                    SqlDataAdapter adapt = new SqlDataAdapter(cmd);
                    adapt.Fill(resultDataset);
                }
            }

            return resultDataset;
        }

        #endregion

        #region Transaction Members

        /// <summary>
        /// Begins a transaction
        /// </summary>
        /// <returns>The new SqlTransaction object</returns>
        public SqlTransaction BeginTransaction()
        {
            Rollback();
            _trans = _conn.BeginTransaction();
            return Transaction;
        }

        /// <summary>
        /// Commits any transaction in effect.
        /// </summary>
        public void Commit()
        {
            if (_trans != null)
            {
                _trans.Commit();
                _trans = null;
            }
        }

        /// <summary>
        /// Rolls back any transaction in effect.
        /// </summary>
        public void Rollback()
        {
            if (_trans != null)
            {
                _trans.Rollback();
                _trans = null;
            }
        }

        #endregion

        #region IDisposable Members

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                // Need to dispose managed resources if being called manually
                if (disposing)
                {
                    if (_conn != null)
                    {
                        Rollback();
                        _conn.Dispose();
                        _conn = null;
                    }
                }
                _disposed = true;
            }
        }

        #endregion
    }
