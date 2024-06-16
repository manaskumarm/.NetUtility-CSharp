// Dapper is an open-source object-relational mapping (ORM) library for .NET and .NET Core applications. The library allows developers quickly and easily access data from databases without the need to write tedious code.
// ADO.NET connections via extension methods on your DbConnection instance. Dapper Plus is mostly used for bulk operation like insert, update and delete etc.
// It supports following databases with package
// SQL Server
// PostgreSQL -> Npgsql 
// MySQL/MariaDB -> MySql.Data or MySqlConnector
// SQLite -> System.Data.SQLite or Microsoft.Data.Sqlite
// Oracle -> Oracle.ManagedDataAccess
// Firebird -> FirebirdSql.Data.FirebirdClient
// DB2 -> IBM.Data.DB2
// Microsoft Access -> System.Data.OleDb

// PM> Install-Package Dapper

// Dapper: Give you full control over the SQL generated / uses stored procedures for everything. Entity Framework: Allow you to code with LINQ and forget everything about SQL

namespace Data.Access 
{
  public class Dapper
  {
    public void ScalarValues()
    {
      using (var connection = new SqlConnection(connectionString))
      {
          var sql = "SELECT COUNT(*) FROM Products";
          var count = connection.ExecuteScalar(sql); // ExecuteScalarAsync for Async uses
      	
          Console.WriteLine($"Total products: {count}");
      }     
    }

    public void SingleRecord()
    {
      using (var connection = new SqlConnection(connectionString))
      {
          var sql = "SELECT * FROM Products WHERE ProductID = 1";
          var product = connection.QuerySingle(sql); // QuerySingleOrDefault
      	
          Console.WriteLine($"{product.ProductID} {product.ProductName}");
      }

      using (var connection = new SqlConnection(connectionString))
      {
          var sql = "SELECT * FROM Products WHERE ProductID = 1";
          var product = connection.QueryFirstOrDefault(sql); // QueryFirst
      	
          Console.WriteLine($"{product.ProductID} {product.ProductName}");
      }
    }

    public void MultipleRows()
    {
      using (var connection = new SqlConnection(connectionString))
      {
          var sql = "SELECT * FROM Customers";
          var customers = connection.Query(sql); //QueryAsync for async uses
      	
          foreach(var customer in customers)
          {
              Console.WriteLine($"{customer.CustomerID} {customer.CompanyName}");
          }
      }
    }

    public void MultipleResultSet()
    {
      string sql = @"
      SELECT * FROM Invoices WHERE InvoiceID = @InvoiceID;
      SELECT * FROM InvoiceItems WHERE InvoiceID = @InvoiceID;
      ";
      using (var connection = new SqlConnection(connectionString))
      {
          using (var multi = connection.QueryMultiple(sql, new {InvoiceID = 1})) // QueryMultipleAsync for async uses
          {
              var invoice = multi.First<Invoice>();
              var invoiceItems = multi.Read<InvoiceItem>().ToList();
          }
      }   
    }

    public void DataReader()
    {
      using(var connection = new SqlConnection(connectionString))
      {
        var reader = await connection.ExecuteReaderAsync("SELECT * FROM Customers;");        
        while (reader.Read())
        {
            int id = reader.GetInt32(0);  // Get the first column of the row as an int
            string name = reader.GetString(1);  // Get the second column of the row as a string    
        
            Console.WriteLine("Id: {0}, Name: {1}", id, name);
        }
      }    
    }

    public void StoredProcedure()
    {
      using(var connection = new SqlConnection(connectionString))
      {
        //Set up DynamicParameters object to pass parameters  
        DynamicParameters parameters = new DynamicParameters();   
        parameters.Add("id", 1);  
      
        //Execute stored procedure and map the returned result to a Customer object  
        var customer = conn.QuerySingleOrDefault<Customer>("GetCustomerById", parameters, commandType: CommandType.StoredProcedure);    

        var sql = "EXEC GetSalesByYear @BeginningDate, @EndingDate";
        var values = new { BeginningDate = "2014-01-01", EndingDate = "2015-12-31" };
        var results = connection.Query(sql, values).ToList();
        results.ForEach(r => Console.WriteLine($"{r.OrderID} {r.Subtotal}"));
  
        var storedProcedureName = "GetSalesByYear";
        var values = new { BeginningDate = "2019-01-01", EndingDate = "2011-12-31" };
        var results = connection.Query(storedProcedureName, values, commandType: CommandType.StoredProcedure).ToList();
        results.ForEach(r => Console.WriteLine($"{r.OrderID} {r.Subtotal}"));
      }
    }

    public void GetDataUsingTransaction()
    {
      using (var connection = new SqlConnection(FiddleHelper.GetConnectionStringSqlServerW3Schools()))
      {
      	connection.Open();
      	
      	using (var transaction = connection.BeginTransaction())
      	{
      		// Dapper
      		var affectedRows1 = connection.Execute(sql, new {CustomerName = "Mark"}, transaction: transaction);
      		
      		// Dapper Transaction
      		var affectedRows2 = transaction.Execute(sql, new {CustomerName = "Mark"});
      		transaction.Commit();
      	}
      }    
    }    
  }
}
