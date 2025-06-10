To implement Azure Cosmos DB in a .NET Core Web API with best practices for exception handling, performance, and reliability, follow this structured approach:

🔧 Step 1: Install Required NuGet Packages
Ensure your project includes the following packages:

dotnet add package Microsoft.Azure.Cosmos
dotnet add package Microsoft.Extensions.Configuration
dotnet add package Microsoft.Extensions.DependencyInjection
dotnet add package Microsoft.Extensions.Logging

🛠️ Step 2: Configure CosmosClient with Dependency Injection
In your Program.cs or Startup.cs, configure the CosmosClient for dependency injection:

builder.Services.AddSingleton<CosmosClient>(serviceProvider =>
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var endpoint = configuration["CosmosDb:Endpoint"];
    var key = configuration["CosmosDb:Key"];
    return new CosmosClient(endpoint, key);
});

Ensure your appsettings.json contains the necessary Cosmos DB settings:

{
  "CosmosDb": {
    "Endpoint": "your-cosmosdb-endpoint",
    "Key": "your-cosmosdb-key"
  }
}

🗄️ Step 3: Implement Repository Pattern
Create an interface and its implementation to abstract Cosmos DB operations:

public interface ICosmosDbRepository
{
    Task<Item> CreateItemAsync(Item item);
    Task<Item> GetItemAsync(string id);
    Task<IEnumerable<Item>> GetItemsAsync(string query);
    Task<Item> UpdateItemAsync(Item item);
    Task DeleteItemAsync(string id);
}

public class CosmosDbRepository : ICosmosDbRepository
{
    private readonly CosmosClient _cosmosClient;
    private readonly Container _container;

    public CosmosDbRepository(CosmosClient cosmosClient)
    {
        _cosmosClient = cosmosClient;
        _container = _cosmosClient.GetContainer("DatabaseName", "ContainerName");
    }

    public async Task<Item> CreateItemAsync(Item item)
    {
        try
        {
            var response = await _container.CreateItemAsync(item, new PartitionKey(item.Id));
            return response.Resource;
        }
        catch (CosmosException ex)
        {
            // Handle specific Cosmos DB exceptions
            throw new Exception($"Error creating item: {ex.Message}", ex);
        }
    }

    public async Task<Item> GetItemAsync(string id)
    {
        try
        {
            var response = await _container.ReadItemAsync<Item>(id, new PartitionKey(id));
            return response.Resource;
        }
        catch (CosmosException ex)
        {
            // Handle specific Cosmos DB exceptions
            throw new Exception($"Error retrieving item: {ex.Message}", ex);
        }
    }

    public async Task<IEnumerable<Item>> GetItemsAsync(string query)
    {
        try
        {
            var iterator = _container.GetItemQueryIterator<Item>(new QueryDefinition(query));
            var results = new List<Item>();
            while (iterator.HasMoreResults)
            {
                var response = await iterator.ReadNextAsync();
                results.AddRange(response);
            }
            return results;
        }
        catch (CosmosException ex)
        {
            // Handle specific Cosmos DB exceptions
            throw new Exception($"Error querying items: {ex.Message}", ex);
        }
    }

    public async Task<Item> UpdateItemAsync(Item item)
    {
        try
        {
            var response = await _container.UpsertItemAsync(item, new PartitionKey(item.Id));
            return response.Resource;
        }
        catch (CosmosException ex)
        {
            // Handle specific Cosmos DB exceptions
            throw new Exception($"Error updating item: {ex.Message}", ex);
        }
    }

    public async Task DeleteItemAsync(string id)
    {
        try
        {
            await _container.DeleteItemAsync<Item>(id, new PartitionKey(id));
        }
        catch (CosmosException ex)
        {
            // Handle specific Cosmos DB exceptions
            throw new Exception($"Error deleting item: {ex.Message}", ex);
        }
    }
}

🧪 Step 4: Implement Controller
Create a controller to handle HTTP requests:

[ApiController]
[Route("api/[controller]")]
public class ItemsController : ControllerBase
{
    private readonly ICosmosDbRepository _repository;

    public ItemsController(ICosmosDbRepository repository)
    {
        _repository = repository;
    }

    [HttpPost]
    public async Task<ActionResult<Item>> CreateItem(Item item)
    {
        try
        {
            var createdItem = await _repository.CreateItemAsync(item);
            return CreatedAtAction(nameof(GetItem), new { id = createdItem.Id }, createdItem);
        }
        catch (Exception ex)
        {
            // Log and handle exception
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Item>> GetItem(string id)
    {
        try
        {
            var item = await _repository.GetItemAsync(id);
            if (item == null)
            {
                return NotFound();
            }
            return Ok(item);
        }
        catch (Exception ex)
        {
            // Log and handle exception
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    [HttpPut]
    public async Task<ActionResult<Item>> UpdateItem(Item item)
    {
        try
        {
            var updatedItem = await _repository.UpdateItemAsync(item);
            return Ok(updatedItem);
        }
        catch (Exception ex)
        {
            // Log and handle exception
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteItem(string id)
    {
        try
        {
            await _repository.DeleteItemAsync(id);
            return NoContent();
        }
        catch (Exception ex)
        {
            // Log and handle exception
            return StatusCode(500, $"Internal server error: {ex.Message}");
        }
    }
}

🛡️ Step 5: Exception Handling and Logging
Ensure robust exception handling and logging:

Use try-catch blocks around Cosmos DB operations.

Log exceptions using a logging framework like Serilog or NLog.

Return appropriate HTTP status codes and messages to the client.

⚡ Step 6: Performance Considerations
Connection Mode: Use ConnectionMode.Direct for better performance in production environments.

Consistency Level: Choose an appropriate consistency level based on your application's requirements.

Partitioning: Design your Cosmos DB containers with a suitable partition key to ensure scalability.

Throughput: Provision adequate throughput (RU/s) based on expected load.

Indexing: Customize indexing policies to optimize query performance.

✅ Summary
By following these steps, you can implement Azure Cosmos DB in your .NET Core Web API with best practices for exception handling, performance, and reliability. This approach ensures a scalable, maintainable, and robust application.
