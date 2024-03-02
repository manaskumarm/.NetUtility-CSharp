using System;
using System.IO;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace MyProject.Utils
{
    /// <summary>
    /// This class contains functinalities to upload and download files to Azure Blob Storage
    /// </summary>
    public class AzureBlobHandler
    {
        static IConfiguration configuration = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json", optional: true, reloadOnChange: true).Build();
        // Parse the connection string and return a reference to the storage account.
        CloudStorageAccount storageAccount = CloudStorageAccount.Parse(configuration["BlobConnectionStr"].ToString());

        #region CloudBlob Upload/Download

        /// <summary>
        /// This method downloads a file from Azure blob storage
        /// </summary>
        /// <param name="fileName"></param>
        public async Task<byte[]> DownloadFile(string containerName, string fileName)
        {
            try
            {
                CloudBlobContainer blobContainer = await GetCloudBlobContainerAsync(containerName);
                CloudBlockBlob blockBlob = blobContainer.GetBlockBlobReference(fileName);

                var memStream = new MemoryStream();
                await blockBlob.DownloadToStreamAsync(memStream);
                return memStream.ToArray();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// This method uploads a file to Azure blob storage
        /// </summary>
        /// <param name="fileName"></param>
        public async Task<bool> UploadFileAsync(byte[] fileContent, string fileName, string containerName, bool isInnerPath = false)
        {
            try
            {
                CloudBlobContainer blobContainer = await GetCloudBlobContainerAsync(containerName);
                if (isInnerPath)
                    fileName = configuration["Blob:FolderPath"].ToString() + fileName;
                CloudBlockBlob cloudBlockBlob = blobContainer?.GetBlockBlobReference(fileName);
                if (cloudBlockBlob != null)
                    await cloudBlockBlob.UploadFromByteArrayAsync(fileContent, 0, fileContent.Length);
                else
                    throw new UnoBaseException("Not able connect Azure Blob");
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return true;
        }

        /// <summary>
        /// This method deletes a file from Azure Blob
        /// </summary>
        /// <param name="containerName"></param>
        /// <param name="filename"></param>
        public async Task DeleteFileAsync(string containerName, string filename)
        {
            // Retrieve reference to a previously created container.
            CloudBlobContainer container = await GetCloudBlobContainerAsync(containerName);
            // Retrieve reference to a blob named as filename.
            CloudBlockBlob blockBlob = container.GetBlockBlobReference(filename);

            // Delete the blob.
            await blockBlob.DeleteAsync();
        }

        /// <summary>
        /// Get Blob container object.
        /// If it is not exists, it crates and returns object.
        /// </summary>
        /// <returns></returns>
        private async Task<CloudBlobContainer> GetCloudBlobContainerAsync(string containerName)
        {
            // Get a reference to the storage account
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            if (string.IsNullOrEmpty(containerName))
                containerName = configuration["Blob:Container"].ToString();
            CloudBlobContainer blobContainer = blobClient.GetContainerReference(containerName);
            bool isExists = await blobContainer.CreateIfNotExistsAsync();
            if (await blobContainer.CreateIfNotExistsAsync())
            {
                await blobContainer.SetPermissionsAsync(new BlobContainerPermissions
                {
                    PublicAccess = BlobContainerPublicAccessType.Unknown
                });
            }

            return blobContainer;
        }

        #endregion
    }
}
