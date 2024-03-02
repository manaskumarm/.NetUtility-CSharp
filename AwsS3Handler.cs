
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Threading.Tasks;
using Amazon.Runtime;

namespace MyProject.Utils
{
    /// <summary>
    /// This class contains following functinalities with AWS S3 Storage: 
    /// - upload a file
    /// - download a file
    /// - delete a file
    /// </summary>
    public class AwsS3Handler
    {
        private static IConfiguration configuration = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json", optional: true, reloadOnChange: true).Build();
        private static AmazonS3Client client = null;

        public AwsS3Handler()
        {
            if (client == null)
                client= new AmazonS3Client(configuration["AwsAccessKeyID"], configuration["AwsAccessKeySecret"]);
        }

        /// <summary>
        /// Upload file to AWS S3
        /// </summary>
        /// <param name="client"></param>
        public async Task<bool> UploadS3ObjectAsync(byte[] fileContent, string fileName, string bucket = "")
        {
            try
            {
                MemoryStream stream = new MemoryStream(fileContent);
                PutObjectRequest request = new PutObjectRequest()
                {
                    InputStream = stream,
                    BucketName = string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket,
                    Key = fileName,
                    CannedACL = S3CannedACL.Private
                };

                PutObjectResponse response = await client.PutObjectAsync(request);
                if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                    return true;
                else
                    return false;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Copy an existing object. Create new one with same content.
        /// </summary>
        /// <param name="fileContent"></param>
        /// <param name="fileName"></param>
        /// <param name="bucket"></param>
        /// <returns></returns>
        public async Task<bool> CopyS3ObjectAsync(string sourceFile, string targetFile, string bucket = "")
        {
            try
            {
                CopyObjectRequest request = new CopyObjectRequest
                {
                    SourceBucket = string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket,
                    SourceKey = sourceFile,
                    DestinationBucket = string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket,
                    DestinationKey = targetFile
                };
                CopyObjectResponse response = await client.CopyObjectAsync(request);
                if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                    return true;
                else
                    return false;
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Delete all files from a folder and delete folder
        /// </summary>
        /// <param name="folderPath"></param>
        /// <param name="bucket"></param>
        /// <returns></returns>
        public async Task<bool> DeleteFilesFromFolder(string folderPath, string bucket = "")
        {
            try
            {
                bucket = string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket;
                // delete sub-folder
                DeleteObjectsRequest deleteRequest = new DeleteObjectsRequest() 
                { 
                    BucketName = bucket
                };

                // Listing contents of a folder
                ListObjectsRequest request = new ListObjectsRequest
                {
                    BucketName = bucket,
                    Prefix = folderPath
                };
                ListObjectsResponse responseList = await client.ListObjectsAsync(request);
                foreach (S3Object obj in responseList.S3Objects)
                {
                    deleteRequest.AddKey(obj.Key);
                }

                if (responseList.S3Objects.Count > 0)
                {
                    DeleteObjectsResponse response = await client.DeleteObjectsAsync(deleteRequest);
                    if (response.HttpStatusCode == System.Net.HttpStatusCode.OK)
                        return true;
                    else
                        return false;
                }
                else
                {
                    return true;
                }
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Delete object from AWS S3
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public async Task<bool> DeleteFile(string key, string bucket = "")
        {
            try
            {
                DeleteObjectResponse response = await client.DeleteObjectAsync(string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket, key);
                if (response.HttpStatusCode == System.Net.HttpStatusCode.NoContent)
                    return true;
                else
                    return false;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Download/Read file from AWS S3
        /// </summary>
        /// <returns></returns>
        public async Task<byte[]> ReadS3ObjectAsync(string key, string bucket = "")
        {
            try
            {
                var request = new GetObjectRequest()
                {
                    BucketName = string.IsNullOrEmpty(bucket) ? configuration["Bucket"].ToString() : bucket,
                    Key = key
                };
                GetObjectResponse response = await client.GetObjectAsync(request).ConfigureAwait(false);

                byte[] data = null;
                if (response != null)
                {
                    StreamReader reader = new StreamReader(response.ResponseStream);

                    using (var memstream = new MemoryStream())
                    {
                        reader.BaseStream.CopyTo(memstream);
                        data = memstream.ToArray();
                    }
                }

                return data;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
