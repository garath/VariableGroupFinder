using Azure.Core;
using Azure.Identity;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;

namespace VariableFinder;

static class Program
{
    /// <summary>
    /// Identify Azure Pipeline Variable Groups using a given secret.
    /// </summary>
    /// <param name="VaultName">The name of the vault containing the secret</param>
    /// <param name="SecretName">The name of the secret</param>
    /// <param name="OrganizationUri">URI of the Azure DevOps organization</param>
    /// <param name="Project">Name of the Azure DevOps project</param>
    static async Task Main(string VaultName, string SecretName, string OrganizationUri = "https://dev.azure.com/dnceng", string Project = "internal")
    {
        ArgumentNullException.ThrowIfNull(VaultName, nameof(VaultName));
        ArgumentNullException.ThrowIfNull(SecretName, nameof(SecretName));
        ArgumentNullException.ThrowIfNull(OrganizationUri, nameof(OrganizationUri));
        ArgumentNullException.ThrowIfNull(Project, nameof(Project));

        DefaultAzureCredential credential = new();
        TokenRequestContext requestContext = new(["499b84ac-1321-427f-aa17-267ca6975798/.default"]);
        AccessToken result = await credential.GetTokenAsync(requestContext, CancellationToken.None);

        IList<VariableGroup> variableGroups = await GetVariableGroups(OrganizationUri, Project, result.Token);

        IEnumerable<(string Name, int Id)> vaultNames = variableGroups
            .Where(group => group.Type.Equals(VariableGroup.TypeIfAzureKeyVault))
            .Where(group => group.ProviderData!.Vault.Equals(VaultName, StringComparison.InvariantCultureIgnoreCase))
            .Where(group => group.Variables.Keys.Contains(SecretName, StringComparer.InvariantCultureIgnoreCase))
            .Select(group => (group.Name, group.Id));

        if (!vaultNames.Any())
        {
            Console.WriteLine($"The secret \"{SecretName}\" was not found in any variable groups");
        }
        else
        {
            Console.WriteLine($"The secret \"{SecretName}\" was found in variable groups:");

            foreach ((string name, int id) in vaultNames.OrderBy(name => name))
            {
                Console.WriteLine($"  {name}: {BuildVariableGroupViewUrl(OrganizationUri, Project, id)}");
            }
        }
    }

    static Uri BuildVariableGroupViewUrl(string organizationUri, string project, int variableGroupId)
    {
        return new Uri($"{organizationUri}/{project}/_library?itemType=VariableGroups&view=VariableGroupView&variableGroupId={variableGroupId}");
    }

    // Requires vso.variablegroups_read permission
    // Documentation: https://docs.microsoft.com/en-us/rest/api/azure/devops/distributedtask/variablegroups/get-variable-groups?view=azure-devops-rest-7.1
    static async Task<IList<VariableGroup>> GetVariableGroups(string organizationUri, string project, string accessToken)
    {
        // GET https://dev.azure.com/{organization}/{project}/_apis/distributedtask/variablegroups&$top={$top}&continuationToken={continuationToken}&queryOrder={queryOrder}&api-version=6.0-preview.2

        using HttpClient client = new(new SocketsHttpHandler()
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = X509RevocationMode.Online
            }, 
        });
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            scheme: "Basic",
            parameter: Convert.ToBase64String(Encoding.UTF8.GetBytes($":{accessToken}"))
        );

        Uri uri = new($"{organizationUri}/{project}/_apis/distributedtask/variablegroups?api-version=7.1-preview.2");

        GetVariableGroupsResponse? response = await client.GetFromJsonAsync<GetVariableGroupsResponse>(uri);

        if (response is null)
            throw new HttpRequestException("Response body not understood");

        return response.VariableGroups;
    }

    internal class GetVariableGroupsResponse
    {
        public int Count { get; }

        [JsonPropertyName("value")]
        public IList<VariableGroup> VariableGroups { get; }

        public GetVariableGroupsResponse(int count, IList<VariableGroup> variableGroups)
        {
            Count = count;
            VariableGroups = variableGroups;
        }
    }

    internal class VariableGroup
    {
        /// <summary>
        /// The value of <see cref="Type"/> if the variables are from an Azure KeyVault
        /// </summary>
        public const string TypeIfAzureKeyVault = "AzureKeyVault";

        /// <summary>
        /// The outer dictionary key is the variable name. The inner dictionary structure depends
        /// on the <see cref="Type"/> of the group.
        /// </summary>
        public IReadOnlyDictionary<string, IReadOnlyDictionary<string, object?>> Variables { get; }

        /// <summary>
        /// The ID of the Variable Group
        /// </summary>
        public int Id { get; }

        /// <summary>
        /// The name of the Variable Group
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The type (or source) of variables in this group
        /// </summary>
        /// // Values I've seen: "Vsts" (for form-filled), "AzureKeyVault"
        public string Type { get; }

        /// <summary>
        /// Only available if provider <see cref="Type"/> is AzureKeyVault
        /// </summary>
        public ProviderData? ProviderData { get; init; }

        public VariableGroup(int id, string name, string type, IReadOnlyDictionary<string, IReadOnlyDictionary<string, object?>> variables)
        {
            Id = id;
            Name = name;
            Type = type;
            Variables = variables;
        }
    }

    internal class ProviderData
    {
        public string Vault { get; }

        public ProviderData(string vault)
        {
            Vault = vault;
        }
    }
}