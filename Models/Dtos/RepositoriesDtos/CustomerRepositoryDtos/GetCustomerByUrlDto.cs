using System;

namespace Models.Dtos.RepositoriesDtos.CustomerRepositoryDtos
{
    public class GetCustomerByUrlDto
    {
        public int Id { get; set; }
        public byte CustomerStatusId { get; set; }
        public byte SubOrganizationStatusId { get; set; }
        public byte OrganizationStatusId { get; set; }
        public int SubOrganizationId { get; set; }
        public int OrganizationId { get; set; }
        public string Url { get; set; }
        public string CallbackUrl { get; set; }
        public int Minutues { get; set; }
        public string SecretKey { get; set; }
        public string Algorithm { get; set; }
        public string Description { get; set; }
        public DateTime AddedDate { get; set; }
    }
}
