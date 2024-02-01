namespace SecurityManager.Models
{
    public class Customer
    {
        public double Minutes { get; set; }
        public string SecurityAlgorithm { get; set; }
        public string Secret { get; set; }
        public string Audience { get; set; }
    }
}
