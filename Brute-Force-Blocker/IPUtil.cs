using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Brute_Force_Blocker
{
    internal class IPUtil
    {

        public class IPInfo
        {
            public string ISP { get; set; }
            public string Country { get; set; }
            public string City { get; set; }
            public string CountryCode { get; set; }
            public string Region { get; set; }
            public string RegionName { get; set; }
            public string Zip { get; set; }
            public float? Lat { get; set; }
            public float? Lon { get; set; }
            public string Timezone { get; set; }
            public string Org { get; set; }
            public string As { get; set; }
        }
        public static async Task<IPInfo> GetIPInfoAsync(string ipAddress)
        {
            IPInfo ipInfo = new IPInfo();

            using (HttpClient client = new HttpClient())
            {
                try
                {
                    string url = $"http://ip-api.com/json/{ipAddress}";

                    HttpResponseMessage response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    string json = await response.Content.ReadAsStringAsync();
                    ipInfo = JsonConvert.DeserializeObject<IPInfo>(json);
                }
                catch (Exception)
                {
                    ipInfo.Country = "Error fetching data!";
                }
            }
            return ipInfo;
        }

    }
}
