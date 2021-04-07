using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json;

namespace Encoders
{
    class JWTEncoder
    {
        string payload = "{ iat: 1613976225, jti: 'g9f4nchf-98da-a768-5e15-ac71dy934e87', first_name: 'abcdef', last_name: 'xyz', email: 'abc.xyz@abc.com' }";
        
        public string GetHs256EncoderToken()
        {
            IDictionary<string, object> payloadData = JsonConvert.DeserializeObject<Dictionary<string, object>>(payload);
            IJwtEncoder jwtEncoder = new JwtEncoder(new HMACSHA256Algorithm(), new JsonNetSerializer(), new JwtBase64UrlEncoder());
            return jwtEncoder.Encode(payloadData, "<yourkey>");
        }
        public string GetRs256EncoderToken(string serialNumber)
        {
            X509Certificate2Collection certificates;
            if (serialNumber == null) {
                throw new ArgumentNullException(nameof(serialNumber));
            }
            IDictionary<string, object> payloadData = JsonConvert.DeserializeObject<Dictionary<string, object>>(payload);
            
            using (var store = new X509Store(StoreLocation.LocalMachine)) {//you can change the store location
                store.Open(OpenFlags.OpenExistingOnly);
                certificates = store.Certificates.Find(X509FindType.FindBySerialNumber, serialNumber, true);
            }
            if (certificates.Count == 0)
                throw new Exception($"Certificate not found based on {serialNumber}");
            IJwtEncoder jwtEncoder = new JwtEncoder(new RS256Algorithm(certificates[0]), new JsonNetSerializer(), new JwtBase64UrlEncoder());
            return jwtEncoder.Encode(payloadData,new byte[0]);
        }
    }
}
