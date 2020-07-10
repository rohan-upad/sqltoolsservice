//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.SqlTools.Hosting.Contracts;
using Microsoft.SqlTools.Hosting.Protocol;
using Microsoft.SqlTools.ServiceLayer.Connection.Contracts;
using Microsoft.SqlTools.Utility;

namespace Microsoft.SqlTools.ServiceLayer.Connection
{
    public class AzureAuthenticationProvider : SqlAuthenticationProvider
    {
        private static int count;

        public override async Task<SqlAuthenticationToken> AcquireTokenAsync(SqlAuthenticationParameters parameters)
        {
            Interlocked.Increment(ref count);
            Logger.Write(TraceEventType.Information, "Request in!" + count);

            var message = new RequestSecurityTokenParams
            {
                Authority = parameters.Authority,
                Provider = "Azure",
                Resource = parameters.Resource,
                ServerName = parameters.ServerName,
                DatabaseName = parameters.DatabaseName,
                ConnectionId = parameters.ConnectionId.ToString(),
                CorrelationId = count,
            };

            var response = await ConnectionService.Instance.ServiceHost.SendRequest(SecurityTokenRequest.Type, message, true);
            var expiresOn = DateTimeOffset.FromUnixTimeSeconds(response.Expiration);

            return new SqlAuthenticationToken(response.Token, expiresOn);
        }

        public override bool IsSupported(SqlAuthenticationMethod authenticationMethod)
        {
            return true;
        }
    }
}