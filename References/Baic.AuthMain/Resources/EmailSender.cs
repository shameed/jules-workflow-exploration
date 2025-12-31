using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System;
using System.Data;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;

namespace Baic.AuthMain.Resources
{
    public class EmailSender : IEmailSender
    {
        public IConfiguration _config;

        public IDbConnection SIDBConnection
        {
            get
            {
                return new SqlConnection(_config.GetConnectionString("SimpleInspireDB"));
            }
        }

        public EmailSender(IConfiguration config)
        {
            _config = config;
        }



        public void SendEmail(string from, string to, string subject, string body)
        {
            try
            {
                var message = new MailMessage(from, to, subject, body);
                var smtpClient = new SmtpClient(_config.GetSection("SMTP_Server").Value, Int16.Parse(_config.GetSection("SMTP_Port").Value));

                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_config.GetSection("SMTP_Mail").Value, _config.GetSection("SMTP_Password").Value);

                smtpClient.EnableSsl = true;

                smtpClient.Send(message);

                Console.WriteLine("Email sent successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending email: " + ex.Message);
            }
        }

        public async Task SendAuthEmail(string UserId, string Otp)
        {
            Int64 emailLogPk = 0;
            try
            {
                using (IDbConnection connection = SIDBConnection)
                {
                    connection.Open();
                    var parameters = new DynamicParameters();
                    parameters.Add("@UserID", UserId, DbType.String, ParameterDirection.Input, 50);
                    parameters.Add("@OTP", Otp, dbType: DbType.String, direction: ParameterDirection.Input, size: 10);
                    parameters.Add("@AsEmailLogPk", dbType: DbType.Int64, direction: ParameterDirection.Output, size: 18);

                    connection.Query("SI_AUTH_SendEmail", parameters, commandType: CommandType.StoredProcedure);

                    emailLogPk = parameters.Get<Int64>("AsEmailLogPk");

                    if (emailLogPk != 0)
                    {
                        var response = await TriggerMail(emailLogPk);
                        if (!response.IsSuccessStatusCode)
                        {
                            Console.WriteLine("Sent email failed");
                        }
                    }

                    Console.WriteLine("OTP email sent successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending OTP email: " + ex.Message);
            }
        }

        public async Task<HttpResponseMessage> TriggerMail(long emailLogId)
        {
            var mailgunService = _config.GetSection("MailgunService").Value;
            var request = new HttpRequestMessage(HttpMethod.Post, $"{mailgunService}/api/mailgun-rackspace/trigger-email/{emailLogId}");
            var content = new { emailLogId };
            var stringContent = Newtonsoft.Json.JsonConvert.SerializeObject(content);
            request.Content = new StringContent(stringContent, Encoding.UTF8, "application/json");

            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("User-Agent", "HttpClientFactory-STS");

            HttpClient client = new HttpClient();
            var response = await client.SendAsync(request);
            return response;
        }

        public async Task SendOtpEmail(string to, string subject, string body, string htmlBody = null, LinkedResource Img = null)
        {
            try
            {
                var message = new MailMessage();
                message.From = new MailAddress(_config.GetSection("SMTP_Mail").Value);
                message.To.Add(new MailAddress(to));
                message.Subject = subject;
                message.Body = body;

                if (htmlBody != null)
                {
                    AlternateView emailTemplate = AlternateView.CreateAlternateViewFromString(htmlBody, null, MediaTypeNames.Text.Html);
                    emailTemplate.LinkedResources.Add(Img);
                    message.AlternateViews.Add(emailTemplate);
                }

                // Configure your SMTP settings here
                var smtpClient = new SmtpClient(_config.GetSection("SMTP_Server").Value, Int16.Parse(_config.GetSection("SMTP_Port").Value))
                {
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(_config.GetSection("SMTP_Mail").Value, _config.GetSection("SMTP_Password").Value),
                    EnableSsl = true
                };

                using (smtpClient)
                {
                    await smtpClient.SendMailAsync(message);
                }

                Console.WriteLine("OTP email sent successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending OTP email: " + ex.Message);
            }
        }

    }
}



