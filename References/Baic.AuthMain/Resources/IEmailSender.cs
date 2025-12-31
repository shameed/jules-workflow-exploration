using System.Net.Http;
using System.Net.Mail;
using System.Threading.Tasks;

namespace Baic.AuthMain.Resources
{
    public interface IEmailSender
    {
        void SendEmail(string from, string to, string subject, string body);
        Task SendAuthEmail(string UserId, string Otp);
        Task SendOtpEmail(string to, string subject, string body, string htmlBody, LinkedResource Img);
        Task<HttpResponseMessage> TriggerMail(long emailLogId);
    }
}