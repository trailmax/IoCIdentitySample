using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;


namespace IoCIdentity.Identity
{
    public class MailtrapEmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            var client = new SmtpClient
            {
                Host = "mailtrap.io",
                Port = 2525,
                Credentials = new NetworkCredential("24i897fhukds19", "360974iousfl15"),
                EnableSsl = true,
            };

            var @from = new MailAddress("no-reply@tech.trailmax.info", "My Awesome Admin");
            var to = new MailAddress(message.Destination);

            var mail = new MailMessage(@from, to)
            {
                Subject = message.Subject,
                Body = message.Body,
                IsBodyHtml = true,
            };

            client.Send(mail);

            return Task.FromResult(0);
        }
    }
}