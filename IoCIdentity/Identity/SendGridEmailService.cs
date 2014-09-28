using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using SendGrid;


namespace IoCIdentity.Identity
{
    public class SendGridEmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            // Create the email object first, then add the properties.
            var myMessage = new SendGridMessage();

            // this defines email and name of the sender
            myMessage.From = new MailAddress("no-reply@tech.trailmax.info", "My Awesome Admin");

            // set where we are sending the email
            myMessage.AddTo(message.Destination);

            myMessage.Subject = message.Subject;

            // make sure all your messages are formatted as HTML
            myMessage.Html = message.Body;

            // Create credentials, specifying your SendGrid username and password.
            var credentials = new NetworkCredential("YourUsername", "YourPassword");

            // Create an Web transport for sending email.
            var transportWeb = new Web(credentials);

            // Send the email.
            await transportWeb.DeliverAsync(myMessage);
        }
    }
}