using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace Baic.AuthMain.Models.AccountViewModels
{
    public class PasswordRecoveryViewModel
    {
        public string UserID { get; set; }

        public string Email { get; set; }
        public SelectList Questions { get; set; }
        public string Question { get; set; }
        public string Answer { get; set; }

        public string ReturnUrl { get; set; }
    }
}
