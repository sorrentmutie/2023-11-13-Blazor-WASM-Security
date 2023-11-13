using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace DemoSecurity.Shared;

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    [DisplayName("Email Address")]
    public string Email { get; set; } = null!;

    [Required]
    [DataType(DataType.Password)]
    [StringLength(10, ErrorMessage = 
        "La password deve essere lunga tra {2} e {1} caratteri", MinimumLength = 6)]
    public string Password { get; set; } = null!;
}
