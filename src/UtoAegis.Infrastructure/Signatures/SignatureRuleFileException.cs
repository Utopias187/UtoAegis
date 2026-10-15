namespace UtoAegis.Infrastructure.Signatures;

public sealed class SignatureRuleFileException : Exception
{
    public SignatureRuleFileException(string message)
        : base(message)
    {
    }

    public SignatureRuleFileException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
