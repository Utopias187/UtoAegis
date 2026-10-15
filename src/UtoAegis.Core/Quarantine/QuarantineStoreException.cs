namespace UtoAegis.Core.Quarantine;

public sealed class QuarantineStoreException : Exception
{
    public QuarantineStoreException(string message)
        : base(message)
    {
    }

    public QuarantineStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
