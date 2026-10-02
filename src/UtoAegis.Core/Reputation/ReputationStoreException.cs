namespace UtoAegis.Core.Reputation;

public sealed class ReputationStoreException : Exception
{
    public ReputationStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ReputationStoreException(string message)
        : base(message)
    {
    }
}
