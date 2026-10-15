namespace UtoAegis.Core.History;

public sealed class ScanHistoryStoreException : Exception
{
    public ScanHistoryStoreException(string message)
        : base(message)
    {
    }

    public ScanHistoryStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
