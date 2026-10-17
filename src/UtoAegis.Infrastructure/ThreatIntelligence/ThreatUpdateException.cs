namespace UtoAegis.Infrastructure.ThreatIntelligence;

public sealed class ThreatUpdateException : Exception
{
    public ThreatUpdateException(string message)
        : base(message)
    {
    }

    public ThreatUpdateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
