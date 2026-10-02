namespace UtoAegis.Infrastructure.Importing;

public sealed class IndicatorImportException : Exception
{
    public IndicatorImportException(string message)
        : base(message)
    {
    }

    public IndicatorImportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
