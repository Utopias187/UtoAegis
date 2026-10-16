namespace UtoAegis.Service;

public sealed class ServiceConfigurationException : Exception
{
    public ServiceConfigurationException(string message)
        : base(message)
    {
    }

    public ServiceConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
