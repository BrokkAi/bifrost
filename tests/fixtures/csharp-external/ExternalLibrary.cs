using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Fixture.Api;

public interface IClient
{
    string Send(Message message);
}

public class Client<T> : IClient
{
    public string Name { get; } = "fixture";
    public static int Instances;
    public Client() { }
    public string Send(Message message) => message.Text;
    public U Convert<U>(U value) => value;
    protected virtual int RetryCount => 3;
    public class Nested { }
    protected class ProtectedNested { }
    private class PrivateNested { }
}

public readonly struct Message
{
    public string Text { get; }
    public Message(string text) => Text = text;
}

public enum Status { Ready, Failed }
public delegate void MessageHandler(Message message);

public sealed class GenericSurface : IEnumerable<Message>
{
    public Dictionary<string, List<Message>> Lookup { get; } = new();
    public Message[] Copy(Message[] input) => input;
    public IEnumerator<Message> GetEnumerator() => Lookup.Values.SelectMany(messages => messages).GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

internal class InternalOnly { public class LeakedNested { } }
