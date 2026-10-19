using System.Net;
using System.Net.Sockets;

namespace Meshtastic.Mqtt;

/// <summary>
/// An IP range in CIDR notation (<c>10.0.0.0/8</c>, <c>2001:db8::/32</c>) and the test whether an
/// address is inside it.
/// </summary>
/// <remarks>
/// The range is parsed once, at startup: an invalid CIDR is a configuration error, not something the
/// broker finds out while a client is waiting for an answer. A single address without a prefix is a
/// range of one. An IPv4-mapped IPv6 address (<c>::ffff:a.b.c.d</c>) is an IPv4 address in disguise, so
/// it matches the IPv4 ranges.
/// </remarks>
public sealed class IpCidr
{
    readonly byte[] _network;
    readonly int _prefix;

    IpCidr(byte[] network, int prefix, string text)
    {
        _network = network;
        _prefix = prefix;
        Text = text;
    }

    /// <summary>The range as it was written in the config.</summary>
    public string Text { get; }

    /// <summary>How many bits of the address the range covers.</summary>
    public int PrefixLength => _prefix;

    /// <summary>Whether the range is an IPv6 one (an IPv4 range covers 32 bits).</summary>
    public bool IsIpv6 => _network.Length == 16;

    /// <summary>Parses a CIDR range (or a single address, which is a range of one).</summary>
    public static bool TryParse(string? text, out IpCidr? cidr, out string error)
    {
        cidr = null;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "the range is empty";
            return false;
        }

        var trimmed = text.Trim();
        var slash = trimmed.IndexOf('/');
        var addressText = slash < 0 ? trimmed : trimmed[..slash];
        if (!IPAddress.TryParse(addressText, out var address) || address is null)
        {
            error = $"'{trimmed}' is not an IPv4 or IPv6 address";
            return false;
        }

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        int prefix;
        if (slash < 0)
        {
            prefix = maxPrefix;
        }
        else
        {
            var prefixText = trimmed[(slash + 1)..];
            if (!int.TryParse(prefixText, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out prefix))
            {
                error = $"'{trimmed}' has no valid prefix length";
                return false;
            }
            if (prefix < 0 || prefix > maxPrefix)
            {
                error = $"'{trimmed}' has a prefix length outside 0-{maxPrefix}";
                return false;
            }
        }

        var bytes = address.GetAddressBytes();
        // The host bits are cleared: a range is the network, not the first address in it.
        for (var bit = prefix; bit < bytes.Length * 8; bit++)
            bytes[bit / 8] &= (byte)~(1 << (7 - bit % 8));

        cidr = new IpCidr(bytes, prefix, trimmed);
        return true;
    }

    /// <summary>Whether the address is inside the range.</summary>
    public bool Matches(IPAddress? address)
    {
        if (address is null)
            return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // An IPv6 range matches the address as it is (an IPv4-mapped one included).
            if (IsIpv6 && MatchesBytes(address.GetAddressBytes()))
                return true;
            // An IPv4-mapped address is an IPv4 address in disguise: it matches the IPv4 ranges.
            return !IsIpv6 && address.IsIPv4MappedToIPv6 && MatchesBytes(address.MapToIPv4().GetAddressBytes());
        }
        return !IsIpv6 && MatchesBytes(address.GetAddressBytes());
    }

    /// <summary>Whether the address (as the broker writes it) is inside the range.</summary>
    public bool Matches(string? address) =>
        address is not null && IPAddress.TryParse(address, out var parsed) && Matches(parsed);

    bool MatchesBytes(byte[] address)
    {
        var wholeBytes = _prefix / 8;
        for (var i = 0; i < wholeBytes; i++)
        {
            if (address[i] != _network[i])
                return false;
        }
        var restBits = _prefix % 8;
        if (restBits == 0)
            return true;
        var mask = (byte)(0xFF << (8 - restBits));
        return (address[wholeBytes] & mask) == (_network[wholeBytes] & mask);
    }
}
