import dns from 'dns';
import net from 'net';
import http from 'http';
import https from 'https';

interface CIDRRange {
  network: bigint;
  mask: bigint;
  version: 4 | 6;
}

// RFC 1918 and other reserved private IPv4 ranges
const BLOCKED_CIDRS_V4 = [
  '0.0.0.0/8',         // Current network (only valid as source address)
  '10.0.0.0/8',        // RFC 1918 Private-Use
  '100.64.0.0/10',     // RFC 6598 Shared Address Space
  '127.0.0.0/8',       // RFC 1122 Loopback
  '169.254.0.0/16',    // RFC 3927 Link-Local (AWS/GCP metadata endpoints)
  '172.16.0.0/12',     // RFC 1918 Private-Use
  '192.0.0.0/24',      // RFC 6890 IETF Protocol Assignments
  '192.0.2.0/24',      // RFC 5737 Test-Net-1
  '192.88.99.0/24',    // RFC 7526 6to4 Relay Anycast (deprecated)
  '192.168.0.0/16',    // RFC 1918 Private-Use
  '198.18.0.0/15',     // RFC 2544 Benchmarking
  '198.51.100.0/24',   // RFC 5737 Test-Net-2
  '203.0.113.0/24',    // RFC 5737 Test-Net-3
  '224.0.0.0/4',       // RFC 1112 Multicast
  '240.0.0.0/4',       // RFC 1112 Reserved
  '255.255.255.255/32' // RFC 919 Broadcast
];

const BLOCKED_CIDRS_V6 = [
  '::/128',            // Unspecified Address
  '::1/128',           // Loopback Address
  '100::/64',          // Discard-Only Address Block (RFC 6666)
  '2001:db8::/32',     // Documentation (RFC 3849)
  'fc00::/7',          // Unique-Local (RFC 4193)
  'fe80::/10',         // Link-Local Unicast (RFC 4291)
  'ff00::/8'           // Multicast (RFC 4291)
];

function ipV4ToBigInt(ip: string): bigint {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address format: ${ip}`);
  }
  const bigintParts = parts.map(part => {
    const num = parseInt(part, 10);
    // Mitigate octal interpretation bypasses (e.g., "012" parsed as octal vs decimal)
    if (isNaN(num) || num < 0 || num > 255 || String(num) !== part) {
      throw new Error(`Invalid or non-canonical IPv4 octet: ${part}`);
    }
    return BigInt(num);
  });
  return bigintParts.reduce((acc, octet) => (acc << 8n) + octet, 0n);
}

function ipV6ToBigInt(ip: string): bigint {
  let fullIp = ip;
  if (ip.includes('::')) {
    const parts = ip.split('::');
    if (parts.length > 2) {
      throw new Error(`Invalid IPv6 formatting: multiple '::' markers in ${ip}`);
    }
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 0) {
      throw new Error(`Invalid IPv6 address segment length: ${ip}`);
    }
    const middle = Array(missing).fill('0');
    fullIp = [...left, ...middle, ...right].join(':');
  }

  const parts = fullIp.split(':');
  if (parts.length !== 8) {
    throw new Error(`Invalid IPv6 address segment count: ${ip}`);
  }

  const segments = parts.map(part => {
    if (part === '') return 0n;
    const num = parseInt(part, 16);
    if (isNaN(num) || num < 0 || num > 0xFFFF) {
      throw new Error(`Invalid IPv6 hexadecimal segment: ${part}`);
    }
    return BigInt(num);
  });

  return segments.reduce((acc, seg) => (acc << 16n) + seg, 0n);
}

function parseCIDR(cidr: string): CIDRRange {
  const [ip, prefixStr] = cidr.split('/');
  const isV6 = ip.includes(':');
  const version = isV6 ? 6 : 4;
  const totalBits = version === 6 ? 128 : 32;
  const prefixLength = prefixStr ? parseInt(prefixStr, 10) : totalBits;

  if (isNaN(prefixLength) || prefixLength < 0 || prefixLength > totalBits) {
    throw new Error(`Invalid CIDR prefix length: ${prefixStr}`);
  }

  const ipBigInt = version === 6 ? ipV6ToBigInt(ip) : ipV4ToBigInt(ip);
  // Construct mask shifting 1s to the left
  const mask = ((1n << BigInt(prefixLength)) - 1n) << BigInt(totalBits - prefixLength);
  const network = ipBigInt & mask;

  return { network, mask, version };
}

// Compile the lists at module startup
const parsedBlockedRanges: CIDRRange[] = [
  ...BLOCKED_CIDRS_V4,
  ...BLOCKED_CIDRS_V6
].map(parseCIDR);

export function isBlockedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 0) {
    // If the string is not a valid IP, block it out of precaution
    return true;
  }

  try {
    const ipBigInt = version === 6 ? ipV6ToBigInt(ip) : ipV4ToBigInt(ip);
    for (const range of parsedBlockedRanges) {
      if (range.version === version) {
        if ((ipBigInt & range.mask) === range.network) {
          return true;
        }
      }
    }
  } catch {
    // Fail-closed security stance: block connection if parsing throws an error
    return true;
  }

  return false;
}

export type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  address: string | dns.LookupAddress[],
  family?: number
) => void;


export function ssrfSafeLookup(
  hostname: string,
  options: dns.LookupOptions & { all?: boolean } | number | undefined | null,
  callback?: LookupCallback
): void {
  let actualCallback: LookupCallback;
  let actualOptions: dns.LookupOptions & { all?: boolean } = {};

  if (typeof options === 'function') {
    actualCallback = options as unknown as LookupCallback;
  } else if (typeof callback === 'function') {
    actualCallback = callback;
    if (typeof options === 'number') {
      actualOptions = { family: options };
    } else if (options) {
      actualOptions = options;
    }
  } else {
    throw new Error('A callback function is required for dns lookup execution');
  }

  dns.lookup(hostname, actualOptions as any, (err, address, family) => {
    if (err) {
      return actualCallback(err, address, family);
    }

    try {
      if (actualOptions.all) {
        const addresses = address as dns.LookupAddress[];
        for (const addrObj of addresses) {
          if (isBlockedIp(addrObj.address)) {
            const ssrfError = new Error(`SSRF Blocked: Resolving to local/private range: ${addrObj.address}`);
            (ssrfError as any).code = 'ERR_SSRF_FORBIDDEN_IP';
            return actualCallback(ssrfError, []);
          }
        }
        return actualCallback(null, addresses);
      } else {
        const addrStr = address as string;
        if (isBlockedIp(addrStr)) {
          const ssrfError = new Error(`SSRF Blocked: Resolving to local/private range: ${addrStr}`);
          (ssrfError as any).code = 'ERR_SSRF_FORBIDDEN_IP';
          return actualCallback(ssrfError, '', family);
        }
        return actualCallback(null, addrStr, family);
      }
    } catch (validationErr: any) {
      return actualCallback(validationErr, '', family);
    }
  });
}

export const ssrfSafeHttpAgent = new http.Agent({ lookup: ssrfSafeLookup, keepAlive: true });
export const ssrfSafeHttpsAgent = new https.Agent({ lookup: ssrfSafeLookup, keepAlive: true });