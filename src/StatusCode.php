<?php declare(strict_types=1);

namespace DkimLib;

enum StatusCode: int
{
    case DKIM_STAT_OK = 0;               // Successful completion
    case DKIM_STAT_BADSIG = 1;           // Signature verification failed
    case DKIM_STAT_NOSIG = 2;            // No signature present
    case DKIM_STAT_NOKEY = 3;            // No key found for signature
    case DKIM_STAT_CANTVRFY = 4;         // Cannot verify (e.g., key or context issue)
    case DKIM_STAT_SYNTAX = 5;           // Signature syntax error
    case DKIM_STAT_NORESOURCE = 6;       // Resource unavailable / out of memory
    case DKIM_STAT_INTERNAL = 7;         // Internal error
    case DKIM_STAT_KEYFAIL = 8;          // Key retrieval failure
    case DKIM_STAT_CBREJECT = 9;         // Rejected by callback
    case DKIM_STAT_MULTIDNSREPLY = 10;   // Multiple DNS replies where single expected
    case DKIM_STAT_INVALID = 11;         // Invalid parameter
    case DKIM_STAT_NOTIMPLEMENT = 12;    // Not implemented
    case DKIM_STAT_TRYAGAIN = 13;        // Temporary failure, try again
    case DKIM_STAT_RESPONSE = 14;        // Response-related failure
    case DKIM_STAT_EXPIRED = 15;         // Signature expired
    case DKIM_STAT_TIMESTAMPSKEW = 16;   // Timestamp skew too great
    case DKIM_STAT_INVALIDHASH = 17;     // Invalid body/hash
    case DKIM_STAT_SIGGEN = 18;          // Error generating signature

    public static function getDescription(self $statusCode): string
    {
        return match ($statusCode) {
            self::DKIM_STAT_OK => 'Successful completion',
            self::DKIM_STAT_BADSIG => 'Signature verification failed',
            self::DKIM_STAT_NOSIG => 'No signature present',
            self::DKIM_STAT_NOKEY => 'No key found for signature',
            self::DKIM_STAT_CANTVRFY => 'Cannot verify (e.g., key or context issue)',
            self::DKIM_STAT_SYNTAX => 'Signature syntax error',
            self::DKIM_STAT_NORESOURCE => 'Resource unavailable / out of memory',
            self::DKIM_STAT_INTERNAL => 'Internal error',
            self::DKIM_STAT_KEYFAIL => 'Key retrieval failure',
            self::DKIM_STAT_CBREJECT => 'Rejected by callback',
            self::DKIM_STAT_MULTIDNSREPLY => 'Multiple DNS replies where single expected',
            self::DKIM_STAT_INVALID => 'Invalid parameter',
            self::DKIM_STAT_NOTIMPLEMENT => 'Not implemented',
            self::DKIM_STAT_TRYAGAIN => 'Temporary failure, try again',
            self::DKIM_STAT_RESPONSE => 'Response-related failure',
            self::DKIM_STAT_EXPIRED => 'Signature expired',
            self::DKIM_STAT_TIMESTAMPSKEW => 'Timestamp skew too great',
            self::DKIM_STAT_INVALIDHASH => 'Invalid body/hash',
            self::DKIM_STAT_SIGGEN => 'Error generating signature',
        };
    }
}
