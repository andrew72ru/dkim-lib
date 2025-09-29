<?php declare(strict_types=1);

namespace DkimLib;

/**
 * @see https://github.com/trusteddomainproject/OpenDKIM/blob/master/libopendkim/dkim.h
 *
 * #define      DKIM_STAT_OK            0    function completed successfully
 * #define      DKIM_STAT_BADSIG        1   signature available but failed
 * #define      DKIM_STAT_NOSIG         2   no signature available
 * #define      DKIM_STAT_NOKEY         3   public key not found
 * #define      DKIM_STAT_CANTVRFY      4   can't get domain key to verify
 * #define      DKIM_STAT_SYNTAX        5   message is not valid syntax
 * #define      DKIM_STAT_NORESOURCE    6   resource unavailable
 * #define      DKIM_STAT_INTERNAL      7   internal error
 * #define      DKIM_STAT_REVOKED       8   key found, but revoked
 * #define      DKIM_STAT_INVALID       9   invalid function parameter
 * #define      DKIM_STAT_NOTIMPLEMENT  10  function not implemented
 * #define      DKIM_STAT_KEYFAIL       11  key retrieval failed
 * #define      DKIM_STAT_CBREJECT      12  callback requested reject
 * #define      DKIM_STAT_CBINVALID     13  callback gave invalid result
 * #define      DKIM_STAT_CBTRYAGAIN    14  callback says try again later
 * #define      DKIM_STAT_CBERROR       15  callback error
 * #define      DKIM_STAT_MULTIDNSREPLY 16  multiple DNS replies
 * #define      DKIM_STAT_SIGGEN        17  signature generation failed
 */
enum StatusCode: int
{
    case DKIM_STAT_OK = 0;
    case DKIM_STAT_BADSIG = 1;
    case DKIM_STAT_NOSIG = 2;
    case DKIM_STAT_NOKEY = 3;
    case DKIM_STAT_CANTVRFY = 4;
    case DKIM_STAT_SYNTAX = 5;
    case DKIM_STAT_NORESOURCE = 6;
    case DKIM_STAT_INTERNAL = 7;
    case DKIM_STAT_REVOKED = 8;
    case DKIM_STAT_INVALID = 9;
    case DKIM_STAT_NOTIMPLEMENT = 10;
    case DKIM_STAT_KEYFAIL = 11;
    case DKIM_STAT_CBREJECT = 12;
    case DKIM_STAT_CBINVALID = 13;
    case DKIM_STAT_CBTRYAGAIN = 14;
    case DKIM_STAT_CBERROR = 15;
    case DKIM_STAT_MULTIDNSREPLY = 16;
    case DKIM_STAT_SIGGEN = 17;

    public static function getDescription(self | int $statusCode): string
    {
        if (\is_int($statusCode)) {
            $s = self::tryFrom($statusCode);

            if (!$s instanceof self) {
                return 'Unknown status code';
            }

            $statusCode = $s;
        }

        return match ($statusCode) {
            self::DKIM_STAT_OK => 'Passed',
            self::DKIM_STAT_BADSIG => 'Bad signature',
            self::DKIM_STAT_NOSIG => 'No signature found',
            self::DKIM_STAT_NOKEY => 'No key found',
            self::DKIM_STAT_CANTVRFY => 'Can\'t get domain key to verify',
            self::DKIM_STAT_SYNTAX => 'Signature syntax error',
            self::DKIM_STAT_NORESOURCE => 'Resource unavailable',
            self::DKIM_STAT_INTERNAL => 'Internal error',
            self::DKIM_STAT_REVOKED => 'Key found but revoked',
            self::DKIM_STAT_INVALID => 'Invalid parameter',
            self::DKIM_STAT_NOTIMPLEMENT => 'Not implemented',
            self::DKIM_STAT_KEYFAIL => 'Key retrieval failure',
            self::DKIM_STAT_CBREJECT => 'Rejected by callback',
            self::DKIM_STAT_CBINVALID => 'Invalid function parameter',
            self::DKIM_STAT_CBTRYAGAIN => 'Temporary error',
            self::DKIM_STAT_CBERROR => 'Callback error',
            self::DKIM_STAT_MULTIDNSREPLY => 'Multiple DNS replies',
            self::DKIM_STAT_SIGGEN => 'Error generating signature',
        };
    }
}
