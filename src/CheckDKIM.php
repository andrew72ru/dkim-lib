<?php declare(strict_types=1);

namespace DkimLib;

use DkimLib\Exception\{InitializationException, LibraryException};

class CheckDKIM
{
    private static array $paths = [
        'libopendkim.so.11',
        '/usr/lib/x86_64-linux-gnu/libopendkim.so.11',
        '/usr/lib/libopendkim.so.11',
        'libopendkim.so',
    ];

    private array $potentialPaths;

    public function __construct(array $libPath = [])
    {
        $this->potentialPaths = $libPath === [] ? self::$paths : $libPath;
    }

    /**
     * @param string $content RFC-2822 email message
     *
     * @throws InitializationException|LibraryException
     *
     * @noinspection PhpUndefinedMethodInspection
     * @noinspection StaticInvocationViaThisInspection
     */
    public function validate(string $content, bool $checkDnsRecord = true): int
    {
        $library = $this->init();
        $validator = $library->dkim_init(null, null);

        if ($validator === null) {
            throw new LibraryException('dkim_init() failed');
        }

        $context = $library->dkim_verify($validator, null, null, \FFI::addr($library->new('int')));
        if ($context === null) {
            throw new LibraryException('dkim_verify() failed to create context');
        }

        $headers = $this->processHeaders($this->getHeaders($content));

        foreach ($headers as $header) {
            $headerCRLF = \sprintf("%s\r\n", $header);
            $length = \strlen($headerCRLF);
            /** @var \FFI\CData $buffer */
            $buffer = $library->new(\sprintf('unsigned char[%s]', $length + 1));
            \FFI::memcpy($buffer, $headerCRLF, $length);
            $buffer[$length] = 0;

            $rc = $library->dkim_header($context, $buffer, $length);
            if ($rc !== 0) { // DKIM_STAT_OK
                throw new LibraryException(\sprintf('The `dkim_header()` failed with status %d: %s', (int) $rc, $header));
            }
        }

        $rc = $library->dkim_eoh($context);
        if ($rc !== 0) {
            return (int) $rc;
        }

        if ($checkDnsRecord === true) {
            $signHeaders = \array_filter($headers, static function (string $header): bool {
                return \str_starts_with($header, 'DKIM-Signature');
            });

            $signHeader = \reset($signHeaders);
            if (!\is_string($signHeader)) {
                return StatusCode::DKIM_STAT_NOKEY->value;
            }

            $dns = $this->getDnsRecord($signHeader);
            if ($dns === null) {
                return StatusCode::DKIM_STAT_KEYFAIL->value; // Key retrieval failure
            }
        }

        $body = $this->getBody($content);
        if ($body !== null) {
            $bodyLines = \explode("\n", $body);
            foreach ($bodyLines as $bodyLine) {
                $bodyLineCRLF = \sprintf("%s\r\n", $bodyLine);
                $buffer = $library->new(\sprintf('unsigned char[%s]', \strlen($bodyLineCRLF)));
                \FFI::memcpy($buffer, $bodyLineCRLF, \strlen($bodyLineCRLF));
                $rc = $library->dkim_body($context, $buffer, \strlen($bodyLineCRLF));
                if ($rc !== 0) {
                    throw new LibraryException(\sprintf('dkim_body() failed with status %d', (int) $rc));
                }
            }
        }
        try {
            $final = $library->dkim_eom($context, \FFI::addr($library->new('unsigned char *')));
        } catch (\Throwable $e) {
            throw new LibraryException($e->getMessage(), previous: $e);
        }

        return StatusCode::from((int) $final)->value;
    }

    public function getDnsRecord(string $dkimHeader): string | null
    {
        $dkimHeader = \str_replace(["\r\n", "\n", "\t", ' '], '', $dkimHeader);
        $parts = \explode(';', $dkimHeader);

        $domain = null;
        $selector = null;
        foreach ($parts as $part) {
            [$tag, $value] = \explode('=', $part, 2) + [null, null];
            if ($tag === 'd') {
                $domain = $value;
            }
            if ($tag === 's') {
                $selector = $value;
            }
        }
        if ($domain === null || $selector === null) {
            return null;
        }
        $fqdn = \sprintf('%s._domainkey.%s', $selector, $domain);
        $record = \dns_get_record($fqdn, \DNS_TXT);
        if (!\is_array($record)) {
            return null;
        }
        $txt = $record[0]['txt'] ?? null;

        return \is_string($txt) ? $txt : null;
    }

    /**
     * @throws LibraryException
     */
    private function getHeaders(string $raw): string
    {
        $normalized = \str_replace(["\r\n", "\r"], "\n", $raw);
        [$header] = \explode("\n\n", $normalized, 2) + [null, null];

        if ($header === null) {
            throw new LibraryException('Unable to load a message headers');
        }

        return $header;
    }

    private function getBody(string $raw): string | null
    {
        $normalized = \str_replace(["\r\n", "\r"], "\n", $raw);
        [,$body] = \explode("\n\n", $normalized, 2) + [null, null];

        return $body;
    }

    /**
     * @return string[]
     */
    private function processHeaders(string $headers): array
    {
        $lines = \explode("\n", $headers);
        $result = [];
        $current = null;
        foreach ($lines as $i => $line) {
            // Skip a possible Unix mbox 'From' line at the very top (not an RFC822 header)
            if ($i === 0 && \str_starts_with($line, 'From ') && !\str_contains($line, ':')) {
                continue;
            }

            if ($line === '') {
                continue;
            }

            $continue = \str_starts_with($line, ' ') || \str_starts_with($line, "\t");
            if ($continue && $current === null) {
                // Ignore orphaned continuation
                continue;
            }
            if ($continue === true) {
                $current .= "\r\n" . $line;
            }

            if ($continue === false) {
                if ($current !== null) {
                    $result[] = $current;
                }
                if (!\str_contains($line, ':')) {
                    $current = null;
                    continue;
                }
                $current = $line;
            }
        }

        if ($current !== null) {
            $result[] = $current;
        }

        return $result;
    }

    /**
     * @throws InitializationException
     */
    private function init(): \FFI
    {
        $cdef = <<<CDEF
        typedef int dkim_stat;
        typedef struct dkim_lib DKIM_LIB;
        typedef struct dkim DKIM;
        
        DKIM_LIB *dkim_init(void *(*mallocf)(void *, size_t), void (*freef)(void *, void *));
        void dkim_close(DKIM_LIB *lib);
        DKIM *dkim_verify(DKIM_LIB *lib, unsigned char *id, void *memclosure, dkim_stat *statusp);
        dkim_stat dkim_header(DKIM *dkim, unsigned char *hdr, size_t len);
        dkim_stat dkim_eoh(DKIM *dkim);
        dkim_stat dkim_body(DKIM *dkim, unsigned char *bodyp, size_t len);
        dkim_stat dkim_eom(DKIM *dkim, unsigned char **bodyhash);
        void dkim_free(DKIM *dkim);
        dkim_stat dkim_options(DKIM_LIB *dkimlib, int op, int opt, void *ptr, size_t len);
CDEF;

        $ffi = null;
        $loadErrors = [];
        foreach ($this->potentialPaths as $libName) {
            try {
                $ffi = \FFI::cdef($cdef, $libName);
                break;
            } catch (\Throwable $e) {
                $loadErrors[] = $libName . ': ' . $e->getMessage();
            }
        }

        if (!$ffi instanceof \FFI) {
            throw new InitializationException(\sprintf('Failed to load a library: %s', \implode('; ', $loadErrors)));
        }

        return $ffi;
    }
}
