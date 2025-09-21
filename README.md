# DKIM verification library for PHP

A tiny PHP library to verify DKIM signatures of RFC‑2822 email messages using the OpenDKIM C library through PHP FFI.

This package provides a simple wrapper around libopendkim’s verification API, exposing a single entry point (`CheckDKIM`) and a typed enum (`StatusCode`) that mirrors libopendkim’s dkim_stat return codes.

## Features
- Verifies DKIM signatures via `libopendkim` (OpenDKIM)
- Pure PHP API powered by PHP FFI (no PHP extensions besides FFI required)
- Detailed result codes mapped to an enum (`StatusCode`) with human‑readable descriptions
- Optional DNS TXT record check for the DKIM selector before full verification
- Configurable `libopendkim` library path via constructor

## Requirements
- PHP 8.1+
- PHP FFI enabled (ext-ffi)
- OpenDKIM runtime library available at runtime (shared library, e.g. libopendkim.so or .dylib)

See the `composer.json` for exact PHP and extension constraints.

## Installation

1. Install via Composer

```
composer require andrew72ru/dkim-lib
```

2. Install the OpenDKIM shared library on your system

- Debian/Ubuntu:
  - `sudo apt-get update && sudo apt-get install -y opendkim libopendkim-dev`
  - The runtime typically installs `libopendkim.so.11` under `/usr/lib` or `/usr/lib/x86_64-linux-gnu`.
- Alpine Linux:
  - `apk add opendkim opendkim-dev`
- CentOS/RHEL (using EPEL):
  - `yum install opendkim opendkim-devel`
- macOS (Homebrew):
  - `brew install opendkim`

If the library is installed in a non‑standard location, you can either:
- pass the full path(s) to the `CheckDKIM` constructor (recommended), or
- adjust your loader path (e.g. `LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on macOS).

By default, the loader attempts a few common names/paths (e.g. `libopendkim.so.11`). When you pass an array of paths, they will be tried in the given order.

3. Ensure FFI is enabled

FFI must be enabled for CLI and/or FPM where you run verification. In php.ini:

```
; for development you can set
ffi.enable = true
; for production consider preload policies
; ffi.enable = preload
```

## Usage
Below is a minimal example showing how to verify a raw email string and interpret the result:

```php
<?php declare(strict_types=1);

require 'vendor/autoload.php';

use DkimLib\{CheckDKIM,StatusCode};
use DkimLib\Exception;

$rawEmail = file_get_contents('path/to/message.eml'); // must include headers and body

$checker = new CheckDKIM(); // default search paths
// Or specify custom library path(s):
// $checker = new CheckDKIM(['/opt/opendkim/lib/libopendkim.so.11', '/usr/local/lib/libopendkim.so']);

try {
    // The second argument controls a preliminary DNS TXT lookup for the DKIM selector (default: true)
    $code = $checker->validate($rawEmail, true); // returns an int matching StatusCode case
} catch (Exception\InitializationException $e) {
    echo 'Initialization error: ' . $e->getMessage(); // OpenDKIM library could not be loaded

    die(1);
} catch (Exception\LibraryException $e) {
    echo 'Library error: ' . $e->getMessage(); // An error reported by libopendkim or the wrapper

    die(1);
}

$status = StatusCode::from($code);

echo 'Result: ' . $status->name . PHP_EOL;
echo 'Description: ' . StatusCode::getDescription($status) . PHP_EOL;
```

Notes:
- The input must be a complete [RFC‑2822 message](https://datatracker.ietf.org/doc/html/rfc2822) (headers and body). The library will feed headers and body to libopendkim incrementally.
- Setting `$checkDnsRecord` to true performs a quick DNS TXT lookup for `<selector>._domainkey.<domain>` extracted from the DKIM-Signature header. If the record is missing, the method returns `StatusCode::DKIM_STAT_KEYFAIL` early.

## Return codes
All return codes come from the StatusCode enum, which mirrors libopendkim’s `dkim_stat`. Use `StatusCode::getDescription()` for a human‑readable explanation.

Common cases include:
- `DKIM_STAT_OK` — successful verification
- `DKIM_STAT_BADSIG` — signature verification failed
- `DKIM_STAT_NOSIG` — no DKIM‑Signature header present
- `DKIM_STAT_NOKEY` — no key found for the signature
- `DKIM_STAT_KEYFAIL` — key retrieval failure (e.g., DNS TXT missing)

For the full list, see the StatusCode enum in `src/StatusCode.php` or the upstream docs: http://www.opendkim.org/staging/libopendkim/index.html

## Acknowledgements
- OpenDKIM (libopendkim)
- Inspired by the libopendkim C API; this package only wraps verification via PHP FFI.
