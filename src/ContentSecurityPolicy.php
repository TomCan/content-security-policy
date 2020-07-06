<?php


namespace TomCan\Csp;


use TomCan\Csp\Exception\CspInvalidDirectiveException;
use TomCan\Csp\Exception\CspInvalidSourceListItemException;

class ContentSecurityPolicy
{

    const DIRECTIVE_BASE_URI = 'base-uri';
    const DIRECTIVE_CONNECT_SRC = 'connect-src';
    const DIRECTIVE_DEFAULT_SRC = 'default-src';
    const DIRECTIVE_CHILD_SRC = 'child-src';
    const DIRECTIVE_FONT_SRC = 'font-src';
    const DIRECTIVE_FORM_ACTION = 'form-action';
    const DIRECTIVE_FRAME_ANCESTORS = 'frame-ancestors';
    const DIRECTIVE_FRAME_SRC = 'frame-src';
    const DIRECTIVE_IMG_SRC = 'img-src';
    const DIRECTIVE_MANIFEST_SRC = 'manifest-src';
    const DIRECTIVE_MEDIA_SRC = 'media-src';
    const DIRECTIVE_NAVIGATE_TO = 'navigate-to';
    const DIRECTIVE_OBJECT_SRC = 'object-src';
    const DIRECTIVE_PLUGIN_TYPES = 'plugin-types';
    const DIRECTIVE_PREFETCH_SRC = 'prefetch-src';
    const DIRECTIVE_REPORT_TO = 'report-to';
    const DIRECTIVE_REPORT_URI = 'report-uri';
    const DIRECTIVE_SANDBOX = 'sandbox';
    const DIRECTIVE_SCRIPT_SRC = 'script-src';
    const DIRECTIVE_SCRIPT_SRC_ATTR = 'script-src-attr';
    const DIRECTIVE_SCRIPT_SRC_ELEM = 'script-src-elem';
    const DIRECTIVE_STYLE_SRC = 'style-src';
    const DIRECTIVE_STYLE_SRC_ATTR = 'style-src-attr';
    const DIRECTIVE_STYLE_SRC_ELEM = 'style-src-elem';
    const DIRECTIVE_UPGRADE_INSECURE_REQUESTS = 'upgrade-insecure-requests';
    const DIRECTIVE_WORKER_SRC = 'worker-src';

    const VALID_DIRECTIVES = [
        self::DIRECTIVE_BASE_URI,
        self::DIRECTIVE_CONNECT_SRC,
        self::DIRECTIVE_CHILD_SRC,
        self::DIRECTIVE_DEFAULT_SRC,
        self::DIRECTIVE_FONT_SRC,
        self::DIRECTIVE_FORM_ACTION,
        self::DIRECTIVE_FRAME_ANCESTORS,
        self::DIRECTIVE_FRAME_SRC,
        self::DIRECTIVE_IMG_SRC,
        self::DIRECTIVE_MANIFEST_SRC,
        self::DIRECTIVE_MEDIA_SRC,
        self::DIRECTIVE_NAVIGATE_TO,
        self::DIRECTIVE_OBJECT_SRC,
        self::DIRECTIVE_PLUGIN_TYPES,
        self::DIRECTIVE_PREFETCH_SRC,
        self::DIRECTIVE_REPORT_TO,
        self::DIRECTIVE_REPORT_URI,
        self::DIRECTIVE_SANDBOX,
        self::DIRECTIVE_SCRIPT_SRC,
        self::DIRECTIVE_SCRIPT_SRC_ATTR,
        self::DIRECTIVE_SCRIPT_SRC_ELEM,
        self::DIRECTIVE_STYLE_SRC,
        self::DIRECTIVE_STYLE_SRC_ATTR,
        self::DIRECTIVE_STYLE_SRC_ELEM,
        self::DIRECTIVE_UPGRADE_INSECURE_REQUESTS,
        self::DIRECTIVE_WORKER_SRC,
    ];

    const MODE_STRICT = 0;
    const MODE_LOOSE = 1;

    const SANDBOX_ALLOW_FORMS = 'allow-forms';
    const SANDBOX_ALLOW_MODALS = 'allow-modals';
    const SANDBOX_ALLOW_ORIENTATION_LOCK = 'allow-orientation-lock';
    const SANDBOX_ALLOW_POINTER_LOCK = 'allow-pointer-lock';
    const SANDBOX_ALLOW_POPUPS = 'allow-popups';
    const SANDBOX_ALLOW_POPUPS_TO_ESCAPE_SANDBOX = 'allow-popups-to-escape-sandbox';
    const SANDBOX_ALLOW_PRESENTATION = 'allow-presentation';
    const SANDBOX_ALLOW_SAME_ORIGIN = 'allow-same-origin';
    const SANDBOX_ALLOW_SCRIPTS = 'allow-scripts';
    const SANDBOX_ALLOW_TOP_NAVIGATION = 'allow-top-navigation';

    const VALID_SANDBOX_OPTIONS = [
        self::SANDBOX_ALLOW_FORMS,
        self::SANDBOX_ALLOW_MODALS,
        self::SANDBOX_ALLOW_ORIENTATION_LOCK,
        self::SANDBOX_ALLOW_POINTER_LOCK,
        self::SANDBOX_ALLOW_POPUPS,
        self::SANDBOX_ALLOW_POPUPS_TO_ESCAPE_SANDBOX,
        self::SANDBOX_ALLOW_PRESENTATION,
        self::SANDBOX_ALLOW_SAME_ORIGIN,
        self::SANDBOX_ALLOW_SCRIPTS,
        self::SANDBOX_ALLOW_TOP_NAVIGATION,
    ];

    // specs define base64-value as 1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )
    // basic matching, need at least 1 character, ending in 0, 1 or 2 =
    const PAT_BASE64 = '[A-Za-z0-9+\/]+={0,2}';

    const PAT_SOURCE_NONCE = "'nonce-".self::PAT_BASE64."'";
    const PAT_SOURCE_NONE = "'none'";
    const PAT_PLUGIN_TYPE = '[-\w.]+/[-\w.\+]+$';
    const PAT_SOURCE_SELF = "'self'";
    const PAT_SOURCE_SHA = "'sha(256|384|512)-".self::PAT_BASE64."'";
    const PAT_SOURCE_STRICT_DYNAMIC = "'strict-dynamic'";
    const PAT_SOURCE_UNSAFE_EVAL = "'unsafe-eval'";
    const PAT_SOURCE_UNSAFE_HASHES = "'unsafe-hashes'";
    const PAT_SOURCE_UNSAFE_INLINE = "'unsafe-inline'";

    const OUTPUT_FULL_HEADER = 0;
    const OUTPUT_VALUE_ONLY = 1;

    private $directives = [];
    private $mode;

    private bool $reportOnly = false;

    private $outputMode = self::OUTPUT_FULL_HEADER;

    public static function fromCspString(string $cspString, array $options = []): ContentSecurityPolicy
    {
        $parser = new CspParser(
            $options['mode'] ?? self::MODE_STRICT
        );
        return $parser->parse($cspString);
    }

    public function __construct(int $mode)
    {
        if ($mode != self::MODE_STRICT && $mode != self::MODE_LOOSE) {
            throw new \InvalidArgumentException('Invalid mode specified');
        }
        $this->mode = $mode;
    }

    public function addToDirective(string $directive, ?string $value): void
    {
        $directive = trim(strtolower($directive));

        if (!in_array($directive, self::VALID_DIRECTIVES)) {
            throw new CspInvalidDirectiveException($directive);
        }

        switch ($directive) {
            case self::DIRECTIVE_SANDBOX:
                $this->addToSandbox($value);
                break;
            case self::DIRECTIVE_UPGRADE_INSECURE_REQUESTS:
                $this->addNoValueDirective($directive);
                break;

            default:
                $this->addToBasicDirective($directive, $value);
        }

    }

    private function addToBasicDirective(string $directive, string $value)
    {
        // check to see if this is a standard source list item
        if (preg_match("/^'.*'$/", $value)) {
            // check to see if source list item is allowed for this directive

            // start with NONE and SELF
            $patterns = [
                self::PAT_SOURCE_NONE,
                self::PAT_SOURCE_SELF,
            ];
            switch ($directive) {
                case 'script-src':
                case 'script-src-attr':
                case 'script-src-elem':
                case 'base-uri':
                case 'child-src':
                case 'form-action':
                case 'navigate-to':
                    $patterns[] = self::PAT_SOURCE_UNSAFE_EVAL;
                    $patterns[] = self::PAT_SOURCE_UNSAFE_INLINE;
                    $patterns[] = self::PAT_SOURCE_SHA;
                    $patterns[] = self::PAT_SOURCE_NONCE;
                    $patterns[] = self::PAT_SOURCE_STRICT_DYNAMIC;
                    $patterns[] = self::PAT_SOURCE_UNSAFE_HASHES;
                    break;

                case 'worker-src':
                case 'manifest-src':
                case 'prefetch-src':
                    $patterns[] = self::PAT_SOURCE_UNSAFE_EVAL;
                    $patterns[] = self::PAT_SOURCE_UNSAFE_INLINE;
                    $patterns[] = self::PAT_SOURCE_SHA;
                    $patterns[] = self::PAT_SOURCE_NONCE;
                    $patterns[] = self::PAT_SOURCE_UNSAFE_HASHES;
                    break;

                case 'plugin-type':
                    $patterns = [
                        self::PAT_SOURCE_NONE,
                        self::PAT_PLUGIN_TYPE,
                    ];
                    break;

                case 'style-src':
                case 'style-src-attr':
                case 'style-src-elem':
                    $patterns[] = self::PAT_SOURCE_UNSAFE_INLINE;
                    $patterns[] = self::PAT_SOURCE_SHA;
                    $patterns[] = self::PAT_SOURCE_NONCE;
                    break;

                case 'report-uri':
                case 'report-to':
                    // no special values allowed
                    $patterns = [];
                    break;
            }

            $predefined_pattern = "/^(" . implode('|',$patterns) . ")$/i";
            if (!preg_match($predefined_pattern, $value)) {
                if ($this->mode == self::MODE_STRICT) {
                    throw new CspInvalidSourceListItemException(sprintf("\"%s\" is not a valid source list item for directive \"%s\" %s", $value, $directive, $predefined_pattern));
                } else {
                    return;
                }
            }
        }

        if (isset($this->directives[$directive])) {
            $this->directives[$directive][$value] = $value;
        } else {
            $this->directives[$directive] = [$value => $value];
        }
    }

    private function addToSandbox(?string $value)
    {
        if (!isset($this->directives[self::DIRECTIVE_SANDBOX])) {
            $this->directives[self::DIRECTIVE_SANDBOX] = [];
        }
        if ($value !== null) {
            if (in_array($value, self::VALID_SANDBOX_OPTIONS)) {
                $this->directives[self::DIRECTIVE_SANDBOX][$value] = $value;
            } else {
                throw new CspInvalidSourceListItemException(sprintf("'%s' is not a valid source list item for directive '%s'", $value, self::DIRECTIVE_SANDBOX));
            }
        }
    }

    private function addNoValueDirective($directive)
    {
        $this->directives[$directive] = [];
    }

    public function setReportOnly(bool $reportOnly): void
    {
        $this->reportOnly = $reportOnly;
    }

    public function isReportOnly(): bool
    {
        return $this->reportOnly;
    }

    public function getDirectives(): array
    {
        return $this->directives;
    }

    public function getDirective(string $directive): ?array
    {
        if (isset($this->directives[$directive])) {
            return $this->directives[$directive];
        } else {
            return null;
        }
    }

    public function getMode(): int
    {
        return $this->mode;
    }

    public function setMode(int $mode): void
    {
        $this->mode = $mode;
    }

    public function getOutputMode(): int
    {
        return $this->outputMode;
    }

    public function setOutputMode(int $outputMode): void
    {
        $this->outputMode = $outputMode;
    }

    public function __toString(): string
    {
        $output = "";
        foreach (self::VALID_DIRECTIVES as $directive) {
            if (isset($this->directives[$directive]))
            $output .= trim($directive . ' ' . implode(' ', $this->directives[$directive])) . '; ';
        }

        if ($this->outputMode == self::OUTPUT_FULL_HEADER) {
            if ($this->reportOnly) {
                return 'Content-Security-Policy-Report-Only: ' . trim($output);
            } else {
                return 'Content-Security-Policy: ' . trim($output);
            }
        } else {
            return trim($output);
        }
    }
}