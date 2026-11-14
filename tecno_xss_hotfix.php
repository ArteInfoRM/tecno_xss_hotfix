<?php
/**
 *  2009-2026 Tecnoacquisti.com
 *
 *  For support feel free to contact us on our website at http://www.tecnoacquisti.com
 *
 *  @author    Arte e Informatica <helpdesk@tecnoacquisti.com>
 *  @copyright 2009-2026 Arte e Informatica
 *  @license   https://opensource.org/licenses/MIT  MIT License
 *  @version   1.1.1
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class Tecno_Xss_Hotfix extends Module
{
    // Smarty token: closing brace is part of the tag, so these two strings do NOT overlap
    const VULNERABLE_TOKEN = '{$thread->email}';
    const PATCHED_TOKEN    = '{$thread->email|escape:\'html\':\'UTF-8\'}';

    // Validate.php isEmail(): Symfony validation mode flag
    const VALIDATE_VULNERABLE = "'mode' => 'loose',";
    const VALIDATE_PATCHED    = "'mode' => 'strict',";

    // Validate.php isEmail(): egulias EmailValidator guard before return
    const VALIDATE_VULNERABLE_17 = 'return !empty($email) && (new EmailValidator())->isValid(';
    const VALIDATE_PATCHED_17    = "if (!empty(\$email) && preg_match('/[<>\"]/', \$email)) { return false; }\n        return !empty(\$email) && (new EmailValidator())->isValid(";
    const VALIDATE_PATCHED_17_SENTINEL = "preg_match('/[<>\"]/', \$email)";

    const BACKUP_SUFFIX = '.tecno-hotfix-backup';

    public function __construct()
    {
        $this->name          = 'tecno_xss_hotfix';
        $this->tab           = 'administration';
        $this->version       = '1.1.1';
        $this->author        = 'Tecnoacquisti.com';
        $this->need_instance = 0;
        $this->bootstrap     = true;

        parent::__construct();

        $this->displayName = $this->l('XSS Hotfix GHSA-w9f3-qc75-qgx9');
        $this->description = $this->l('Security patch for stored XSS in Customer Threads BO (CVE 9.3/10, CWE-79)');
        $this->ps_versions_compliancy = ['min' => '1.7.0.0', 'max' => '9.99.99'];
    }

    public function install()
    {
        if (!parent::install()) {
            return false;
        }
        $this->applyPatches();
        return true;
    }

    public function uninstall()
    {
        // Patch on template is INTENTIONALLY permanent: removing the module does NOT revert the fix.
        return parent::uninstall();
    }

    // -------------------------------------------------------------------------
    // Path helpers  (prefixed to avoid conflicts with ModuleCore method names)
    // -------------------------------------------------------------------------

    protected function getXssTplPath()
    {
        // _PS_ADMIN_DIR_ is only defined in HTTP admin context, never in CLI
        if (!defined('_PS_ADMIN_DIR_')) {
            return '';
        }
        return _PS_ADMIN_DIR_ . '/themes/default/template/controllers/customer_threads/helpers/view/view.tpl';
    }

    protected function getValidateClassPath()
    {
        return _PS_ROOT_DIR_ . '/classes/Validate.php';
    }

    protected function getOverrideClassPath()
    {
        return _PS_ROOT_DIR_ . '/override/classes/Validate.php';
    }

    // -------------------------------------------------------------------------
    // Override detection
    // -------------------------------------------------------------------------

    protected function hasIsEmailOverride()
    {
        $path = $this->getOverrideClassPath();
        if (!file_exists($path)) {
            return false;
        }
        $content = @file_get_contents($path);
        return $content !== false && (bool) preg_match('/function\s+isEmail\s*\(/', $content);
    }

    // -------------------------------------------------------------------------
    // Patching logic
    // -------------------------------------------------------------------------

    /**
     * Patch the BO customer_threads view template.
     * Replaces ALL bare {$thread->email} with the escaped version.
     * Creates a .tecno-hotfix-backup before writing.
     *
     * @return array{status:string, message:string}
     */
    protected function patchTemplate()
    {
        $path = $this->getXssTplPath();

        if ($path === '') {
            return ['status' => 'skipped_cli', 'message' => $this->l('Template patch skipped: _PS_ADMIN_DIR_ not available in CLI context. Open the module configuration page in the Back-Office to apply.')];
        }
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        $content = file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }

        if (strpos($content, self::VULNERABLE_TOKEN) === false) {
            $status = $this->getTemplatePatchStatus();
            if ($status['status'] === 'patched') {
                $status['status'] = 'already_patched';
            }

            return $status;
        }
        if (!is_writable($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not writable: %s'), $path)];
        }

        $backupPath = $path . self::BACKUP_SUFFIX;
        if (!copy($path, $backupPath)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot create backup: %s'), $backupPath)];
        }

        $patched = str_replace(self::VULNERABLE_TOKEN, self::PATCHED_TOKEN, $content);
        if (file_put_contents($path, $patched) === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot write patched file: %s'), $path)];
        }

        return ['status' => 'patched', 'message' => sprintf($this->l('Template patched successfully. Backup: %s'), $backupPath)];
    }

    /**
     * Patch only recognized vulnerable isEmail() implementations without an override.
     *
     * @return array{status:string, message:string}
     */
    protected function patchValidate()
    {
        if ($this->hasIsEmailOverride()) {
            return [
                'status'  => 'skipped_override',
                'message' => sprintf(
                    $this->l('Skipped: isEmail() override detected in %s. Apply the fix manually (see below).'),
                    $this->getOverrideClassPath()
                ),
            ];
        }

        $path = $this->getValidateClassPath();

        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Validate.php not found: %s'), $path)];
        }
        $content = file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read Validate.php: %s'), $path)];
        }

        $inspection = $this->inspectEmailValidator($content);
        if ($inspection['status'] !== 'vulnerable') {
            $status = $this->getValidatorInspectionStatus($inspection);
            if ($status['status'] === 'patched') {
                $status['status'] = 'already_patched';
            }

            return $status;
        }
        if (!is_writable($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Validate.php not writable: %s'), $path)];
        }

        $body = $inspection['body'];
        if ($inspection['kind'] === 'egulias') {
            $guard = substr(self::VALIDATE_PATCHED_17, 0, -strlen(self::VALIDATE_VULNERABLE_17));
            $body = "\n        " . $guard . ltrim($body);
        } else {
            // The complete method body is recognized before replacing its mode literal.
            $offset = 0;
            foreach (token_get_all('<?php ' . $body) as $token) {
                $text = is_array($token) ? $token[1] : $token;
                if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING && $text === "'loose'") {
                    $body = substr_replace($body, "'strict'", $offset - 6, strlen($text));
                    break;
                }
                $offset += strlen($text);
            }
        }
        $newContent = substr_replace($content, $body, $inspection['start'], $inspection['length']);
        if ($this->inspectEmailValidator($newContent)['status'] !== 'patched') {
            return ['status' => 'unknown', 'message' => $this->l('Validate.php: unrecognized isEmail() implementation. No changes made; manual review required.')];
        }

        $backupPath = $path . self::BACKUP_SUFFIX;
        if (!copy($path, $backupPath)) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot create backup: %s'), $backupPath)];
        }

        if (file_put_contents($path, $newContent) === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot write Validate.php: %s'), $path)];
        }

        return ['status' => 'patched', 'message' => sprintf($this->l('Validate.php patched successfully. Backup: %s'), $backupPath)];
    }

    /**
     * Apply both patches and clear Smarty cache if at least one patch was written.
     *
     * @return array
     */
    public function applyPatches()
    {
        $results = [
            'template' => $this->patchTemplate(),
            'validate' => $this->patchValidate(),
        ];

        if ($results['template']['status'] === 'patched' || $results['validate']['status'] === 'patched') {
            Tools::clearSmartyCache();
            Tools::clearCache();
        }

        return $results;
    }

    // -------------------------------------------------------------------------
    // Read-only status checks (used by getContent to show current state)
    // -------------------------------------------------------------------------

    protected function getTemplatePatchStatus()
    {
        $path = $this->getXssTplPath();
        if ($path === '') {
            return ['status' => 'unknown', 'message' => $this->l('Status not available in CLI context.')];
        }
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        $content = @file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }
        if (strpos($content, self::VULNERABLE_TOKEN) !== false) {
            return ['status' => 'vulnerable', 'message' => $this->l('Template is VULNERABLE — patch not yet applied!')];
        }
        if (strpos($content, self::PATCHED_TOKEN) !== false) {
            return ['status' => 'patched', 'message' => $this->l('Template patched correctly.')];
        }
        return ['status' => 'unknown', 'message' => $this->l('Template: cannot determine status (tokens not found in file).')];
    }

    protected function getValidatePatchStatus()
    {
        if ($this->hasIsEmailOverride()) {
            return ['status' => 'skipped_override', 'message' => $this->l('Override present — manual fix required (see below).')];
        }
        $path = $this->getValidateClassPath();
        if (!file_exists($path)) {
            return ['status' => 'error', 'message' => sprintf($this->l('File not found: %s'), $path)];
        }
        $content = @file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error', 'message' => sprintf($this->l('Cannot read: %s'), $path)];
        }
        return $this->getValidatorInspectionStatus($this->inspectEmailValidator($content));
    }

    /**
     * Normalize PHP tokens, preserving token types, boundaries and literals.
     *
     * @param string $code PHP fragment without an opening tag
     *
     * @return string
     */
    protected function normalizePhpCode($code)
    {
        $normalized = '';
        foreach (token_get_all('<?php ' . $code) as $token) {
            if (is_array($token)) {
                if (in_array($token[0], [T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }
                $normalized .= token_name($token[0]) . ':' . strlen($token[1]) . ':' . $token[1] . ';';
            } else {
                $normalized .= 'CHAR:1:' . $token . ';';
            }
        }

        return $normalized;
    }

    /**
     * Locate the direct ValidateCore::isEmail() body, ignoring comments and strings.
     * Ambiguous declarations and unfamiliar signatures require manual review.
     *
     * @param string $content Complete Validate.php source
     *
     * @return array|null Body and byte offsets, or null when unrecognized
     */
    protected function getEmailMethodBody($content)
    {
        $tokens = [];
        $offset = 0;
        foreach (token_get_all($content) as $token) {
            $id = is_array($token) ? $token[0] : null;
            $text = is_array($token) ? $token[1] : $token;
            if ($id === T_NAMESPACE) {
                return null;
            }
            if (!in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $tokens[] = ['id' => $id, 'text' => $text, 'offset' => $offset];
            }
            $offset += strlen($text);
        }

        $classCount = 0;
        $method = null;
        $count = count($tokens);
        for ($i = 0; $i < $count; ++$i) {
            if ($tokens[$i]['id'] !== T_CLASS || !isset($tokens[$i + 1])
                || $tokens[$i + 1]['id'] !== T_STRING || strcasecmp($tokens[$i + 1]['text'], 'ValidateCore') !== 0) {
                continue;
            }
            ++$classCount;
            while ($i < $count && $tokens[$i]['text'] !== '{') {
                ++$i;
            }
            $depth = 1;
            for (++$i; $i < $count && $depth > 0; ++$i) {
                $token = $tokens[$i];
                if ($depth === 1 && $token['id'] === T_FUNCTION && isset($tokens[$i + 1])
                    && strcasecmp($tokens[$i + 1]['text'], 'isEmail') === 0) {
                    $signature = '';
                    for ($j = $i; $j < $count && $tokens[$j]['text'] !== '{' && $tokens[$j]['text'] !== ';'; ++$j) {
                        $signature .= $tokens[$j]['text'];
                    }
                    if ($signature !== 'functionisEmail($email)' || $method !== null
                        || $j >= $count || $tokens[$j]['text'] !== '{') {
                        return null;
                    }
                    $start = $tokens[$j]['offset'] + 1;
                    $bodyDepth = 1;
                    for (++$j; $j < $count; ++$j) {
                        if ($tokens[$j]['text'] === '{' || in_array($tokens[$j]['id'], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true)) {
                            ++$bodyDepth;
                        } elseif ($tokens[$j]['text'] === '}') {
                            --$bodyDepth;
                        }
                        if ($bodyDepth === 0) {
                            $length = $tokens[$j]['offset'] - $start;
                            $method = ['body' => substr($content, $start, $length), 'start' => $start, 'length' => $length];
                            $i = $j;
                            break;
                        }
                    }
                    if ($bodyDepth !== 0) {
                        return null;
                    }
                    continue;
                }
                if ($token['text'] === '{' || in_array($token['id'], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true)) {
                    ++$depth;
                } elseif ($token['text'] === '}') {
                    --$depth;
                }
            }
            --$i;
            if ($depth !== 0) {
                return null;
            }
        }

        return $classCount === 1 ? $method : null;
    }

    /**
     * Match audited upstream method bodies after removing whitespace and comments.
     * Hashes identify implementations, not the integrity of the whole core file.
     *
     * @param string $content Complete Validate.php source
     *
     * @return array
     */
    protected function inspectEmailValidator($content)
    {
        $method = $this->getEmailMethodBody($content);
        if ($method === null) {
            return ['status' => 'unknown'];
        }
        $normalized = $this->normalizePhpCode($method['body']);
        // Native PS 1.7.4.0 / 1.7.6.9 rejects the HTML delimiters already.
        if (hash('sha256', $normalized) === 'aaf4b0b20aea487a406c8b1d26c2506b07187924d395718137fd1ee01bf9d72d') {
            return ['status' => 'not_applicable', 'kind' => 'native'] + $method;
        }

        $guard = $this->normalizePhpCode(substr(self::VALIDATE_PATCHED_17, 0, -strlen(self::VALIDATE_VULNERABLE_17)));
        $guardCount = 0;
        while (strpos($normalized, $guard) === 0) {
            $normalized = substr($normalized, strlen($guard));
            ++$guardCount;
        }
        // Egulias: PS 1.7.7.0 / 1.7.8.11 and PS 8.0.0 / 8.0.2.
        if (in_array(hash('sha256', $normalized), [
            '99105473398b3d7dd86406582ce81e064b5c9282104aa20c73a62ce270805fc3',
            'fc3babd28b61a787e454f6e596ca185079c575f19afee6073eb2c815ecd5dcbf',
        ], true)) {
            return ['status' => $guardCount > 0 ? 'patched' : 'vulnerable', 'kind' => 'egulias'] + $method;
        }
        // Symfony: PS 8.2.5 / 9.1.0 loose and PS 8.2.6 / 9.1.1 strict.
        $hash = hash('sha256', $this->normalizePhpCode($method['body']));
        if (in_array($hash, [
            '7e6172c80e0841723f3e3e7836f2a1647af0bc8de0835f2599e4d2702fd20044',
            'd90afe88514fc8f6c122d18b6e7c0b808f3fdad61d36b867344a5e525c3da80d',
        ], true)) {
            return ['status' => 'vulnerable', 'kind' => 'symfony'] + $method;
        }
        if (in_array($hash, [
            'e9c577bed2f5a0a374634a33f592a3ecf9932ac8384764d07c568c1b3ace1760',
            'dcf4efe597fa1649d08495aa1de49f14e6d420e5b3d4017212495f709485bd0d',
        ], true)) {
            return ['status' => 'patched', 'kind' => 'symfony'] + $method;
        }

        return ['status' => 'unknown'];
    }

    /**
     * Translate inspection results consistently for checks and patch attempts.
     *
     * @param array $inspection Recognized implementation status
     *
     * @return array
     */
    protected function getValidatorInspectionStatus($inspection)
    {
        switch ($inspection['status']) {
            case 'not_applicable':
                return ['status' => 'not_applicable', 'message' => $this->l('Validate.php: recognized native validation already rejects HTML delimiters. No validator patch required.')];
            case 'patched':
                return ['status' => 'patched', 'message' => $this->l('Validate.php patched correctly.')];
            case 'vulnerable':
                return ['status' => 'vulnerable', 'message' => $this->l('Validate.php is VULNERABLE — patch not yet applied!')];
            default:
                return ['status' => 'unknown', 'message' => $this->l('Validate.php: unrecognized isEmail() implementation. No changes made; manual review required.')];
        }
    }

    // -------------------------------------------------------------------------
    // Manual fix snippet
    // -------------------------------------------------------------------------

    /**
     * Show a guard to insert while retaining all existing validation logic.
     *
     * @param bool $hasOverride Whether the target is the override file
     *
     * @return string
     */
    protected function getManualFixCode($hasOverride)
    {
        $path = $hasOverride ? 'override/classes/Validate.php' : 'classes/Validate.php';

        return '// Review ' . $path . " and insert this at the start of isEmail() if needed:\n"
            . <<<'PHPCODE'
// Keep all existing validation logic after this guard.
// GHSA-w9f3-qc75-qgx9: reject HTML delimiters.
if (!empty($email) && preg_match('/[<>"]/', $email)) {
    return false;
}
PHPCODE;
    }

    // -------------------------------------------------------------------------
    // Back-office configuration page
    // -------------------------------------------------------------------------

    public function getContent()
    {
        // All navigation is POST-based (action="" forms) to stay on the Symfony
        // module-configure URL in PS8/9 without manually constructing it.

        // Show forensic page when the dedicated submit buttons are present
        if (Tools::isSubmit('go_forensic_scan') || Tools::isSubmit('run_forensic_scan')) {
            return $this->renderForensicScan();
        }

        $patchResults = null;
        if (Tools::isSubmit('apply_patches')) {
            $patchResults = $this->applyPatches();
        }

        $hasOverride  = $this->hasIsEmailOverride();
        $psVersion    = _PS_VERSION_;
        $validateStatus = $this->getValidatePatchStatus();
        $needsManual = $hasOverride || $validateStatus['status'] === 'unknown';

        $this->context->smarty->assign([
            'ps_version'       => $psVersion,
            'has_override'     => $hasOverride,
            'override_path'    => $this->getOverrideClassPath(),
            'needs_manual_fix' => $needsManual,
            'validator_signature_unknown' => $validateStatus['status'] === 'unknown',
            'manual_fix_code'  => $this->getManualFixCode($hasOverride),
            'template_status'  => $this->getTemplatePatchStatus(),
            'validate_status'  => $validateStatus,
            'patch_results'    => $patchResults,
        ]);

        return $this->display(__FILE__, 'views/templates/admin/status.tpl');
    }

    // -------------------------------------------------------------------------
    // Forensic scan — DB-only IoC analysis
    // -------------------------------------------------------------------------

    protected function renderForensicScan()
    {
        $scanResults = null;
        if (Tools::isSubmit('run_forensic_scan')) {
            $scanResults = $this->runForensicScan();
        }

        $this->context->smarty->assign([
            'scan_results' => $scanResults,
        ]);

        return $this->display(__FILE__, 'views/templates/admin/forensic.tpl');
    }

    /**
     * Query all PS tables involved in GHSA-w9f3-qc75-qgx9 for XSS IoC patterns.
     * Uses only Db::getInstance() + _DB_PREFIX_: works on any PS installation.
     *
     * @return array{total_hits:int, scanned_at:string, sections:array}
     */
    protected function runForensicScan()
    {
        $db  = Db::getInstance();
        $pfx = _DB_PREFIX_;

        // XSS IoC conditions applied to email columns
        $emailWhere =
            "email LIKE '%<%'"
            . " OR email LIKE '%>%'"
            . " OR email LIKE '%\"%'"
            . " OR email LIKE '%script%'"
            . " OR email LIKE '%javascript:%'"
            . " OR email LIKE '%onerror=%'"
            . " OR email LIKE '%onload=%'"
            . " OR email LIKE '%onfocus=%'"
            . " OR email LIKE '%onmouse%'"
            . " OR email LIKE '%document.%'"
            . " OR email LIKE '%cookie%'"
            . " OR email LIKE '%eval(%'";

        $sections  = [];
        $totalHits = 0;

        // ── 1. ps_customer — registered accounts ──────────────────────────
        $sections['customers'] = $this->scanTable($db, "
            SELECT id_customer AS id, email, date_add, active, deleted
            FROM `{$pfx}customer`
            WHERE {$emailWhere}
            ORDER BY date_add DESC
            LIMIT 200
        ", [
            'label'    => $this->l('Registered accounts (ps_customer)'),
            'critical' => false,
            'columns'  => ['ID', $this->l('Email'), $this->l('Registered'), $this->l('Active'), $this->l('Deleted')],
            'fields'   => ['id', 'email', 'date_add', 'active', 'deleted'],
        ]);

        // ── 2. ps_customer_thread — PRIMARY ATTACK VECTOR ─────────────────
        // This is the email rendered verbatim in the vulnerable BO template
        $sections['threads'] = $this->scanTable($db, "
            SELECT id_customer_thread AS id, email, date_add, status
            FROM `{$pfx}customer_thread`
            WHERE {$emailWhere}
            ORDER BY date_add DESC
            LIMIT 200
        ", [
            'label'    => $this->l('Contact-form threads — PRIMARY VECTOR (ps_customer_thread)'),
            'critical' => true,
            'columns'  => ['ID', $this->l('Email'), $this->l('Date'), $this->l('Status')],
            'fields'   => ['id', 'email', 'date_add', 'status'],
        ]);

        // ── 3. ps_customer_message — message body ─────────────────────────
        $sections['messages'] = $this->scanTable($db, "
            SELECT m.id_customer_message AS id,
                   t.email,
                   m.date_add,
                   LEFT(m.message, 160) AS message_snippet
            FROM `{$pfx}customer_message` m
            INNER JOIN `{$pfx}customer_thread` t
                    ON m.id_customer_thread = t.id_customer_thread
            WHERE m.message LIKE '%<script%'
               OR m.message LIKE '%javascript:%'
               OR m.message LIKE '%onerror=%'
               OR m.message LIKE '%document.cookie%'
            ORDER BY m.date_add DESC
            LIMIT 100
        ", [
            'label'    => $this->l('Message bodies (ps_customer_message)'),
            'critical' => false,
            'columns'  => ['ID', $this->l('From'), $this->l('Date'), $this->l('Snippet')],
            'fields'   => ['id', 'email', 'date_add', 'message_snippet'],
        ]);

        // ── 4. ps_employee — informational: list all admin accounts ────────
        // Not an IoC count but essential post-exploitation check
        $sections['employees'] = $this->scanTable($db, "
            SELECT id_employee AS id,
                   CONCAT(firstname, ' ', lastname) AS name,
                   email,
                   id_profile,
                   active
            FROM `{$pfx}employee`
            ORDER BY id_employee DESC
            LIMIT 50
        ", [
            'label'       => $this->l('Admin accounts — verify no unauthorized additions (ps_employee)'),
            'critical'    => false,
            'informational' => true,
            'columns'     => ['ID', $this->l('Name'), $this->l('Email'), $this->l('Profile'), $this->l('Active')],
            'fields'      => ['id', 'name', 'email', 'id_profile', 'active'],
        ]);

        // Count IoC hits (employees are informational, excluded)
        foreach (['customers', 'threads', 'messages'] as $key) {
            $totalHits += count($sections[$key]['rows']);
        }

        return [
            'total_hits' => $totalHits,
            'scanned_at' => date('Y-m-d H:i:s'),
            'sections'   => $sections,
        ];
    }

    /**
     * Run a single SELECT query and return a normalised section array.
     *
     * @param  Db     $db
     * @param  string $sql
     * @param  array  $meta  label, critical, columns, fields[, informational]
     * @return array
     */
    protected function scanTable(Db $db, $sql, array $meta)
    {
        $base = array_merge([
            'label'         => '',
            'critical'      => false,
            'informational' => false,
            'columns'       => [],
            'fields'        => [],
            'rows'          => [],
            'error'         => null,
        ], $meta);

        try {
            $rows = $db->executeS($sql);
            $base['rows'] = $rows ?: [];
        } catch (Exception $e) {
            $base['error'] = $e->getMessage();
        }

        return $base;
    }
}
