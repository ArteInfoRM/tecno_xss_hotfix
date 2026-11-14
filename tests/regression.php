<?php
/**
 * Regression checks for recognized validator implementations and template patching.
 *
 * @author    Arte e Informatica <helpdesk@tecnoacquisti.com>
 * @copyright 2009-2026 Arte e Informatica
 * @license   https://opensource.org/licenses/MIT MIT License
 */
if (PHP_SAPI !== 'cli') {
    exit;
}

define('_PS_VERSION_', '1.7.4.0');

class Tools
{
    public static function isSubmit($name)
    {
        return false;
    }
}

class TestSmartyAssignments
{
    public $values = [];

    public function assign($values)
    {
        $this->values = $values;
    }
}

class Module
{
    public $context;

    public function display($file, $template)
    {
        return $this->context->smarty->values;
    }

    public function l($message)
    {
        return $message;
    }
}

require dirname(__DIR__) . '/tecno_xss_hotfix.php';

class HotfixTestModule extends Tecno_Xss_Hotfix
{
    public $testDirectory;
    public $overridePresent = false;

    public function __construct($directory)
    {
        $this->testDirectory = $directory;
    }

    protected function getValidateClassPath()
    {
        return $this->testDirectory . '/Validate.php';
    }

    protected function getXssTplPath()
    {
        return $this->testDirectory . '/view.tpl';
    }

    protected function hasIsEmailOverride()
    {
        return $this->overridePresent;
    }

    protected function getOverrideClassPath()
    {
        return $this->testDirectory . '/override.php';
    }

    public function inspect($source)
    {
        return $this->inspectEmailValidator($source);
    }

    public function patchValidator()
    {
        return $this->patchValidate();
    }

    public function templateStatus()
    {
        return $this->getTemplatePatchStatus();
    }

    public function patchView()
    {
        return $this->patchTemplate();
    }
}

$fixtures = isset($argv[1]) ? rtrim($argv[1], '/') : '';
$directory = sys_get_temp_dir() . '/tecno-xss-regression-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
$module = new HotfixTestModule($directory);
$checks = 0;

function checkResult($condition, $label)
{
    global $checks;
    ++$checks;
    if (!$condition) {
        throw new RuntimeException($label);
    }
}

function readFixture($name)
{
    global $fixtures;
    $path = $fixtures . '/' . $name;
    if (!is_file($path)) {
        throw new RuntimeException('Missing upstream fixture: ' . $path);
    }

    return file_get_contents($path);
}

try {
    $versions = [
        '1.7.4.0' => 'not_applicable',
        '1.7.6.9' => 'not_applicable',
        '1.7.7.0' => 'vulnerable',
        '1.7.8.11' => 'vulnerable',
        '8.0.0' => 'vulnerable',
        '8.0.2' => 'vulnerable',
        '8.2.5' => 'vulnerable',
        '8.2.6' => 'patched',
        '9.1.0' => 'vulnerable',
        '9.1.1' => 'patched',
    ];
    foreach ($versions as $version => $expected) {
        $source = readFixture('Validate-' . $version . '.php');
        checkResult($module->inspect($source)['status'] === $expected, 'Inspect PS ' . $version);
        file_put_contents($directory . '/Validate.php', $source);
        $backup = $directory . '/Validate.php' . Tecno_Xss_Hotfix::BACKUP_SUFFIX;
        if (is_file($backup)) {
            unlink($backup);
        }
        $result = $module->patchValidator();
        if ($expected === 'vulnerable') {
            checkResult($result['status'] === 'patched', 'Patch PS ' . $version);
            checkResult(file_get_contents($backup) === $source, 'Original backup PS ' . $version);
            $patched = file_get_contents($directory . '/Validate.php');
            checkResult($module->inspect($patched)['status'] === 'patched', 'Verify PS ' . $version);
            checkResult($module->patchValidator()['status'] === 'already_patched', 'Repeat PS ' . $version);
            checkResult(file_get_contents($directory . '/Validate.php') === $patched, 'No repeat changes PS ' . $version);
            checkResult(file_get_contents($backup) === $source, 'Preserve backup PS ' . $version);
        } else {
            checkResult(in_array($result['status'], ['not_applicable', 'already_patched'], true), 'Skip PS ' . $version);
            checkResult(file_get_contents($directory . '/Validate.php') === $source, 'No changes PS ' . $version);
            checkResult(!is_file($backup), 'No backup for unchanged PS ' . $version);
        }
    }

    $source = readFixture('Validate-1.7.8.11.php');
    $inspection = $module->inspect($source);
    $guard = "if (!empty(\$email) && preg_match('/[<>\"]/', \$email)) { return false; }\n";
    $duplicate = substr_replace($source, $guard . $guard . $inspection['body'], $inspection['start'], $inspection['length']);
    checkResult($module->inspect($duplicate)['status'] === 'patched', 'Recognize previously duplicated guards');
    file_put_contents($directory . '/Validate.php', $duplicate);
    file_put_contents($backup, 'original-backup');
    checkResult($module->patchValidator()['status'] === 'already_patched', 'Skip duplicated guards');
    checkResult(file_get_contents($backup) === 'original-backup', 'Keep existing duplicate-patch backup');
    checkResult(file_get_contents($directory . '/Validate.php') === $duplicate, 'Leave existing duplicate guards unchanged');

    $source = readFixture('Validate-8.2.5.php');
    $spoof = "\n// 'mode' => 'strict',\n";
    $source = str_replace('class ValidateCore', $spoof . 'class ValidateCore', $source);
    checkResult($module->inspect($source)['status'] === 'vulnerable', 'Ignore strict-mode comment outside method');
    $inspection = $module->inspect($source);
    $withComment = substr_replace($source, $spoof . $inspection['body'], $inspection['start'], $inspection['length']);
    checkResult($module->inspect($withComment)['status'] === 'vulnerable', 'Ignore strict-mode comment inside method');
    file_put_contents($directory . '/Validate.php', $withComment);
    checkResult($module->patchValidator()['status'] === 'patched', 'Patch despite misleading comment');
    checkResult(substr_count(file_get_contents($directory . '/Validate.php'), $spoof) === 2, 'Leave comments unchanged');

    $inspection = $module->inspect($source);
    $body = $inspection['body'];
    $unknownSources = [
        '<?php class ValidateCore { public static function isEmail($email) { return true; } }',
        str_replace("'loose'", "'custom'", $source),
        substr_replace($source, $body . "\nreturn true;", $inspection['start'], $inspection['length']),
        str_replace('function isEmail($email)', 'function isEmail($other)', $source),
        str_replace('class ValidateCore', 'class OtherClass', $source),
        str_replace('new EmailValidator', 'newEmailValidator', readFixture('Validate-1.7.8.11.php')),
        $source . "\nclass ValidateCore {}",
        "<?php class OtherClass { public static function isEmail(\$email) {" . $body . '} } class ValidateCore {}',
        "<?php class ValidateCore { public function other() { function isEmail(\$email) {" . $body . '} } }',
        str_replace('[a-z', '[<>a-z', readFixture('Validate-1.7.4.0.php')),
    ];
    foreach ($unknownSources as $index => $unknown) {
        checkResult($module->inspect($unknown)['status'] === 'unknown', 'Unknown case ' . $index);
        file_put_contents($directory . '/Validate.php', $unknown);
        file_put_contents($backup, 'keep-me');
        checkResult($module->patchValidator()['status'] === 'unknown', 'Skip unknown case ' . $index);
        checkResult(file_get_contents($directory . '/Validate.php') === $unknown, 'No write unknown case ' . $index);
        checkResult(file_get_contents($backup) === 'keep-me', 'Keep backup unknown case ' . $index);
    }

    file_put_contents($directory . '/Validate.php', $source);
    $module->overridePresent = true;
    checkResult($module->patchValidator()['status'] === 'skipped_override', 'Skip when override present');
    checkResult(file_get_contents($directory . '/Validate.php') === $source, 'Keep core when override present');
    $module->overridePresent = false;

    $module->context = (object) ['smarty' => new TestSmartyAssignments()];
    file_put_contents($directory . '/view.tpl', Tecno_Xss_Hotfix::PATCHED_TOKEN);
    foreach (['1.7.4.0' => false, '8.2.6' => false] as $version => $needsManual) {
        file_put_contents($directory . '/Validate.php', readFixture('Validate-' . $version . '.php'));
        $values = $module->getContent();
        checkResult($values['needs_manual_fix'] === $needsManual, 'No manual fix for recognized PS ' . $version);
        checkResult($values['validator_signature_unknown'] === false, 'Known signature in configuration');
    }
    file_put_contents($directory . '/Validate.php', $unknownSources[0]);
    $values = $module->getContent();
    checkResult($values['needs_manual_fix'] === true, 'Manual review for unknown validator');
    checkResult($values['validator_signature_unknown'] === true, 'Unknown signature in configuration');
    checkResult(strpos($values['manual_fix_code'], 'parent::isEmail') === false, 'Manual guard preserves existing implementation');
    $module->overridePresent = true;
    $values = $module->getContent();
    checkResult($values['needs_manual_fix'] === true, 'Manual fix for override');
    checkResult($values['validator_signature_unknown'] === false, 'Override has separate status');
    $module->overridePresent = false;

    $template = readFixture('view-1.7.4.0.tpl');
    checkResult(strpos($template, Tecno_Xss_Hotfix::PATCHED_TOKEN) !== false, 'Fixture has escaped token');
    checkResult(substr_count($template, Tecno_Xss_Hotfix::VULNERABLE_TOKEN) === 2, 'Fixture has two bare tokens');
    file_put_contents($directory . '/view.tpl', $template);
    checkResult($module->templateStatus()['status'] === 'vulnerable', 'Mixed template is vulnerable');
    checkResult($module->patchView()['status'] === 'patched', 'Patch mixed template');
    $patched = file_get_contents($directory . '/view.tpl');
    checkResult(strpos($patched, Tecno_Xss_Hotfix::VULNERABLE_TOKEN) === false, 'Remove all bare template tokens');
    checkResult($module->templateStatus()['status'] === 'patched', 'Fully escaped template status');
    checkResult($module->patchView()['status'] === 'already_patched', 'Repeated template patch');
    checkResult(file_get_contents($directory . '/view.tpl' . Tecno_Xss_Hotfix::BACKUP_SUFFIX) === $template, 'Keep original template backup');
    file_put_contents($directory . '/view.tpl', 'Unrecognized template');
    checkResult($module->patchView()['status'] === 'unknown', 'Unknown template is not already patched');
    checkResult(file_get_contents($directory . '/view.tpl') === 'Unrecognized template', 'Leave unknown template unchanged');

    echo $checks . " regression checks passed.\n";
} finally {
    foreach (glob($directory . '/*') as $path) {
        unlink($path);
    }
    rmdir($directory);
}
