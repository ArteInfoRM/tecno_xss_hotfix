# Offline regression checks

Run from the workspace root:

```sh
php modules/tecno_xss_hotfix/tests/regression.php /path/to/upstream-fixtures
```

The runner creates an isolated temporary directory, patches fixture copies only, checks statuses and backup preservation, and removes its own temporary files. It does not bootstrap PrestaShop or change installed core files. The tests directory is excluded from release archives.

## Fixture provenance

Download official sources separately from `https://raw.githubusercontent.com/PrestaShop/PrestaShop/<tag>/classes/Validate.php`, naming each file `Validate-<tag>.php` for these tags:

- `1.7.4.0`, `1.7.6.9`, `1.7.7.0`, `1.7.8.11`
- `8.0.0`, `8.0.2`, `8.2.5`, `8.2.6`
- `9.1.0`, `9.1.1`

Also download `https://raw.githubusercontent.com/PrestaShop/PrestaShop/1.7.4.0/admin-dev/themes/default/template/controllers/customer_threads/helpers/view/view.tpl` as `view-1.7.4.0.tpl`.

These upstream source files retain their own licenses and are not bundled or relicensed by this module. The production fingerprints cover only normalized method bodies, never complete core files. Unrecognized implementations require manual review.
